#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

from neutron_lib._i18n import _
from oslo_log import log as logging

from tempest.common import utils
from tempest.common import waiters
from tempest import config
from tempest.lib.common.utils import data_utils
from tempest.lib.common.utils.linux import remote_client
from tempest.lib.common.utils import test_utils
from tempest.lib import decorators

from neutron_tempest_plugin.common import tempest_fixtures
from neutron_tempest_plugin.scenario import constants
from neutron_tempest_plugin.tap_as_a_service.scenario import manager

CONF = config.CONF
LOG = logging.getLogger(__name__)

# tcpdump display flags per mirror_type. ERSPAN needs a hex dump (-XX) so
# callers can decode the ERSPAN header (session_id, inner frame) themselves;
# GRE mirrors are fully human-readable (key=0x.., ICMP summary) without it.
TCPDUMP_FLAGS = {
    'gre': '-vvv -n -nn',
    'erspanv1': '-vvv -n -XX',
}
LOG_LOCATION = "/tmp/tcpdumplog"


def _tcpdump_cmd(mirror_type):
    return "sudo tcpdump %s proto GRE > %s" % (
        TCPDUMP_FLAGS[mirror_type], LOG_LOCATION)


def _make_directions(in_id, out_id, both_id):
    """Build a mirror `directions` dict.

    BOTH is only included if the tap-mirror-both-direction extension is
    enabled.
    """
    directions = {'IN': in_id, 'OUT': out_id}
    if utils.is_extension_enabled('tap-mirror-both-direction', 'network'):
        directions['BOTH'] = both_id
    return directions


def _create_mirror(test_case, name, port_id, directions, remote_ip,
                   mirror_type):
    """Create a tap mirror and register its (per-test) cleanup."""
    mirror = test_case.tap_mirrors_client.create_tap_mirror(
        name=data_utils.rand_name(name),
        port_id=port_id,
        directions=directions,
        remote_ip=remote_ip,
        mirror_type=mirror_type)
    test_case.addCleanup(
        test_utils.call_and_ignore_notfound_exc,
        test_case.tap_mirrors_client.delete_tap_mirror,
        mirror['tap_mirror']['id'])
    return mirror


def _ensure_public_router_cls(cls):
    """Classmethod-safe equivalent of manager._ensure_public_router.

    create_router_by_client already self-registers cleanup via cls.routers,
    so no explicit cleanup is needed here.
    """
    client = cls.client
    if CONF.network.public_router_id:
        return client.show_router(CONF.network.public_router_id)['router']
    elif CONF.network.public_network_id:
        router = cls.create_router_by_client(project_id=client.project_id)
        return client.update_router(
            router['id'],
            external_gateway_info=dict(
                network_id=CONF.network.public_network_id))['router']
    else:
        raise Exception(_("Neither 'public_router_id' nor "
                          "'public_network_id' has been configured."))


def _create_shared_network_cls(cls):
    """Classmethod-safe equivalent of manager.create_networks."""
    network = cls.create_network()
    router = _ensure_public_router_cls(cls)
    subnet = cls.create_subnet(network)
    cls.client.add_router_interface_with_subnet_id(
        router_id=router['id'], subnet_id=subnet['id'])
    cls.addClassResourceCleanup(
        test_utils.call_and_ignore_notfound_exc,
        cls.client.remove_router_interface_with_subnet_id,
        router_id=router['id'], subnet_id=subnet['id'])
    return network, subnet, router


def _create_shared_server_with_floatingip_cls(cls, network,
                                              use_taas_cloud_image=False,
                                              port_security_enabled=True):
    """Classmethod-safe version of manager._create_server_with_floatingip."""
    if use_taas_cloud_image:
        image = cls.image_ref
        flavor = cls.flavor_ref
    else:
        image = CONF.compute.image_ref
        flavor = CONF.compute.flavor_ref

    port_kwargs = {'port_security_enabled': port_security_enabled}
    if port_security_enabled is not False:
        port_kwargs['security_groups'] = [cls.secgroup['id']]
    port = cls.create_port(network, **port_kwargs)

    server = cls.os_primary.servers_client.create_server(
        name=data_utils.rand_name('server-test'),
        flavorRef=flavor,
        imageRef=image,
        key_name=cls.keypair['name'],
        networks=[{'port': port['id']}],
        security_groups=[{'name': cls.secgroup['name']}])['server']
    # Track the server so this class's resource_cleanup can delete it (which
    # unbinds its port) before the base resource_cleanup removes that port --
    # the delete_port policy only lets the owner delete an *unused* port.
    cls._taas_server_ids.append(server['id'])

    client = cls.os_primary.servers_client
    cls.wait_for_server_status(
        cls, server, constants.SERVER_STATUS_ACTIVE, client=client)
    cls.wait_for_guest_os_ready(cls, server, client=client)

    fip = cls.create_floatingip(port=port)
    return port, fip


def _make_remote_client_cls(cls, fip, advanced=False):
    user = cls.username if advanced else CONF.validation.image_ssh_user
    client = remote_client.RemoteClient(
        fip['floating_ip_address'], user,
        pkey=cls.keypair['private_key'],
        ssh_key_type=CONF.validation.ssh_key_type)
    client.validate_authentication()
    return client


def _create_shared_monitor_cls(cls):
    """Boot one monitor VM (own network) and return (client, floating IP)."""
    netmon, _, _ = _create_shared_network_cls(cls)
    _, fip = _create_shared_server_with_floatingip_cls(
        cls, netmon, use_taas_cloud_image=True, port_security_enabled=False)
    return _make_remote_client_cls(cls, fip, advanced=True), \
        fip['floating_ip_address']


def _serialize_topology_lifetime(cls):
    """Serialize GRE/ERSPAN classes so their 4-VM topologies never coexist.

    Registered first so it's the last cleanup to run (LIFO), releasing only
    after this class's VMs are deleted -- otherwise the next class could
    start booting while these are still up, doubling peak compute demand.
    """
    lock = tempest_fixtures.LockFixture('tap_mirror_topology')
    lock.setUp()
    cls.addClassResourceCleanup(lock.cleanUp)


def _create_shared_topology(cls):
    """Boot 2 cirros VMs (vm0/vm1) + 2 monitor VMs once per test class.

    Called from resource_setup so all tests in the class reuse them
    instead of each booting their own (the dominant cost of these
    scenario tests). Only tap mirrors are created/cleaned up per test.
    """
    cls.setup_advanced_image()
    cls._taas_server_ids = []
    cls.network, cls.subnet, cls.router = _create_shared_network_cls(cls)

    cls.vm0_port, vm0_fip = _create_shared_server_with_floatingip_cls(
        cls, cls.network)
    cls.vm1_port, vm1_fip = _create_shared_server_with_floatingip_cls(
        cls, cls.network)
    cls.vm0_client = _make_remote_client_cls(cls, vm0_fip)
    cls.vm1_client = _make_remote_client_cls(cls, vm1_fip)

    cls.monitor1_client, cls.monitor1_ip = _create_shared_monitor_cls(cls)
    cls.monitor2_client, cls.monitor2_ip = _create_shared_monitor_cls(cls)


def _cleanup_shared_servers(cls):
    """Delete shared servers so the base cleanup can delete their ports."""
    servers_client = cls.os_primary.servers_client
    for server_id in getattr(cls, '_taas_server_ids', []):
        test_utils.call_and_ignore_notfound_exc(
            servers_client.delete_server, server_id)
    for server_id in getattr(cls, '_taas_server_ids', []):
        test_utils.call_and_ignore_notfound_exc(
            waiters.wait_for_server_termination, servers_client, server_id)


def _restart_tcpdump(test_case, monitor_client, tcpdump_cmd):
    """(Re)start tcpdump on a (possibly test-class-shared) monitor VM.

    Kills any leftover tcpdump left running by a previous test that reused
    this same monitor VM, so its output doesn't bleed into this capture.
    """
    monitor_client.exec_command("sudo pkill -x tcpdump || true")
    test_case._run_in_background(monitor_client, tcpdump_cmd)
    test_case.assertIn("tcpdump", monitor_client.exec_command("ps -ax"))


def _run_tap_mirror_connectivity(test_case, mirror_type='gre'):
    """Mirror vm1_port (IN/OUT[/BOTH]) to a single monitor VM remote IP.

    Shared by the GRE and ERSPAN variants of this scenario; only
    mirror_type differs. Uses the class-shared vm0/vm1/monitor1 from
    _create_shared_topology -- only the tap mirror is created/cleaned up
    per test. Callers apply their own protocol-specific assertions on the
    returned tcpdump output.
    """
    vm0_port = test_case.vm0_port
    vm1_port = test_case.vm1_port
    vm0_client = test_case.vm0_client
    vm1_ip = vm1_port['fixed_ips'][0]['ip_address']
    monitor_client = test_case.monitor1_client

    test_case.check_remote_connectivity(vm0_client, vm1_ip, ping_count=5)

    directions = _make_directions('101', '102', '103')
    _create_mirror(test_case, "tap_mirror", vm1_port['id'], directions,
                   test_case.monitor1_ip, mirror_type)
    _restart_tcpdump(test_case, monitor_client, _tcpdump_cmd(mirror_type))

    test_case.check_remote_connectivity(vm0_client, vm1_ip, ping_count=50)

    output = monitor_client.exec_command("cat %s" % LOG_LOCATION)
    test_case.assertLess(0, len(output))

    return {
        'output': output,
        'vm0_ip': vm0_port['fixed_ips'][0]['ip_address'],
        'vm1_ip': vm1_ip,
        'directions': directions,
    }


def _run_one_source_two_dest_mirror(test_case, mirror_type='gre'):
    """Mirror vm0_port to 2 separate monitor VMs on different networks.

    Shared by the GRE and ERSPAN variants of this scenario. Uses the
    class-shared vm0/vm1/monitor1/monitor2 from _create_shared_topology --
    only the tap mirrors are created/cleaned up per test.
    """
    vm0_port = test_case.vm0_port
    vm1_port = test_case.vm1_port
    vm0_client = test_case.vm0_client
    vm1_ip = vm1_port['fixed_ips'][0]['ip_address']
    test_case.check_remote_connectivity(vm0_client, vm1_ip, ping_count=5)

    monitor1_client = test_case.monitor1_client
    monitor2_client = test_case.monitor2_client
    directions1 = _make_directions('101', '102', '105')
    directions2 = _make_directions('103', '104', '106')
    _create_mirror(test_case, "tap_mirror1", vm0_port['id'], directions1,
                   test_case.monitor1_ip, mirror_type)
    _create_mirror(test_case, "tap_mirror2", vm0_port['id'], directions2,
                   test_case.monitor2_ip, mirror_type)

    tcpdump_cmd = _tcpdump_cmd(mirror_type)
    _restart_tcpdump(test_case, monitor1_client, tcpdump_cmd)
    _restart_tcpdump(test_case, monitor2_client, tcpdump_cmd)

    test_case.check_remote_connectivity(vm0_client, vm1_ip, ping_count=50)

    output1 = monitor1_client.exec_command("cat %s" % LOG_LOCATION)
    test_case.assertLess(0, len(output1))
    output2 = monitor2_client.exec_command("cat %s" % LOG_LOCATION)
    test_case.assertLess(0, len(output2))

    return {
        'output1': output1,
        'output2': output2,
        'vm0_ip': vm0_port['fixed_ips'][0]['ip_address'],
        'vm1_ip': vm1_ip,
        'directions1': directions1,
        'directions2': directions2,
    }


def _run_two_source_one_dest_mirror(test_case, mirror_type='gre'):
    """Mirror vm0_port and vm1_port to the same monitor VM remote IP.

    Shared by the GRE and ERSPAN variants of this scenario. Uses the
    class-shared vm0/vm1/monitor1 from _create_shared_topology -- only the
    tap mirrors are created/cleaned up per test.
    """
    vm0_port = test_case.vm0_port
    vm1_port = test_case.vm1_port
    vm0_client = test_case.vm0_client
    vm1_ip = vm1_port['fixed_ips'][0]['ip_address']
    test_case.check_remote_connectivity(vm0_client, vm1_ip, ping_count=5)

    monitor_client = test_case.monitor1_client
    r_ip = test_case.monitor1_ip
    directions_vm0 = _make_directions('101', '102', '105')
    directions_vm1 = _make_directions('103', '104', '106')
    _create_mirror(test_case, "tap_mirror_vm0", vm0_port['id'],
                   directions_vm0, r_ip, mirror_type)
    _create_mirror(test_case, "tap_mirror_vm1", vm1_port['id'],
                   directions_vm1, r_ip, mirror_type)
    _restart_tcpdump(test_case, monitor_client, _tcpdump_cmd(mirror_type))

    test_case.check_remote_connectivity(vm0_client, vm1_ip, ping_count=50)

    output = monitor_client.exec_command("cat %s" % LOG_LOCATION)
    test_case.assertLess(0, len(output))

    return {
        'output': output,
        'vm0_ip': vm0_port['fixed_ips'][0]['ip_address'],
        'vm1_ip': vm1_ip,
        'directions_vm0': directions_vm0,
        'directions_vm1': directions_vm1,
    }


def _run_ipv6_connectivity(test_case, mirror_type='gre'):
    """Set up a fresh dual-stack topology, ping over IPv6, capture output.

    Unlike the other _run_* helpers, this builds a topology from scratch
    per test (not the class-shared one) since it needs its own IPv6
    subnet. Used by both *_ipv6_connectivity tests (GRE here, ERSPAN via
    import). Safely reuses _make_remote_client_cls/_create_mirror/
    _restart_tcpdump with a test instance instead of cls, since those only
    read attributes off their first argument rather than calling methods
    on it.
    """
    test_case.client.create_security_group_rule(
        security_group_id=test_case.secgroup['id'],
        direction='ingress',
        ethertype='IPv6',
        protocol='ipv6-icmp')

    test_case.network, test_case.subnet, test_case.router = \
        test_case.create_networks()

    # ULA avoids overlap with the external network's 2001:db8::/64.
    subnet_v6 = test_case.client.create_subnet(
        network_id=test_case.network['id'],
        ip_version=6, cidr='fd12::/64',
        ipv6_ra_mode='slaac',
        ipv6_address_mode='slaac')['subnet']
    test_case.addCleanup(test_utils.call_and_ignore_notfound_exc,
                         test_case.client.delete_subnet, subnet_v6['id'])
    test_case.client.add_router_interface_with_subnet_id(
        router_id=test_case.router['id'], subnet_id=subnet_v6['id'])
    test_case.addCleanup(
        test_utils.call_and_ignore_notfound_exc,
        test_case.client.remove_router_interface_with_subnet_id,
        router_id=test_case.router['id'], subnet_id=subnet_v6['id'])

    vm0_port, vm0_fip = test_case._create_server_with_floatingip(
        security_group=test_case.secgroup['name'])
    vm1_port, vm1_fip = test_case._create_server_with_floatingip(
        security_group=test_case.secgroup['name'])
    vm0_client = _make_remote_client_cls(test_case, vm0_fip)

    netmon, _, _ = test_case.create_networks()
    _, monitor_fip = test_case._create_server_with_floatingip(
        use_taas_cloud_image=True, network=netmon,
        security_group=test_case.secgroup['name'],
        port_security_enabled=False)
    monitor_client = _make_remote_client_cls(test_case, monitor_fip,
                                             advanced=True)
    r_ip = monitor_fip['floating_ip_address']

    directions = _make_directions('101', '102', '103')
    _create_mirror(test_case, "tap_mirror_ipv6", vm1_port['id'], directions,
                   r_ip, mirror_type)
    _restart_tcpdump(test_case, monitor_client, _tcpdump_cmd(mirror_type))

    vm0_ipv6 = next(ip['ip_address'] for ip in vm0_port['fixed_ips']
                    if ip['subnet_id'] == subnet_v6['id'])
    vm1_ipv6 = next(ip['ip_address'] for ip in vm1_port['fixed_ips']
                    if ip['subnet_id'] == subnet_v6['id'])

    # Early pings may be lost during SLAAC setup; ignore failures.
    try:
        vm0_client.exec_command("ping6 -c 100 %s" % vm1_ipv6)
    except Exception as e:
        LOG.debug("ping6 did not complete: %s", e)

    output = monitor_client.exec_command("cat %s" % LOG_LOCATION)
    test_case.assertTrue(output)

    return {
        'output': output,
        'vm0_ipv6': vm0_ipv6,
        'vm1_ipv6': vm1_ipv6,
        'directions': directions,
    }


class TestTapMirror(manager.BaseTaasScenarioTests):
    """Scenario tests for tap mirror using the GRE protocol.

    GRE tap mirrors carry the mirror's tunnel_id as the GRE Key field
    (e.g. tunnel_id 101 appears as key=0x65), so direction is verified by
    matching that key plus the inner ICMP echo request/reply text.
    """

    @classmethod
    @utils.requires_ext(extension='security-group', service='network')
    @utils.requires_ext(extension='tap-mirror', service='network')
    def skip_checks(cls):
        super().skip_checks()
        # resource_setup boots the monitor VMs (advanced/taas cloud image)
        # for the whole class up front, so this has to be checked here
        # rather than per-test: by the time a per-test skipUnless would
        # run, resource_setup has already tried (and failed) to boot them.
        if not (CONF.neutron_plugin_options.advanced_image_ref or
                CONF.neutron_plugin_options.default_image_is_advanced):
            raise cls.skipException(
                "Advanced image is required to run this test.")

    @classmethod
    def resource_setup(cls):
        super().resource_setup()
        _serialize_topology_lifetime(cls)
        cls.keypair = cls.create_keypair()
        cls.secgroup = cls.create_security_group(
            name=data_utils.rand_name('secgroup'))
        cls.create_loginable_secgroup_rule(secgroup_id=cls.secgroup['id'])
        cls.create_pingable_secgroup_rule(secgroup_id=cls.secgroup['id'])
        _create_shared_topology(cls)

    @classmethod
    def resource_cleanup(cls):
        _cleanup_shared_servers(cls)
        super().resource_cleanup()

    @decorators.idempotent_id('d9cfca96-fa83-417a-b111-1c02f6fe2796')
    def test_tap_mirror_connectivity(self):
        """Test that traffic between 2 VMs mirrored to a FIP

        .. code-block:: HTML

           +------------+
           | Monitor VM |
           |   FIP      |
           +-----+------+
                 |
                 |
           +-----+------+
           |   NetMon   |
           +------------+

           +---------------+
           |   Net0        |
           +---+---------+-+
               |         |
               |         |
           +---+-+     +-+---+
           | VM0 |     | VM1 |
           +-----+     +-----+

        This is a simplified scenario adapted to the CI machinery.
        The mirroring destination should be outside of the cloud.
        """
        result = _run_tap_mirror_connectivity(self, mirror_type='gre')
        output = result['output']
        vm0_ip = result['vm0_ip']
        vm1_ip = result['vm1_ip']
        directions = result['directions']

        output_lines = output.splitlines()

        self._check_icmp_mirror_direction(output_lines, vm0_ip, vm1_ip, "IN",
                                          "key=0x65")
        self._check_icmp_mirror_direction(output_lines, vm0_ip, vm1_ip, "OUT",
                                          "key=0x66")
        if 'BOTH' in directions:
            self._check_icmp_mirror_direction(output_lines, vm0_ip, vm1_ip,
                                              "BOTH", "key=0x67")

    @decorators.idempotent_id('f6acb2ba-9d58-4cd3-99f8-b5553653e683')
    def test_tap_mirror_ipv6_connectivity(self):
        """Test that IPv6 traffic between 2 VMs is mirrored via GRE to a FIP.

        .. code-block:: HTML

           +------------+
           | Monitor VM |
           |   FIP      |
           +-----+------+
                 |
           +-----+------+
           |   NetMon   |
           +------------+

           +-------------------+
           |   Net0 (v4+v6)    |
           +---+----------+----+
               |          |
           +---+-+      +-+---+
           | VM0 |      | VM1 |
           +-----+      +-----+

        VM1's port is mirrored via GRE (IN, OUT, and optionally BOTH) to the
        monitor VM's FIP.  VM0 pings VM1 over IPv6, producing ICMPv6 echo
        requests (IN, type=128) and echo replies (OUT, type=129) that appear
        in the GRE capture keyed by direction.
        """
        result = _run_ipv6_connectivity(self, mirror_type='gre')
        output = result['output']
        vm0_ipv6 = result['vm0_ipv6']
        vm1_ipv6 = result['vm1_ipv6']
        directions = result['directions']

        output_lines = output.splitlines()
        dir_keys = [("IN", "key=0x65"), ("OUT", "key=0x66")]
        if 'BOTH' in directions:
            dir_keys.append(("BOTH", "key=0x67"))
        for direction, key in dir_keys:
            self._check_icmp_mirror_direction(
                output_lines, vm0_ipv6, vm1_ipv6, direction, key)

    def _check_icmp_mirror_direction(self, output_lines, ip_sender,
                                     ip_receiver, direction, key):
        """Check mirrored ICMP/ICMPv6 direction in tcpdump output.

        Scans forward from each GRE key line looking for the inner packet
        line.  Checks for both the IP pair and the ICMP message directly in
        the candidate line, which works for IPv4 and IPv6 (the IPv6 line
        format embeds metadata before the addresses, making split unreliable).
        Using 'echo request'/'echo reply' matches both ICMP and ICMPv6.

        BOTH direction must have at least one match for each of IN and OUT.
        """
        directions = [direction] if direction != "BOTH" else ['IN', 'OUT']
        for d in directions:
            left_ip = ip_sender if d == 'IN' else ip_receiver
            right_ip = ip_receiver if d == 'IN' else ip_sender
            icmp_msg = 'echo request' if d == 'IN' else 'echo reply'
            found_log = False
            for i, line in enumerate(output_lines):
                if key not in line:
                    continue
                lookahead = output_lines[i + 1:i + 6]
                if any(icmp_msg in c and f'{left_ip} > {right_ip}' in c
                      for c in lookahead):
                    found_log = True
                    break
            self.assertTrue(found_log, msg=f"Did not find direction "
                f"{direction} and key {key} in the tcpdump log")

    @decorators.idempotent_id('7a4f9d54-16e8-499f-9791-0217aee309e1')
    def test_one_source_two_dest_remote_ip_mirror(self):
        """Test traffic from 1 src VM mirrored to 2 destination VM remote IPs

        .. code-block:: HTML

               +-------------+   +-------------+
               | Monitor VM1 |   | Monitor VM2 |
               |   FIP       |   |   FIP       |
               +------+------+   +------+------+
                      |                 |
               +------+------+   +------+------+
               |   NetMon1   |   |   NetMon2   |
               +-------------+   +-------------+
               +-------------------+
               |       Net0        |
               +---+----------+----+
                   |          |
                   |          |
               +---+-+      +-+---+
               | VM0 |      | VM1 |
               +-----+      +-----+

        VM0 source port is mirrored via GRE to 2 remote IPs (monitor VMs)
        using BOTH direction with tunnel ids 105 and 106.
        """

        if not self.is_driver_ovn:
            raise self.skipException("Test is supported only in OVN")

        result = _run_one_source_two_dest_mirror(self, mirror_type='gre')
        output1 = result['output1']
        output2 = result['output2']
        vm0_ip = result['vm0_ip']
        vm1_ip = result['vm1_ip']
        directions1 = result['directions1']
        directions2 = result['directions2']

        output1_lines = output1.splitlines()
        output2_lines = output2.splitlines()
        # vm0_port IN captures echo reply (vm1->vm0), OUT captures echo request
        self._check_icmp_mirror_direction(output1_lines, vm0_ip, vm1_ip,
                                          "OUT", "key=0x65")
        self._check_icmp_mirror_direction(output1_lines, vm0_ip, vm1_ip,
                                          "IN", "key=0x66")
        if 'BOTH' in directions1:
            self._check_icmp_mirror_direction(output1_lines, vm0_ip, vm1_ip,
                                              "BOTH", "key=0x69")
        self._check_icmp_mirror_direction(output2_lines, vm0_ip, vm1_ip,
                                          "OUT", "key=0x67")
        self._check_icmp_mirror_direction(output2_lines, vm0_ip, vm1_ip,
                                          "IN", "key=0x68")
        if 'BOTH' in directions2:
            self._check_icmp_mirror_direction(output2_lines, vm0_ip, vm1_ip,
                                              "BOTH", "key=0x6a")

    @decorators.idempotent_id('640e8e23-00f4-457c-8e91-04bb011fa94c')
    def test_two_source_one_dest_remote_ip_mirror(self):
        """Test traffic from 2 src VMs mirrored to 1 destination VM remote IP

        .. code-block:: HTML

               +------------+
               | Monitor VM |
               |   FIP      |
               +-----+------+
                     |
                     |
               +-----+------+
               |   NetMon   |
               +------------+
               +-------------------+
               |       Net0        |
               +---+----------+----+
                   |          |
                   |          |
               +---+-+      +-+---+
               | VM0 |      | VM1 |
               +-----+      +-----+

        Both VM0 and VM1 source ports are mirrored via GRE to the remote IP
        of the monitor VM using BOTH direction with tunnel ids 105 and 106.
        """

        if not self.is_driver_ovn:
            raise self.skipException("Test is supported only in OVN")

        result = _run_two_source_one_dest_mirror(self, mirror_type='gre')
        output = result['output']
        vm0_ip = result['vm0_ip']
        vm1_ip = result['vm1_ip']
        directions_vm0 = result['directions_vm0']
        directions_vm1 = result['directions_vm1']

        output_lines = output.splitlines()
        # vm0_port IN captures echo reply (vm1->vm0), OUT captures echo request
        self._check_icmp_mirror_direction(output_lines, vm0_ip, vm1_ip,
                                          "OUT", "key=0x65")
        self._check_icmp_mirror_direction(output_lines, vm0_ip, vm1_ip,
                                          "IN", "key=0x66")
        if 'BOTH' in directions_vm0:
            self._check_icmp_mirror_direction(output_lines, vm0_ip, vm1_ip,
                                              "BOTH", "key=0x69")
        # vm1_port IN captures echo request (vm0->vm1), OUT captures echo
        # reply (vm1->vm0)
        self._check_icmp_mirror_direction(output_lines, vm0_ip, vm1_ip,
                                          "IN", "key=0x67")
        self._check_icmp_mirror_direction(output_lines, vm0_ip, vm1_ip,
                                          "OUT", "key=0x68")
        if 'BOTH' in directions_vm1:
            self._check_icmp_mirror_direction(output_lines, vm0_ip, vm1_ip,
                                              "BOTH", "key=0x6a")
