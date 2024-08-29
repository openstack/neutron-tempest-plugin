# Copyright (c) 2017 Midokura SARL
# All Rights Reserved.
#
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

import time

import ddt
from neutron_lib import constants as lib_constants
from neutron_lib.services.qos import constants as qos_consts
from oslo_log import log
from tempest.common import utils
from tempest.common import waiters
from tempest.lib.common.utils import data_utils
from tempest.lib import decorators
from tempest.lib import exceptions
import testtools

from neutron_tempest_plugin.api import base as base_api
from neutron_tempest_plugin.common import ssh
from neutron_tempest_plugin.common import utils as common_utils
from neutron_tempest_plugin import config
from neutron_tempest_plugin.scenario import base
from neutron_tempest_plugin.scenario import constants
from neutron_tempest_plugin.scenario import test_qos


CONF = config.CONF
LOG = log.getLogger(__name__)


class FloatingIpTestCasesMixin(object):
    credentials = ['primary', 'admin']

    @classmethod
    @utils.requires_ext(extension="router", service="network")
    def resource_setup(cls):
        super(FloatingIpTestCasesMixin, cls).resource_setup()
        cls.network = cls.create_network()
        cls.subnet = cls.create_subnet(cls.network)
        cls.router = cls.create_router_by_client()
        cls.create_router_interface(cls.router['id'], cls.subnet['id'])
        cls.keypair = cls.create_keypair()

        cls.secgroup = cls.os_primary.network_client.create_security_group(
            name=data_utils.rand_name('secgroup'))['security_group']
        cls.security_groups.append(cls.secgroup)
        cls.create_loginable_secgroup_rule(secgroup_id=cls.secgroup['id'])
        cls.create_pingable_secgroup_rule(secgroup_id=cls.secgroup['id'])

        if cls.same_network:
            cls._dest_network = cls.network
        else:
            cls._dest_network = cls._create_dest_network()

    @classmethod
    def _get_external_gateway(cls):
        if CONF.network.public_network_id:
            subnets = cls.os_admin.network_client.list_subnets(
                network_id=CONF.network.public_network_id)

            for subnet in subnets['subnets']:
                if (subnet['gateway_ip'] and
                    subnet['ip_version'] == lib_constants.IP_VERSION_4):
                    return subnet['gateway_ip']

    @classmethod
    def _create_dest_network(cls):
        network = cls.create_network()
        subnet = cls.create_subnet(network)
        cls.create_router_interface(cls.router['id'], subnet['id'])
        return network

    def _create_server(self, create_floating_ip=True, network=None):
        if network is None:
            network = self.network
        port = self.create_port(network, security_groups=[self.secgroup['id']])
        if create_floating_ip:
            fip = self.create_floatingip(port=port)
        else:
            fip = None
        server = self.create_server(
            flavor_ref=CONF.compute.flavor_ref,
            image_ref=CONF.compute.image_ref,
            key_name=self.keypair['name'],
            networks=[{'port': port['id']}])['server']
        waiters.wait_for_server_status(self.os_primary.servers_client,
                                       server['id'],
                                       constants.SERVER_STATUS_ACTIVE)
        return {'port': port, 'fip': fip, 'server': server}

    def _test_east_west(self, src_has_fip, dest_has_fip):
        # The proxy VM is used to control the source VM when it doesn't
        # have a floating-ip.
        if src_has_fip:
            proxy = None
            proxy_client = None
        else:
            proxy = self._create_server()
            proxy_client = ssh.Client(proxy['fip']['floating_ip_address'],
                                      CONF.validation.image_ssh_user,
                                      pkey=self.keypair['private_key'])

        # Source VM
        if src_has_fip:
            src_server = self._create_server()
            src_server_ip = src_server['fip']['floating_ip_address']
        else:
            src_server = self._create_server(create_floating_ip=False)
            src_server_ip = src_server['port']['fixed_ips'][0]['ip_address']
        ssh_client = ssh.Client(src_server_ip,
                                CONF.validation.image_ssh_user,
                                pkey=self.keypair['private_key'],
                                proxy_client=proxy_client)

        # Destination VM
        if dest_has_fip:
            dest_server = self._create_server(network=self._dest_network)
        else:
            dest_server = self._create_server(create_floating_ip=False,
                                              network=self._dest_network)

        # Check connectivity
        self.check_remote_connectivity(ssh_client,
            dest_server['port']['fixed_ips'][0]['ip_address'],
            servers=[src_server, dest_server])
        if dest_has_fip:
            self.check_remote_connectivity(ssh_client,
                dest_server['fip']['floating_ip_address'],
                servers=[src_server, dest_server])


@ddt.ddt
class FloatingIpSameNetwork(FloatingIpTestCasesMixin,
                            base.BaseTempestTestCase):

    same_network = True

    @decorators.idempotent_id('05c4e3b3-7319-4052-90ad-e8916436c23b')
    @ddt.unpack
    @ddt.data({'src_has_fip': True, 'dest_has_fip': True},
              {'src_has_fip': True, 'dest_has_fip': False},
              {'src_has_fip': False, 'dest_has_fip': True},
              {'src_has_fip': True, 'dest_has_fip': False})
    def test_east_west(self, src_has_fip, dest_has_fip):
        self._test_east_west(src_has_fip=src_has_fip,
                             dest_has_fip=dest_has_fip)


@ddt.ddt
class FloatingIpSeparateNetwork(FloatingIpTestCasesMixin,
                                base.BaseTempestTestCase):

    same_network = False

    @decorators.idempotent_id('f18f0090-3289-4783-b956-a0f8ac511e8b')
    @ddt.unpack
    @ddt.data({'src_has_fip': True, 'dest_has_fip': True},
              {'src_has_fip': True, 'dest_has_fip': False},
              {'src_has_fip': False, 'dest_has_fip': True},
              {'src_has_fip': True, 'dest_has_fip': False})
    def test_east_west(self, src_has_fip, dest_has_fip):
        self._test_east_west(src_has_fip=src_has_fip,
                             dest_has_fip=dest_has_fip)


class DefaultSnatToExternal(FloatingIpTestCasesMixin,
                            base.BaseTempestTestCase):
    same_network = True

    @decorators.idempotent_id('3d73ea1a-27c6-45a9-b0f8-04a283d9d764')
    def test_snat_external_ip(self):
        """Check connectivity to an external IP"""
        gateway_external_ip = self._get_external_gateway()

        if not gateway_external_ip:
            raise self.skipTest("IPv4 gateway is not configured for public "
                                "network or public_network_id is not "
                                "configured")
        proxy = self._create_server()
        proxy_client = ssh.Client(proxy['fip']['floating_ip_address'],
                                  CONF.validation.image_ssh_user,
                                  pkey=self.keypair['private_key'])
        src_server = self._create_server(create_floating_ip=False)
        src_server_ip = src_server['port']['fixed_ips'][0]['ip_address']
        ssh_client = ssh.Client(src_server_ip,
                                CONF.validation.image_ssh_user,
                                pkey=self.keypair['private_key'],
                                proxy_client=proxy_client)
        self.check_remote_connectivity(ssh_client,
                                       gateway_external_ip,
                                       servers=[proxy, src_server])

    @decorators.idempotent_id('b911b124-b6cb-449d-83d9-b34f3665741d')
    @utils.requires_ext(extension='extraroute', service='network')
    @testtools.skipUnless(
        CONF.neutron_plugin_options.snat_rules_apply_to_nested_networks,
        "Backend doesn't enable nested SNAT.")
    def test_nested_snat_external_ip(self):
        """Check connectivity to an external IP from a nested network."""
        gateway_external_ip = self._get_external_gateway()

        if not gateway_external_ip:
            raise self.skipTest("IPv4 gateway is not configured for public "
                                "network or public_network_id is not "
                                "configured")
        proxy = self._create_server()
        proxy_client = ssh.Client(proxy['fip']['floating_ip_address'],
                                  CONF.validation.image_ssh_user,
                                  pkey=self.keypair['private_key'])

        # Create a nested router
        router = self.create_router(
            router_name=data_utils.rand_name('router'),
            admin_state_up=True)

        # Attach outer subnet to it
        outer_port = self.create_port(self.network)
        self.client.add_router_interface_with_port_id(router['id'],
                                                      outer_port['id'])

        # Attach a nested subnet to it
        network = self.create_network()
        subnet = self.create_subnet(network)
        self.create_router_interface(router['id'], subnet['id'])

        # Set up static routes in both directions
        self.client.update_extra_routes(
            self.router['id'],
            outer_port['fixed_ips'][0]['ip_address'], subnet['cidr'])
        self.client.update_extra_routes(
            router['id'], self.subnet['gateway_ip'], '0.0.0.0/0')

        # Create a server inside the nested network
        src_server = self._create_server(create_floating_ip=False,
                                         network=network)

        # Validate that it can access external gw ip (via nested snat)
        src_server_ip = src_server['port']['fixed_ips'][0]['ip_address']
        ssh_client = ssh.Client(src_server_ip,
                                CONF.validation.image_ssh_user,
                                pkey=self.keypair['private_key'],
                                proxy_client=proxy_client)
        self.check_remote_connectivity(ssh_client,
                                       gateway_external_ip,
                                       servers=[proxy, src_server])


class FloatingIPPortDetailsTest(FloatingIpTestCasesMixin,
                                base.BaseTempestTestCase):
    same_network = True

    @classmethod
    @utils.requires_ext(extension="router", service="network")
    @utils.requires_ext(extension="fip-port-details", service="network")
    def resource_setup(cls):
        super(FloatingIPPortDetailsTest, cls).resource_setup()

    @decorators.idempotent_id('a663aeee-dd81-492b-a207-354fd6284dbe')
    def test_floatingip_port_details(self):
        """Tests the following:

        1. Create a port with floating ip in Neutron.
        2. Create two servers in Nova.
        3. Attach the port to the server.
        4. Detach the port from the server.
        5. Attach the port to the second server.
        6. Detach the port from the second server.
        """
        port = self.create_port(self.network)
        fip = self.create_and_associate_floatingip(port['id'])
        server1 = self._create_server(create_floating_ip=False)
        server2 = self._create_server(create_floating_ip=False)

        for server in [server1, server2]:
            # attach the port to the server
            self.create_interface(
                server['server']['id'], port_id=port['id'])
            waiters.wait_for_interface_status(
                self.os_primary.interfaces_client, server['server']['id'],
                port['id'], lib_constants.PORT_STATUS_ACTIVE)
            fip = self.client.show_floatingip(fip['id'])['floatingip']
            server_data = self.os_admin.servers_client.show_server(
                server['server']['id'])['server']
            zone = 'compute:' + server_data['OS-EXT-AZ:availability_zone']
            self._check_port_details(
                fip, port, status=lib_constants.PORT_STATUS_ACTIVE,
                device_id=server['server']['id'],
                device_owner=zone)
            LOG.debug('Port check for server %s and FIP %s finished, '
                      'lets detach port %s from server!',
                      server['server']['id'], fip['id'], port['id'])

            # detach the port from the server; this is a cast in the compute
            # API so we have to poll the port until the device_id is unset.
            self.delete_interface(server['server']['id'], port['id'])
            port = self._wait_for_port_detach(port['id'])
            LOG.debug('Port %s has been detached from server %s, lets check '
                      'the status of port in FIP %s details!',
                      port['id'], server['server']['id'], fip['id'])
            fip = self._wait_for_fip_port_down(fip['id'])
            self._check_port_details(
                fip, port, status=lib_constants.PORT_STATUS_DOWN,
                device_id='', device_owner='')

    def _check_port_details(self, fip, port, status, device_id, device_owner):
        self.assertIn('port_details', fip)
        port_details = fip['port_details']
        self.assertEqual(port['name'], port_details['name'])
        self.assertEqual(port['network_id'], port_details['network_id'])
        self.assertEqual(port['mac_address'], port_details['mac_address'])
        self.assertEqual(port['admin_state_up'],
                         port_details['admin_state_up'])
        self.assertEqual(status, port_details['status'])
        self.assertEqual(device_id, port_details['device_id'])
        self.assertEqual(device_owner, port_details['device_owner'])

    def _wait_for_port_detach(self, port_id, timeout=120, interval=10):
        """Waits for the port's device_id to be unset.

        :param port_id: The id of the port being detached.
        :returns: The final port dict from the show_port response.
        """
        port = self.client.show_port(port_id)['port']
        device_id = port['device_id']
        start = int(time.time())

        # NOTE(mriedem): Nova updates the port's device_id to '' rather than
        # None, but it's not contractual so handle Falsey either way.
        while device_id:
            time.sleep(interval)
            port = self.client.show_port(port_id)['port']
            device_id = port['device_id']

            timed_out = int(time.time()) - start >= timeout

            if device_id and timed_out:
                message = ('Port %s failed to detach (device_id %s) within '
                           'the required time (%s s).' %
                           (port_id, device_id, timeout))
                raise exceptions.TimeoutException(message)

        return port

    def _wait_for_fip_port_down(self, fip_id, timeout=120, interval=10):
        """Waits for the fip's attached port status to be 'DOWN'.

        :param fip_id: The id of the floating IP.
        :returns: The final fip dict from the show_floatingip response.
        """
        fip = self.client.show_floatingip(fip_id)['floatingip']
        self.assertIn('port_details', fip)
        port_details = fip['port_details']
        status = port_details['status']
        start = int(time.time())

        while status != lib_constants.PORT_STATUS_DOWN:
            time.sleep(interval)
            fip = self.client.show_floatingip(fip_id)['floatingip']
            self.assertIn('port_details', fip)
            port_details = fip['port_details']
            status = port_details['status']

            timed_out = int(time.time()) - start >= timeout

            if status != lib_constants.PORT_STATUS_DOWN and timed_out:
                port_id = fip.get("port_id")
                port = self.os_admin.network_client.show_port(port_id)['port']
                message = ('Floating IP %s attached port status failed to '
                           'transition to DOWN (current status %s) within '
                           'the required time (%s s). Port details: %s' %
                           (fip_id, status, timeout, port))
                raise exceptions.TimeoutException(message)

        LOG.debug('Port %s attached to FIP %s is down after %s!',
                  fip.get("port_id"), fip_id, int(time.time()) - start)
        return fip


class FloatingIPQosTest(FloatingIpTestCasesMixin,
                        test_qos.QoSTestMixin,
                        base.BaseTempestTestCase):

    same_network = True

    @classmethod
    @utils.requires_ext(extension="router", service="network")
    @utils.requires_ext(extension="qos", service="network")
    @utils.requires_ext(extension="qos-fip", service="network")
    @base_api.require_qos_rule_type(qos_consts.RULE_TYPE_BANDWIDTH_LIMIT)
    def resource_setup(cls):
        super(FloatingIPQosTest, cls).resource_setup()

    @classmethod
    def setup_clients(cls):
        super(FloatingIPQosTest, cls).setup_clients()
        cls.admin_client = cls.os_admin.network_client
        cls.qos_bw_limit_rule_client = \
            cls.os_admin.qos_limit_bandwidth_rules_client

    @decorators.idempotent_id('5eb48aea-eaba-4c20-8a6f-7740070a0aa3')
    def test_qos(self):
        """Test floating IP is binding to a QoS policy with

           ingress and egress bandwidth limit rules. And it applied correctly
           by sending a file from the instance to the test node.
           Then calculating the bandwidth every ~1 sec by the number of bits
           received / elapsed time.
        """

        self.skip_if_no_extension_enabled_in_l3_agents("fip_qos")

        self._test_basic_resources()

        # Create a new QoS policy
        policy_id = self._create_qos_policy()
        ssh_client = self._create_ssh_client()

        # As admin user create a new QoS rules
        rule_data = {'max_kbps': constants.LIMIT_KILO_BITS_PER_SECOND,
                     'max_burst_kbps': constants.LIMIT_KILO_BYTES,
                     'direction': lib_constants.INGRESS_DIRECTION}
        self.qos_bw_limit_rule_client.create_limit_bandwidth_rule(
             qos_policy_id=policy_id, **rule_data)

        rule_data = {'max_kbps': constants.LIMIT_KILO_BITS_PER_SECOND,
                     'max_burst_kbps': constants.LIMIT_KILO_BYTES,
                     'direction': lib_constants.EGRESS_DIRECTION}
        self.qos_bw_limit_rule_client.create_limit_bandwidth_rule(
             qos_policy_id=policy_id, **rule_data)

        rules = self.qos_bw_limit_rule_client.list_limit_bandwidth_rules(
            policy_id)
        self.assertEqual(2, len(rules['bandwidth_limit_rules']))

        fip = self.os_admin.network_client.get_floatingip(
            self.fip['id'])['floatingip']
        self.assertEqual(self.port['id'], fip['port_id'])

        # Associate QoS to the FIP
        self.os_admin.network_client.update_floatingip(
            self.fip['id'],
            qos_policy_id=policy_id)

        fip = self.os_admin.network_client.get_floatingip(
            self.fip['id'])['floatingip']
        self.assertEqual(policy_id, fip['qos_policy_id'])

        # Basic test, Check that actual BW while downloading file
        # is as expected (Original BW)
        common_utils.wait_until_true(lambda: self._check_bw(
            ssh_client,
            self.fip['floating_ip_address'],
            port=self.NC_PORT),
            timeout=120,
            sleep=1,
            exception=RuntimeError(
                'Failed scenario: "Create a QoS policy associated with FIP" '
                'Actual BW is not as expected!'))

        # As admin user update QoS rules
        for rule in rules['bandwidth_limit_rules']:
            self.qos_bw_limit_rule_client.update_limit_bandwidth_rule(
                policy_id, rule['id'],
                **{'max_kbps': constants.LIMIT_KILO_BITS_PER_SECOND * 2,
                   'max_burst_kbps': constants.LIMIT_KILO_BITS_PER_SECOND * 2})

        # Check that actual BW while downloading file
        # is as expected (Update BW)
        common_utils.wait_until_true(lambda: self._check_bw(
            ssh_client,
            self.fip['floating_ip_address'],
            port=self.NC_PORT,
            expected_bw=test_qos.QoSTestMixin.LIMIT_BYTES_SEC * 2),
            timeout=120,
            sleep=1,
            exception=RuntimeError(
                'Failed scenario: "Update QoS policy associated with FIP" '
                'Actual BW is not as expected!'))


class TestFloatingIPUpdate(FloatingIpTestCasesMixin,
                           base.BaseTempestTestCase):

    same_network = None

    @decorators.idempotent_id('1bdd849b-03dd-4b8f-994f-457cf8a36f93')
    def test_floating_ip_update(self):
        """Test updating FIP with another port.

        The test creates two servers and attaches floating ip to first server.
        Then it checks server is accesible using the FIP. FIP is then
        associated with the second server and connectivity is checked again.
        """
        ports = [self.create_port(
            self.network, security_groups=[self.secgroup['id']])
            for i in range(2)]

        servers = []
        for port in ports:
            name = data_utils.rand_name("server-%s" % port['id'][:8])
            server = self.create_server(
                name=name,
                flavor_ref=CONF.compute.flavor_ref,
                key_name=self.keypair['name'],
                image_ref=CONF.compute.image_ref,
                networks=[{'port': port['id']}])['server']
            server['name'] = name
            servers.append(server)
        for server in servers:
            self.wait_for_server_active(server)
            self.wait_for_guest_os_ready(server)

        self.fip = self.create_floatingip(port=ports[0])
        self.check_connectivity(self.fip['floating_ip_address'],
                                CONF.validation.image_ssh_user,
                                self.keypair['private_key'],
                                servers=servers)
        self.client.update_floatingip(self.fip['id'], port_id=ports[1]['id'])

        def _wait_for_fip_associated():
            try:
                self.check_servers_hostnames(servers[-1:], log_errors=False)
            except (AssertionError, exceptions.SSHTimeout):
                return False
            return True

        # The FIP is now associated with the port of the second server.
        try:
            common_utils.wait_until_true(_wait_for_fip_associated, sleep=3)
        except common_utils.WaitTimeout:
            self._log_console_output(servers[-1:])
            self.fail(
                "Server %s is not accessible via its floating ip %s" % (
                    servers[-1]['id'], self.fip['id']))


class FloatingIpMultipleRoutersTest(base.BaseTempestTestCase):
    credentials = ['primary', 'admin']

    @classmethod
    @utils.requires_ext(extension="router", service="network")
    def skip_checks(cls):
        super(FloatingIpMultipleRoutersTest, cls).skip_checks()

    def _create_keypair_and_secgroup(self):
        self.keypair = self.create_keypair()
        self.secgroup = self.create_security_group()
        self.create_loginable_secgroup_rule(
            secgroup_id=self.secgroup['id'])
        self.create_pingable_secgroup_rule(
            secgroup_id=self.secgroup['id'])

    def _delete_floating_ip(self, fip_address):
        ip_address = fip_address['floating_ip_address']

        def _fip_is_free():
            fips = self.os_admin.network_client.list_floatingips()
            for fip in fips['floatingips']:
                if ip_address == fip['floating_ip_address']:
                    return False
            return True

        self.delete_floatingip(fip_address)
        try:
            common_utils.wait_until_true(_fip_is_free, timeout=30, sleep=5)
        except common_utils.WaitTimeout:
            self.fail("Can't reuse IP address %s because it is not free" %
                      ip_address)

    def _create_network_and_servers(self, servers_num=1, fip_addresses=None,
                                    delete_fip_ids=None):
        delete_fip_ids = delete_fip_ids or []
        if fip_addresses:
            self.assertEqual(servers_num, len(fip_addresses),
                             ('Number of specified fip addresses '
                              'does not match the number of servers'))
        network = self.create_network()
        subnet = self.create_subnet(network)
        router = self.create_router_by_client()
        self.create_router_interface(router['id'], subnet['id'])

        fips = []
        for server in range(servers_num):
            fip = fip_addresses[server] if fip_addresses else None
            delete_fip = fip['id'] in delete_fip_ids if fip else False
            fips.append(
                self._create_server_and_fip(network=network,
                                            fip_address=fip,
                                            delete_fip_address=delete_fip))
        return fips

    def _create_server_and_fip(self, network, fip_address=None,
                               delete_fip_address=False):
        server = self.create_server(
            flavor_ref=CONF.compute.flavor_ref,
            image_ref=CONF.compute.image_ref,
            key_name=self.keypair['name'],
            networks=[{'uuid': network['id']}],
            security_groups=[{'name': self.secgroup['name']}])
        waiters.wait_for_server_status(self.os_primary.servers_client,
                                       server['server']['id'],
                                       constants.SERVER_STATUS_ACTIVE)
        port = self.client.list_ports(
            network_id=network['id'],
            device_id=server['server']['id'])['ports'][0]

        if fip_address:
            if delete_fip_address:
                self._delete_floating_ip(fip_address)
            fip = self.create_floatingip(
                floating_ip_address=fip_address['floating_ip_address'],
                client=self.os_admin.network_client,
                port=port)
            self.addCleanup(
                self.delete_floatingip, fip, self.os_admin.network_client)
        else:
            fip = self.create_floatingip(port=port)
        return fip

    def _check_fips_connectivity(self, mutable_fip, permanent_fip):
        for fip in [mutable_fip, permanent_fip]:
            fip['ssh_client'] = ssh.Client(fip['floating_ip_address'],
                                           CONF.validation.image_ssh_user,
                                           pkey=self.keypair['private_key'])
        self.check_remote_connectivity(
            permanent_fip['ssh_client'], mutable_fip['floating_ip_address'])
        self.check_remote_connectivity(
            mutable_fip['ssh_client'], permanent_fip['floating_ip_address'])

    @testtools.skipUnless(CONF.network.public_network_id,
                          'The public_network_id option must be specified.')
    @decorators.idempotent_id('b0382ab3-3c86-4415-84e3-649a8b040dab')
    def test_reuse_ip_address_with_other_fip_on_other_router(self):
        """Reuse IP address by another floating IP on another router

        Scenario:
            1. Create and connect a router to the external network.
            2. Create and connect an internal network to the router.
            3. Create and connect 2 VMs to the internal network.
            4. Create FIPs in the external network for the VMs.
            5. Make sure that VM1 can ping VM2 FIP address.
            6. Create and connect one more router to the external network.
            7. Create and connect an internal network to the second router.
            8. Create and connect a VM (VM3) to the internal network of
               the second router.
            9. Delete VM2 FIP but save IP address that it used. The FIP is
               deleted just before the creation of the new IP to "reserve" the
               IP address associated (see LP#1880976).
            10. Create a FIP for the VM3 in the external network with
                the same IP address that was used for VM2.
            11. Make sure that now VM1 is able to reach VM3 using the FIP.

        Note, the scenario passes only in case corresponding
        ARP update was sent to the external network when reusing same IP
        address for another FIP.
        """

        self._create_keypair_and_secgroup()
        [mutable_fip, permanent_fip] = (
            self._create_network_and_servers(servers_num=2))
        self._check_fips_connectivity(mutable_fip, permanent_fip)
        [mutable_fip] = self._create_network_and_servers(
            servers_num=1, fip_addresses=[mutable_fip],
            delete_fip_ids=[mutable_fip['id']])
        self._check_fips_connectivity(mutable_fip, permanent_fip)
