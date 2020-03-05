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

import collections

from neutron_lib import constants
from oslo_log import log as logging
from tempest.common import utils as tutils
from tempest.lib.common.utils import data_utils
from tempest.lib import decorators
import testtools

from neutron_tempest_plugin.common import ip
from neutron_tempest_plugin.common import ssh
from neutron_tempest_plugin.common import utils
from neutron_tempest_plugin import config
from neutron_tempest_plugin.scenario import base


LOG = logging.getLogger(__name__)
CONF = config.CONF


ServerWithTrunkPort = collections.namedtuple(
    'ServerWithTrunkPort',
    ['port', 'subport', 'trunk', 'floating_ip', 'server',
     'ssh_client'])


class TrunkTest(base.BaseTempestTestCase):
    credentials = ['primary', 'admin']
    force_tenant_isolation = False

    @classmethod
    @tutils.requires_ext(extension="trunk", service="network")
    def resource_setup(cls):
        super(TrunkTest, cls).resource_setup()
        # setup basic topology for servers we can log into
        cls.rand_name = data_utils.rand_name(
            cls.__name__.rsplit('.', 1)[-1])
        cls.network = cls.create_network(name=cls.rand_name)
        cls.subnet = cls.create_subnet(network=cls.network,
                                       name=cls.rand_name)
        cls.router = cls.create_router_by_client()
        cls.create_router_interface(cls.router['id'], cls.subnet['id'])
        cls.keypair = cls.create_keypair(name=cls.rand_name)

    def setUp(self):
        super(TrunkTest, self).setUp()
        self.security_group = self.create_security_group(name=self.rand_name)
        self.create_loginable_secgroup_rule(self.security_group['id'])

    def _create_server_with_network(self, network, use_advanced_image=False):
        port = self._create_server_port(network=network)
        floating_ip = self.create_floatingip(port=port)
        ssh_client = self._create_ssh_client(
            floating_ip=floating_ip, use_advanced_image=use_advanced_image)
        server = self._create_server(port=port,
                                     use_advanced_image=use_advanced_image)
        return ServerWithTrunkPort(port=port, subport=None, trunk=None,
                                   floating_ip=floating_ip, server=server,
                                   ssh_client=ssh_client)

    def _create_server_with_trunk_port(self, subport_network=None,
                                       segmentation_id=None,
                                       use_advanced_image=False):
        port = self._create_server_port()
        floating_ip = self.create_floatingip(port=port)
        ssh_client = self._create_ssh_client(
            floating_ip=floating_ip, use_advanced_image=use_advanced_image)

        subport = None
        subports = None
        if subport_network:
            subport = self._create_server_port(
                network=subport_network, mac_address=port['mac_address'])
            subports = [{'port_id': subport['id'],
                         'segmentation_type': 'vlan',
                         'segmentation_id': segmentation_id}]
        trunk = self.create_trunk(port=port, subports=subports)

        server = self._create_server(port=port,
                                     use_advanced_image=use_advanced_image)
        return ServerWithTrunkPort(port=port, subport=subport, trunk=trunk,
                                   floating_ip=floating_ip, server=server,
                                   ssh_client=ssh_client)

    def _create_server_port(self, network=None, **params):
        network = network or self.network
        return self.create_port(network=network, name=self.rand_name,
                                security_groups=[self.security_group['id']],
                                **params)

    def _create_server(self, port, use_advanced_image=False, **params):
        if use_advanced_image:
            flavor_ref = CONF.neutron_plugin_options.advanced_image_flavor_ref
            image_ref = CONF.neutron_plugin_options.advanced_image_ref
        else:
            flavor_ref = CONF.compute.flavor_ref
            image_ref = CONF.compute.image_ref
        return self.create_server(flavor_ref=flavor_ref,
                                  image_ref=image_ref,
                                  key_name=self.keypair['name'],
                                  networks=[{'port': port['id']}],
                                  **params)['server']

    def _show_port(self, port, update=False):
        observed = self.client.show_port(port['id'])['port']
        if update:
            port.update(observed)
        return observed

    def _show_trunk(self, trunk, update=False):
        observed = self.client.show_trunk(trunk['id'])['trunk']
        if update:
            trunk.update(observed)
        return observed

    def _is_trunk_status(self, trunk, status, update=False):
        return self._show_trunk(trunk, update)['status'] == status

    def _is_port_status(self, port, status, update=False):
        return self._show_port(port, update)['status'] == status

    def _wait_for_port(self, port, status=constants.ACTIVE):
        utils.wait_until_true(
            lambda: self._is_port_status(port, status),
            exception=RuntimeError(
                "Timed out waiting for port {!r} to transition to get "
                "status {!r}.".format(port['id'], status)))

    def _wait_for_trunk(self, trunk, status=constants.ACTIVE):
        utils.wait_until_true(
            lambda: self._is_trunk_status(trunk, status),
            exception=RuntimeError(
                "Timed out waiting for trunk {!r} to transition to get "
                "status {!r}.".format(trunk['id'], status)))

    def _create_ssh_client(self, floating_ip, use_advanced_image=False):
        if use_advanced_image:
            username = CONF.neutron_plugin_options.advanced_image_ssh_user
        else:
            username = CONF.validation.image_ssh_user
        return ssh.Client(host=floating_ip['floating_ip_address'],
                          username=username,
                          pkey=self.keypair['private_key'])

    def _assert_has_ssh_connectivity(self, ssh_client):
        ssh_client.exec_command("true")

    def _configure_vlan_subport(self, vm, vlan_tag, vlan_subnet):
        self.wait_for_server_active(server=vm.server)
        self._wait_for_trunk(trunk=vm.trunk)
        self._wait_for_port(port=vm.port)
        self._wait_for_port(port=vm.subport)

        ip_command = ip.IPCommand(ssh_client=vm.ssh_client)
        for address in ip_command.list_addresses(port=vm.port):
            port_iface = address.device.name
            break
        else:
            self.fail("Parent port fixed IP not found on server.")

        subport_iface = ip_command.configure_vlan_subport(
            port=vm.port, subport=vm.subport, vlan_tag=vlan_tag,
            subnets=[vlan_subnet])
        for address in ip_command.list_addresses(port=vm.subport):
            self.assertEqual(subport_iface, address.device.name)
            self.assertEqual(port_iface, address.device.parent)
            break
        else:
            self.fail("Sub-port fixed IP not found on server.")

    @decorators.idempotent_id('bb13fe28-f152-4000-8131-37890a40c79e')
    def test_trunk_subport_lifecycle(self):
        """Test trunk creation and subport transition to ACTIVE status.

        This is a basic test for the trunk extension to ensure that we
        can create a trunk, attach it to a server, add/remove subports,
        while ensuring the status transitions as appropriate.

        This test does not assert any dataplane behavior for the subports.
        It's just a high-level check to ensure the agents claim to have
        wired the port correctly and that the trunk port itself maintains
        connectivity.
        """
        vm1 = self._create_server_with_trunk_port()
        vm2 = self._create_server_with_trunk_port()
        for vm in (vm1, vm2):
            self.wait_for_server_active(server=vm.server)
            self._wait_for_trunk(vm.trunk)
            self._assert_has_ssh_connectivity(vm.ssh_client)

        # create a few more networks and ports for subports
        # check limit of networks per project
        segment_ids = range(
            3, 3 + CONF.neutron_plugin_options.max_networks_per_project)
        tagged_networks = [self.create_network() for _ in segment_ids]
        tagged_ports = [self.create_port(network=network)
                        for network in tagged_networks]
        subports = [{'port_id': tagged_ports[i]['id'],
                     'segmentation_type': 'vlan',
                     'segmentation_id': segment_id}
                    for i, segment_id in enumerate(segment_ids)]

        # add all subports to server1
        self.client.add_subports(vm1.trunk['id'], subports)
        self._wait_for_trunk(vm1.trunk)
        for port in tagged_ports:
            self._wait_for_port(port)

        # ensure main data-plane wasn't interrupted
        self._assert_has_ssh_connectivity(vm1.ssh_client)

        # move subports over to other server
        self.client.remove_subports(vm1.trunk['id'], subports)
        # ensure all subports go down
        for port in tagged_ports:
            self._wait_for_port(port, status=constants.DOWN)

        self.client.add_subports(vm2.trunk['id'], subports)

        # wait for both trunks to go back to ACTIVE
        for vm in [vm1, vm2]:
            self._wait_for_trunk(vm.trunk)

        # ensure subports come up on other trunk
        for port in tagged_ports:
            self._wait_for_port(port)

        # final connectivity check
        for vm in [vm1, vm2]:
            self._wait_for_trunk(vm.trunk)
            self._assert_has_ssh_connectivity(vm1.ssh_client)

    @testtools.skipUnless(
        (CONF.neutron_plugin_options.advanced_image_ref or
         CONF.neutron_plugin_options.default_image_is_advanced),
        "Advanced image is required to run this test.")
    @decorators.idempotent_id('a8a02c9b-b453-49b5-89a2-cce7da66aafb')
    def test_subport_connectivity(self):
        vlan_tag = 10
        vlan_network = self.create_network()
        vlan_subnet = self.create_subnet(network=vlan_network, gateway=None)

        use_advanced_image = (
            not CONF.neutron_plugin_options.default_image_is_advanced)

        vm1 = self._create_server_with_trunk_port(
            subport_network=vlan_network,
            segmentation_id=vlan_tag,
            use_advanced_image=use_advanced_image)
        vm2 = self._create_server_with_trunk_port(
            subport_network=vlan_network,
            segmentation_id=vlan_tag,
            use_advanced_image=use_advanced_image)

        for vm in [vm1, vm2]:
            self._configure_vlan_subport(vm=vm,
                                         vlan_tag=vlan_tag,
                                         vlan_subnet=vlan_subnet)

        # Ping from server1 to server2 via VLAN interface should fail because
        # we haven't allowed ICMP
        self.check_remote_connectivity(
            vm1.ssh_client,
            vm2.subport['fixed_ips'][0]['ip_address'],
            should_succeed=False)

        # allow intra-security-group traffic
        sg_rule = self.create_pingable_secgroup_rule(self.security_group['id'])
        self.addCleanup(
                self.os_primary.network_client.delete_security_group_rule,
                sg_rule['id'])
        self.check_remote_connectivity(
            vm1.ssh_client,
            vm2.subport['fixed_ips'][0]['ip_address'],
            servers=[vm1, vm2])

    @testtools.skipUnless(CONF.compute_feature_enabled.cold_migration,
                          'Cold migration is not available.')
    @testtools.skipUnless(CONF.compute.min_compute_nodes > 1,
                          'Less than 2 compute nodes, skipping multinode '
                          'tests.')
    @testtools.skipUnless(
        (CONF.neutron_plugin_options.advanced_image_ref or
         CONF.neutron_plugin_options.default_image_is_advanced),
        "Advanced image is required to run this test.")
    @decorators.attr(type='slow')
    @decorators.idempotent_id('ecd7de30-1c90-4280-b97c-1bed776d5d07')
    def test_trunk_vm_migration(self):
        '''Test connectivity after migration of the server with trunk

        A successfully migrated server shows a VERIFY_RESIZE status that
        requires confirmation. Need to reconfigure VLAN interface on server
        side after migration is finished as the configuration doesn't survive
        the reboot.
        '''
        vlan_tag = 10
        vlan_network = self.create_network()
        vlan_subnet = self.create_subnet(vlan_network)
        sg_rule = self.create_pingable_secgroup_rule(self.security_group['id'])
        self.addCleanup(
                self.os_primary.network_client.delete_security_group_rule,
                sg_rule['id'])

        use_advanced_image = (
            not CONF.neutron_plugin_options.default_image_is_advanced)
        servers = {}
        for role in ['migrate', 'connection_test']:
            servers[role] = self._create_server_with_trunk_port(
                                subport_network=vlan_network,
                                segmentation_id=vlan_tag,
                                use_advanced_image=use_advanced_image)
        for role in ['migrate', 'connection_test']:
            self.wait_for_server_active(servers[role].server)
            self._configure_vlan_subport(vm=servers[role],
                                         vlan_tag=vlan_tag,
                                         vlan_subnet=vlan_subnet)

        self.check_remote_connectivity(
                servers['connection_test'].ssh_client,
                servers['migrate'].subport['fixed_ips'][0]['ip_address'])

        client = self.os_admin.compute.ServersClient()
        client.migrate_server(servers['migrate'].server['id'])
        self.wait_for_server_status(servers['migrate'].server,
                                    'VERIFY_RESIZE')
        client.confirm_resize_server(servers['migrate'].server['id'])
        self._configure_vlan_subport(vm=servers['migrate'],
                                     vlan_tag=vlan_tag,
                                     vlan_subnet=vlan_subnet)

        self.check_remote_connectivity(
                servers['connection_test'].ssh_client,
                servers['migrate'].subport['fixed_ips'][0]['ip_address'])

    @testtools.skipUnless(
        (CONF.neutron_plugin_options.advanced_image_ref or
         CONF.neutron_plugin_options.default_image_is_advanced),
        "Advanced image is required to run this test.")
    @testtools.skipUnless(
        CONF.neutron_plugin_options.q_agent == "linuxbridge",
        "Linux bridge agent is required to run this test.")
    @decorators.idempotent_id('d61cbdf6-1896-491c-b4b4-871caf7fbffe')
    def test_parent_port_connectivity_after_trunk_deleted_lb(self):
        vlan_tag = 10
        vlan_network = self.create_network()
        vlan_subnet = self.create_subnet(vlan_network)
        self.create_router_interface(self.router['id'], vlan_subnet['id'])

        use_advanced_image = (
            not CONF.neutron_plugin_options.default_image_is_advanced)

        # Create servers
        trunk_network_server = self._create_server_with_trunk_port(
            subport_network=vlan_network,
            segmentation_id=vlan_tag,
            use_advanced_image=use_advanced_image)
        normal_network_server = self._create_server_with_network(self.network)
        vlan_network_server = self._create_server_with_network(vlan_network)
        vms = [normal_network_server, vlan_network_server]

        self._configure_vlan_subport(vm=trunk_network_server,
                                     vlan_tag=vlan_tag,
                                     vlan_subnet=vlan_subnet)
        for vm in vms:
            self.wait_for_server_active(vm.server)

        # allow ICMP traffic
        sg_rule = self.create_pingable_secgroup_rule(self.security_group['id'])
        self.addCleanup(
                self.os_primary.network_client.delete_security_group_rule,
                sg_rule['id'])

        # Ping from trunk_network_server to normal_network_server
        # via parent port
        self.check_remote_connectivity(
            trunk_network_server.ssh_client,
            normal_network_server.port['fixed_ips'][0]['ip_address'],
            should_succeed=True,
            servers=vms)

        # Ping from trunk_network_server to vlan_network_server via VLAN
        # interface should success
        self.check_remote_connectivity(
            trunk_network_server.ssh_client,
            vlan_network_server.port['fixed_ips'][0]['ip_address'],
            should_succeed=True,
            servers=vms)

        # Delete the trunk
        self.delete_trunk(
            trunk_network_server.trunk,
            detach_parent_port=False)
        LOG.debug("Trunk %s is deleted.",
                  trunk_network_server.trunk['id'])

        # Ping from trunk_network_server to normal_network_server
        # via parent port success after trunk deleted
        self.check_remote_connectivity(
            trunk_network_server.ssh_client,
            normal_network_server.port['fixed_ips'][0]['ip_address'],
            should_succeed=True,
            servers=vms)

        # Ping from trunk_network_server to vlan_network_server via VLAN
        # interface should fail after trunk deleted
        self.check_remote_connectivity(
            trunk_network_server.ssh_client,
            vlan_network_server.port['fixed_ips'][0]['ip_address'],
            should_succeed=False)
