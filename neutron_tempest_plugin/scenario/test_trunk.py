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

from oslo_log import log as logging
from tempest.common import utils as tutils
from tempest.common import waiters
from tempest.lib.common.utils import data_utils
from tempest.lib import decorators
import testtools

from neutron_tempest_plugin.common import ssh
from neutron_tempest_plugin.common import utils
from neutron_tempest_plugin import config
from neutron_tempest_plugin.scenario import base
from neutron_tempest_plugin.scenario import constants

LOG = logging.getLogger(__name__)
CONF = config.CONF

CONFIGURE_VLAN_INTERFACE_COMMANDS = (
    'IFACE=$(PATH=$PATH:/usr/sbin ip l | grep "^[0-9]*: e"|cut -d \: -f 2) &&'
    'sudo ip l a link $IFACE name $IFACE.%(tag)d type vlan id %(tag)d &&'
    'sudo ip l s up dev $IFACE.%(tag)d && '
    'ps -ef | grep -q "[d]hclient .*$IFACE.%(tag)d" || '
    'sudo dhclient $IFACE.%(tag)d;')


class TrunkTest(base.BaseTempestTestCase):
    credentials = ['primary']
    force_tenant_isolation = False

    @classmethod
    @tutils.requires_ext(extension="trunk", service="network")
    def resource_setup(cls):
        super(TrunkTest, cls).resource_setup()
        # setup basic topology for servers we can log into
        cls.network = cls.create_network()
        cls.subnet = cls.create_subnet(cls.network)
        cls.router = cls.create_router_by_client()
        cls.create_router_interface(cls.router['id'], cls.subnet['id'])
        cls.keypair = cls.create_keypair()
        cls.secgroup = cls.os_primary.network_client.create_security_group(
            name=data_utils.rand_name('secgroup'))
        cls.security_groups.append(cls.secgroup['security_group'])
        cls.create_loginable_secgroup_rule(
            secgroup_id=cls.secgroup['security_group']['id'])

    def _create_server_with_trunk_port(self):
        port = self.create_port(self.network, security_groups=[
            self.secgroup['security_group']['id']])
        trunk = self.create_trunk(port)
        server, fip = self._create_server_with_fip(port['id'])
        return {'port': port, 'trunk': trunk, 'fip': fip,
                'server': server}

    def _create_server_with_fip(self, port_id, use_advanced_image=False,
                                **server_kwargs):
        fip = self.create_floatingip(port_id=port_id)
        flavor_ref = CONF.compute.flavor_ref
        image_ref = CONF.compute.image_ref
        if use_advanced_image:
            flavor_ref = CONF.neutron_plugin_options.advanced_image_flavor_ref
            image_ref = CONF.neutron_plugin_options.advanced_image_ref
        return (
            self.create_server(
                flavor_ref=flavor_ref,
                image_ref=image_ref,
                key_name=self.keypair['name'],
                networks=[{'port': port_id}],
                security_groups=[{'name': self.secgroup[
                    'security_group']['name']}],
                **server_kwargs)['server'],
            fip)

    def _is_port_down(self, port_id):
        p = self.client.show_port(port_id)['port']
        return p['status'] == 'DOWN'

    def _is_port_active(self, port_id):
        p = self.client.show_port(port_id)['port']
        return p['status'] == 'ACTIVE'

    def _is_trunk_active(self, trunk_id):
        t = self.client.show_trunk(trunk_id)['trunk']
        return t['status'] == 'ACTIVE'

    def _create_server_with_network(self, network, use_advanced_image=False):
        port = self.create_port(network, security_groups=[
            self.secgroup['security_group']['id']])
        server, fip = self._create_server_with_fip(
            port['id'], use_advanced_image=use_advanced_image)
        ssh_user = CONF.validation.image_ssh_user
        if use_advanced_image:
            ssh_user = CONF.neutron_plugin_options.advanced_image_ssh_user

        server_ssh_client = ssh.Client(
            fip['floating_ip_address'],
            ssh_user,
            pkey=self.keypair['private_key'])

        return {
            'server': server,
            'fip': fip,
            'ssh_client': server_ssh_client,
            'port': port,
        }

    def _create_server_with_port_and_subport(self, vlan_network, vlan_tag,
                                             use_advanced_image=False):
        parent_port = self.create_port(self.network, security_groups=[
            self.secgroup['security_group']['id']])
        port_for_subport = self.create_port(
            vlan_network,
            security_groups=[self.secgroup['security_group']['id']],
            mac_address=parent_port['mac_address'])
        subport = {
            'port_id': port_for_subport['id'],
            'segmentation_type': 'vlan',
            'segmentation_id': vlan_tag}
        trunk = self.create_trunk(parent_port, [subport])

        server, fip = self._create_server_with_fip(
            parent_port['id'], use_advanced_image=use_advanced_image)

        ssh_user = CONF.validation.image_ssh_user
        if use_advanced_image:
            ssh_user = CONF.neutron_plugin_options.advanced_image_ssh_user

        server_ssh_client = ssh.Client(
            fip['floating_ip_address'],
            ssh_user,
            pkey=self.keypair['private_key'])

        return {
            'server': server,
            'fip': fip,
            'ssh_client': server_ssh_client,
            'subport': port_for_subport,
            'parentport': parent_port,
            'trunk': trunk,
        }

    def _wait_for_server(self, server, advanced_image=False):
        ssh_user = CONF.validation.image_ssh_user
        if advanced_image:
            ssh_user = CONF.neutron_plugin_options.advanced_image_ssh_user
        waiters.wait_for_server_status(self.os_primary.servers_client,
                                       server['server']['id'],
                                       constants.SERVER_STATUS_ACTIVE)
        self.check_connectivity(server['fip']['floating_ip_address'],
                                ssh_user,
                                self.keypair['private_key'])

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
        server1 = self._create_server_with_trunk_port()
        server2 = self._create_server_with_trunk_port()
        for server in (server1, server2):
            self._wait_for_server(server)
        trunk1_id, trunk2_id = server1['trunk']['id'], server2['trunk']['id']
        # trunks should transition to ACTIVE without any subports
        utils.wait_until_true(
            lambda: self._is_trunk_active(trunk1_id),
            exception=RuntimeError("Timed out waiting for trunk %s to "
                                   "transition to ACTIVE." % trunk1_id))
        utils.wait_until_true(
            lambda: self._is_trunk_active(trunk2_id),
            exception=RuntimeError("Timed out waiting for trunk %s to "
                                   "transition to ACTIVE." % trunk2_id))
        # create a few more networks and ports for subports
        # check limit of networks per project
        max_vlan = 3 + CONF.neutron_plugin_options.max_networks_per_project
        allowed_vlans = range(3, max_vlan)
        subports = [{'port_id': self.create_port(self.create_network())['id'],
                     'segmentation_type': 'vlan', 'segmentation_id': seg_id}
                    for seg_id in allowed_vlans]
        # add all subports to server1
        self.client.add_subports(trunk1_id, subports)
        # ensure trunk transitions to ACTIVE
        utils.wait_until_true(
            lambda: self._is_trunk_active(trunk1_id),
            exception=RuntimeError("Timed out waiting for trunk %s to "
                                   "transition to ACTIVE." % trunk1_id))
        # ensure all underlying subports transitioned to ACTIVE
        for s in subports:
            utils.wait_until_true(lambda: self._is_port_active(s['port_id']))
        # ensure main dataplane wasn't interrupted
        self.check_connectivity(server1['fip']['floating_ip_address'],
                                CONF.validation.image_ssh_user,
                                self.keypair['private_key'])
        # move subports over to other server
        self.client.remove_subports(trunk1_id, subports)
        # ensure all subports go down
        for s in subports:
            utils.wait_until_true(
                lambda: self._is_port_down(s['port_id']),
                exception=RuntimeError("Timed out waiting for subport %s to "
                                       "transition to DOWN." % s['port_id']))
        self.client.add_subports(trunk2_id, subports)
        # wait for both trunks to go back to ACTIVE
        utils.wait_until_true(
            lambda: self._is_trunk_active(trunk1_id),
            exception=RuntimeError("Timed out waiting for trunk %s to "
                                   "transition to ACTIVE." % trunk1_id))
        utils.wait_until_true(
            lambda: self._is_trunk_active(trunk2_id),
            exception=RuntimeError("Timed out waiting for trunk %s to "
                                   "transition to ACTIVE." % trunk2_id))
        # ensure subports come up on other trunk
        for s in subports:
            utils.wait_until_true(
                lambda: self._is_port_active(s['port_id']),
                exception=RuntimeError("Timed out waiting for subport %s to "
                                       "transition to ACTIVE." % s['port_id']))
        # final connectivity check
        self.check_connectivity(server1['fip']['floating_ip_address'],
                                CONF.validation.image_ssh_user,
                                self.keypair['private_key'])
        self.check_connectivity(server2['fip']['floating_ip_address'],
                                CONF.validation.image_ssh_user,
                                self.keypair['private_key'])

    @testtools.skipUnless(
          CONF.neutron_plugin_options.advanced_image_ref,
          "Advanced image is required to run this test.")
    @decorators.idempotent_id('a8a02c9b-b453-49b5-89a2-cce7da66aafb')
    def test_subport_connectivity(self):
        vlan_tag = 10

        vlan_network = self.create_network()
        self.create_subnet(vlan_network, gateway=None)

        servers = [
            self._create_server_with_port_and_subport(
                vlan_network, vlan_tag, use_advanced_image=True)
            for i in range(2)]

        for server in servers:
            self._wait_for_server(server, advanced_image=True)
            # Configure VLAN interfaces on server
            command = CONFIGURE_VLAN_INTERFACE_COMMANDS % {'tag': vlan_tag}
            server['ssh_client'].exec_command(command)
            out = server['ssh_client'].exec_command(
                'PATH=$PATH:/usr/sbin;ip addr list')
            LOG.debug("Interfaces on server %s: %s", server, out)

        # Ping from server1 to server2 via VLAN interface should fail because
        # we haven't allowed ICMP
        self.check_remote_connectivity(
            servers[0]['ssh_client'],
            servers[1]['subport']['fixed_ips'][0]['ip_address'],
            should_succeed=False
        )
        # allow intra-securitygroup traffic
        self.client.create_security_group_rule(
            security_group_id=self.secgroup['security_group']['id'],
            direction='ingress', ethertype='IPv4', protocol='icmp',
            remote_group_id=self.secgroup['security_group']['id'])
        self.check_remote_connectivity(
            servers[0]['ssh_client'],
            servers[1]['subport']['fixed_ips'][0]['ip_address'],
            should_succeed=True
        )

    @testtools.skipUnless(
          CONF.neutron_plugin_options.advanced_image_ref,
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

        trunk_network_server = self._create_server_with_port_and_subport(
            vlan_network, vlan_tag, use_advanced_image=True)
        normal_network_server = self._create_server_with_network(self.network)
        vlan_network_server = self._create_server_with_network(vlan_network)

        self._wait_for_server(trunk_network_server, advanced_image=True)
        # Configure VLAN interfaces on server
        command = CONFIGURE_VLAN_INTERFACE_COMMANDS % {'tag': vlan_tag}
        trunk_network_server['ssh_client'].exec_command(command)
        out = trunk_network_server['ssh_client'].exec_command(
            'PATH=$PATH:/usr/sbin;ip addr list')
        LOG.debug("Interfaces on server %s: %s", trunk_network_server, out)

        self._wait_for_server(normal_network_server)
        self._wait_for_server(vlan_network_server)

        # allow intra-securitygroup traffic
        rule = self.client.create_security_group_rule(
            security_group_id=self.secgroup['security_group']['id'],
            direction='ingress', ethertype='IPv4', protocol='icmp',
            remote_group_id=self.secgroup['security_group']['id'])
        self.addCleanup(self.client.delete_security_group_rule,
                        rule['security_group_rule']['id'])

        # Ping from trunk_network_server to normal_network_server
        # via parent port
        self.check_remote_connectivity(
            trunk_network_server['ssh_client'],
            normal_network_server['port']['fixed_ips'][0]['ip_address'],
            should_succeed=True
        )

        # Ping from trunk_network_server to vlan_network_server via VLAN
        # interface should success
        self.check_remote_connectivity(
            trunk_network_server['ssh_client'],
            vlan_network_server['port']['fixed_ips'][0]['ip_address'],
            should_succeed=True
        )

        # Delete the trunk
        self.delete_trunk(trunk_network_server['trunk'],
            detach_parent_port=False)
        LOG.debug("Trunk %s is deleted.", trunk_network_server['trunk']['id'])

        # Ping from trunk_network_server to normal_network_server
        # via parent port success after trunk deleted
        self.check_remote_connectivity(
            trunk_network_server['ssh_client'],
            normal_network_server['port']['fixed_ips'][0]['ip_address'],
            should_succeed=True
        )

        # Ping from trunk_network_server to vlan_network_server via VLAN
        # interface should fail after trunk deleted
        self.check_remote_connectivity(
            trunk_network_server['ssh_client'],
            vlan_network_server['port']['fixed_ips'][0]['ip_address'],
            should_succeed=False
        )
