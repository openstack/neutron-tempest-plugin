# Copyright (c) 2020 Red Hat, Inc.
#
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
from tempest.lib.common.utils import data_utils
from tempest.lib import decorators

from neutron_tempest_plugin.common import ip
from neutron_tempest_plugin.common import ssh
from neutron_tempest_plugin import config
from neutron_tempest_plugin.scenario import base


LOG = logging.getLogger(__name__)
CONF = config.CONF
MIN_VLAN_ID = 1
MAX_VLAN_ID = 4094


class VlanTransparencyTest(base.BaseTempestTestCase):
    credentials = ['primary', 'admin']
    force_tenant_isolation = False

    required_extensions = ['vlan-transparent', 'allowed-address-pairs']

    @classmethod
    def resource_setup(cls):
        super(VlanTransparencyTest, cls).resource_setup()
        # setup basic topology for servers we can log into
        cls.rand_name = data_utils.rand_name(
            cls.__name__.rsplit('.', 1)[-1])
        cls.network = cls.create_network(name=cls.rand_name,
                                         vlan_transparent=True)
        cls.subnet = cls.create_subnet(network=cls.network,
                                       name=cls.rand_name)
        cls.router = cls.create_router_by_client()
        cls.create_router_interface(cls.router['id'], cls.subnet['id'])
        cls.keypair = cls.create_keypair(name=cls.rand_name)
        cls.vm_ports = []
        cls.security_group = cls.create_security_group(name=cls.rand_name)
        cls.create_loginable_secgroup_rule(cls.security_group['id'])

        if CONF.neutron_plugin_options.default_image_is_advanced:
            cls.flavor_ref = CONF.compute.flavor_ref
            cls.image_ref = CONF.compute.image_ref
        else:
            cls.flavor_ref = \
                CONF.neutron_plugin_options.advanced_image_flavor_ref
            cls.image_ref = CONF.neutron_plugin_options.advanced_image_ref

    @classmethod
    def skip_checks(cls):
        super(VlanTransparencyTest, cls).skip_checks()
        if not (CONF.neutron_plugin_options.advanced_image_ref or
                CONF.neutron_plugin_options.default_image_is_advanced):
            raise cls.skipException(
                'Advanced image is required to run these tests.')

    def _create_port_and_server(self, index,
                                port_security=True,
                                allowed_address_pairs=None):
        server_name = 'server-%s-%d' % (self.rand_name, index)
        port_name = 'port-%s-%d' % (self.rand_name, index)
        if port_security:
            sec_groups = [self.security_group['id']]
        else:
            sec_groups = None
        self.vm_ports.append(
            self.create_port(network=self.network, name=port_name,
                             security_groups=sec_groups,
                             port_security_enabled=port_security,
                             allowed_address_pairs=allowed_address_pairs))
        return self.create_server(flavor_ref=self.flavor_ref,
                                  image_ref=self.image_ref,
                                  key_name=self.keypair['name'],
                                  networks=[{'port': self.vm_ports[-1]['id']}],
                                  name=server_name)['server']

    def _configure_vlan_transparent(self, port, ssh_client,
                                    vlan_tag, vlan_ip):
        ip_command = ip.IPCommand(ssh_client=ssh_client)
        addresses = ip_command.list_addresses(port=port)
        port_iface = ip.get_port_device_name(addresses, port)
        subport_iface = ip_command.configure_vlan_transparent(
            port=port, vlan_tag=vlan_tag, ip_addresses=[vlan_ip])

        for address in ip_command.list_addresses(ip_addresses=vlan_ip):
            self.assertEqual(subport_iface, address.device.name)
            self.assertEqual(port_iface, address.device.parent)
            break
        else:
            self.fail("Sub-port fixed IP not found on server.")

    def _create_ssh_client(self, floating_ip):
        if CONF.neutron_plugin_options.default_image_is_advanced:
            username = CONF.validation.image_ssh_user
        else:
            username = CONF.neutron_plugin_options.advanced_image_ssh_user
        return ssh.Client(host=floating_ip['floating_ip_address'],
                          username=username,
                          pkey=self.keypair['private_key'])

    def _test_basic_vlan_transparency_connectivity(
            self, port_security=True, use_allowed_address_pairs=False):
        vlan_tag = data_utils.rand_int_id(start=MIN_VLAN_ID, end=MAX_VLAN_ID)
        vlan_ipmask_template = '192.168.%d.{ip_last_byte}/24' % (vlan_tag %
                                                                 256)
        vms = []
        vlan_ipmasks = []
        floating_ips = []
        ssh_clients = []

        for i in range(2):
            vlan_ipmasks.append(vlan_ipmask_template.format(
                ip_last_byte=(i + 1) * 10))
            if use_allowed_address_pairs:
                allowed_address_pairs = [{'ip_address': vlan_ipmasks[i]}]
            else:
                allowed_address_pairs = None
            vms.append(self._create_port_and_server(
                index=i,
                port_security=port_security,
                allowed_address_pairs=allowed_address_pairs))
            floating_ips.append(self.create_floatingip(port=self.vm_ports[-1]))
            ssh_clients.append(
                self._create_ssh_client(floating_ip=floating_ips[i]))

            self.check_connectivity(
                host=floating_ips[i]['floating_ip_address'],
                ssh_client=ssh_clients[i])
            self._configure_vlan_transparent(port=self.vm_ports[-1],
                                             ssh_client=ssh_clients[i],
                                             vlan_tag=vlan_tag,
                                             vlan_ip=vlan_ipmasks[i])

        if port_security:
            # Ping from vm0 to vm1 via VLAN interface should fail because
            # we haven't allowed ICMP
            self.check_remote_connectivity(
                ssh_clients[0],
                vlan_ipmasks[1].split('/')[0],
                servers=vms,
                should_succeed=False)

            # allow intra-security-group traffic
            sg_rule = self.create_pingable_secgroup_rule(
                self.security_group['id'])
            self.addCleanup(
                    self.os_primary.network_client.delete_security_group_rule,
                    sg_rule['id'])

        # Ping from vm0 to vm1 via VLAN interface should pass because
        # either port security is disabled or the ICMP sec group rule has been
        # added
        self.check_remote_connectivity(
            ssh_clients[0],
            vlan_ipmasks[1].split('/')[0],
            servers=vms)
        # Ping from vm1 to vm0 and check untagged packets are not dropped
        self.check_remote_connectivity(
            ssh_clients[1],
            self.vm_ports[-2]['fixed_ips'][0]['ip_address'],
            servers=vms)

    @decorators.idempotent_id('a2694e3a-6d4d-4a23-9fcc-c3ed3ef37b16')
    def test_vlan_transparent_port_sec_disabled(self):
        self._test_basic_vlan_transparency_connectivity(
            port_security=False, use_allowed_address_pairs=False)

    @decorators.idempotent_id('2dd03b4f-9c20-4cda-8c6a-40fa453ec69a')
    def test_vlan_transparent_allowed_address_pairs(self):
        self._test_basic_vlan_transparency_connectivity(
            port_security=True, use_allowed_address_pairs=True)
