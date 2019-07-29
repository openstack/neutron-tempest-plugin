# Copyright 2019 Red Hat, Inc.
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

from oslo_log import log
from tempest.lib.common.utils import data_utils
from tempest.lib import decorators

from neutron_tempest_plugin import config
from neutron_tempest_plugin.scenario import base

CONF = config.CONF

LOG = log.getLogger(__name__)


class PortForwardingTestJSON(base.BaseTempestTestCase):

    required_extensions = ['router', 'floating-ip-port-forwarding']

    @classmethod
    def resource_setup(cls):
        super(PortForwardingTestJSON, cls).resource_setup()
        cls.network = cls.create_network()
        cls.subnet = cls.create_subnet(cls.network)
        cls.router = cls.create_router_by_client()
        cls.create_router_interface(cls.router['id'], cls.subnet['id'])
        cls.fip = cls.create_floatingip()
        cls.secgroup = cls.create_security_group(
            name=data_utils.rand_name("test_port_secgroup"))
        cls.create_loginable_secgroup_rule(secgroup_id=cls.secgroup['id'])
        cls.keypair = cls.create_keypair()

    @decorators.idempotent_id('ab40fc48-ca8d-41a0-b2a3-f6679c847bfe')
    def test_port_forwarding_to_2_servers(self):
        internal_tcp_port = 22
        servers = []
        for i in range(1, 3):
            external_tcp_port = 1000 + i
            name = data_utils.rand_name("server-%s" % i)
            port = self.create_port(
                self.network,
                security_groups=[self.secgroup['id']])
            server = self.create_server(
                flavor_ref=CONF.compute.flavor_ref,
                image_ref=CONF.compute.image_ref,
                key_name=self.keypair['name'], name=name,
                networks=[{'port': port['id']}])['server']
            server['name'] = name
            self.wait_for_server_active(server)
            server['port_forwarding'] = self.create_port_forwarding(
                self.fip['id'],
                internal_port_id=port['id'],
                internal_ip_address=port['fixed_ips'][0]['ip_address'],
                internal_port=internal_tcp_port,
                external_port=external_tcp_port,
                protocol="tcp")
            servers.append(server)

        self.check_servers_hostnames(servers)
