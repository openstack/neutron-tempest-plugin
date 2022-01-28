#   Copyright 2021 Huawei, Inc. All rights reserved.
#
#   Licensed under the Apache License, Version 2.0 (the "License"); you may
#   not use this file except in compliance with the License. You may obtain
#   a copy of the License at
#
#        http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#   WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#   License for the specific language governing permissions and limitations
#   under the License.
#

from oslo_log import log as logging
from tempest.common import utils
from tempest.common import waiters
from tempest.lib.common.utils import data_utils
from tempest.lib import decorators

from neutron_tempest_plugin.common import ssh
from neutron_tempest_plugin import config
from neutron_tempest_plugin.scenario import base
from neutron_tempest_plugin.scenario import constants as const

LOG = logging.getLogger(__name__)
CONF = config.CONF


class LocalIPTest(base.BaseTempestTestCase):
    credentials = ['primary', 'admin']

    @classmethod
    @utils.requires_ext(extension="local_ip", service="network")
    def resource_setup(cls):
        super(LocalIPTest, cls).resource_setup()
        cls.network = cls.create_network()
        cls.subnet = cls.create_subnet(cls.network)
        cls.keypair = cls.create_keypair()

        # Create security group with admin privileges
        cls.secgroup = cls.create_security_group(
            name=data_utils.rand_name('secgroup'))

        # Execute funcs to achieve ssh and ICMP capabilities
        cls.create_loginable_secgroup_rule(secgroup_id=cls.secgroup['id'])
        cls.create_pingable_secgroup_rule(secgroup_id=cls.secgroup['id'])

        # Create router
        cls.router = cls.create_router(
            router_name=data_utils.rand_name("router-test"),
            admin_state_up=True,
            external_network_id=CONF.network.public_network_id)
        cls.create_router_interface(cls.router['id'], cls.subnet['id'])

    def _create_server(self, name=None):
        port = self.create_port(
            self.network, security_groups=[self.secgroup['id']])
        server = self.create_server(
            flavor_ref=CONF.compute.flavor_ref,
            image_ref=CONF.compute.image_ref,
            key_name=self.keypair['name'], name=name,
            networks=[{'port': port['id']}])['server']
        waiters.wait_for_server_status(self.os_primary.servers_client,
                                       server['id'],
                                       const.SERVER_STATUS_ACTIVE)

        return {'port': port, 'server': server}

    @decorators.idempotent_id('3aa4b288-011a-4aa2-9024-19ad2ce40bfd')
    def test_local_ip_connectivity(self):
        server1 = self._create_server(name='local_ip_vm1')
        server2 = self._create_server(name='local_ip_vm2')

        fip = self.create_and_associate_floatingip(server1['port']['id'])
        ssh_client = ssh.Client(
            fip['floating_ip_address'],
            CONF.validation.image_ssh_user,
            pkey=self.keypair['private_key'])

        servers = [server1['server'], server2['server']]

        # first check basic connectivity
        self.check_remote_connectivity(
            ssh_client,
            server2['port']['fixed_ips'][0]['ip_address'],
            servers=servers)

        local_ip = self.create_local_ip(network_id=self.network['id'])
        self.create_local_ip_association(local_ip['id'],
                                         fixed_port_id=server2['port']['id'])
        # check connectivity with local ip address
        self.check_remote_connectivity(
            ssh_client, local_ip['local_ip_address'],
            servers=servers, check_response_ip=False)

        # check basic connectivity after local ip association
        self.check_remote_connectivity(
            ssh_client,
            server2['port']['fixed_ips'][0]['ip_address'],
            servers=servers,
            check_response_ip=False)
