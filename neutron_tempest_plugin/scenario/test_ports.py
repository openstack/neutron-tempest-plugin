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
import ipaddress

from oslo_log import log as logging
from tempest.common import waiters
from tempest.lib.common.utils import data_utils
from tempest.lib import decorators

from neutron_tempest_plugin import config
from neutron_tempest_plugin.scenario import base
from neutron_tempest_plugin.scenario import constants as const

LOG = logging.getLogger(__name__)
CONF = config.CONF


class PortsTest(base.BaseTempestTestCase):
    credentials = ['primary', 'admin']

    @classmethod
    def resource_setup(cls):
        super(PortsTest, cls).resource_setup()
        # setup basic topology for servers we can log into it
        cls.router = cls.create_router_by_client()
        cls.keypair = cls.create_keypair()
        cls.secgroup = cls.create_security_group(
            name=data_utils.rand_name("test_port_secgroup"))
        cls.create_loginable_secgroup_rule(
            secgroup_id=cls.secgroup['id'])
        cls.create_pingable_secgroup_rule(
            secgroup_id=cls.secgroup['id'])
        cls.network = cls.create_network()
        cls.subnet = cls.create_subnet(cls.network)
        cls.create_router_interface(cls.router['id'], cls.subnet['id'])
        cls.port = cls.create_port(cls.network,
                                   name=data_utils.rand_name("port"),
                                   security_groups=[cls.secgroup['id']])

    def _create_instance_with_port(self, port):
        """Create instance for port testing

        :param port (object): the port used
        """
        servers, fips = ([], [])
        server_args = {
            'flavor_ref': CONF.compute.flavor_ref,
            'image_ref': CONF.compute.image_ref,
            'key_name': self.keypair['name'],
            'networks': [{'port': port['id']}]
        }
        servers.append(self.create_server(**server_args))
        waiters.wait_for_server_status(
            self.os_primary.servers_client, servers[0]['server']['id'],
            const.SERVER_STATUS_ACTIVE)
        fips.append(self.create_floatingip(port=port))
        return fips, servers

    @decorators.idempotent_id('5500797e-b8c2-4e07-a5e0-89fa4e814965')
    def test_previously_used_port(self):
        for i in range(2):
            fips, servers = self._create_instance_with_port(
                self.port)
            self.check_connectivity(fips[0]['floating_ip_address'],
                                    CONF.validation.image_ssh_user,
                                    self.keypair['private_key'])
            self.os_primary.servers_client.delete_server(
                servers[0]['server']['id'])
            waiters.wait_for_server_termination(
                self.os_primary.servers_client,
                servers[0]['server']['id'])
            self._try_delete_resource(self.delete_floatingip, fips[0])

    @decorators.idempotent_id('62e32802-1d21-11eb-b322-74e5f9e2a801')
    def test_port_with_fixed_ip(self):
        """Test scenario:

        1) Get the last IP from the range of Subnet "Allocation pool"
        2) Create Port with fixed_ip resolved in #1
        3) Create a VM using updated Port in #2 and add Floating IP
        4) Check SSH access to VM
        """
        ip_range = [str(ip) for ip in ipaddress.IPv4Network(
            self.subnet['cidr'])]
        # Because of the tests executed in Parallel the IP may already
        # be in use, so we'll try using IPs from Allocation pool
        # (in reverse order) up until Port is successfully created.
        for ip in reversed(ip_range):
            try:
                port = self.create_port(
                    self.network,
                    name=data_utils.rand_name("fixed_ip_port"),
                    security_groups=[self.secgroup['id']],
                    fixed_ips=[{'ip_address': ip}])
                if port is not None:
                    break
            except Exception as e:
                LOG.warning('Failed to create Port, using Fixed_IP:%s, '
                            'the Error was:%s', ip, e)
        fip, server = self._create_instance_with_port(port)
        self.check_connectivity(fip[0]['floating_ip_address'],
                                CONF.validation.image_ssh_user,
                                self.keypair['private_key'])
