# Copyright 2026 Red Hat, LLC
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

from neutron_lib.utils import test
from tempest.lib.common.utils import data_utils
from tempest.lib import decorators

from neutron_tempest_plugin import config
from neutron_tempest_plugin.scenario import base

CONF = config.CONF


class NetworkOVNBGPTest(base.BaseAdminTempestTestCase):
    credentials = ['primary', 'admin']
    required_extensions = ['ovn-bgp']

    @classmethod
    def resource_setup(cls):
        super().resource_setup()
        cls.keypair = cls.create_keypair()
        cls.secgroup = cls.create_security_group(
            name=data_utils.rand_name('ovn-bgp-secgroup'))
        cls.create_loginable_secgroup_rule(
            secgroup_id=cls.secgroup['id'])
        cls.create_pingable_secgroup_rule(
            secgroup_id=cls.secgroup['id'])

    @test.unstable_test("bug 2167462 / FDP-4384")
    @decorators.idempotent_id('b0bbcb98-f176-4f4d-9a9e-87dcacdfe8d3')
    def test_leak_routes_connectivity(self):
        network = self.create_network()
        subnet = self.create_subnet(network)
        router = self.create_router_by_client(
            external_network_id=CONF.network.public_network_id)
        self.client.add_router_interface_with_subnet_id(
            router['id'], subnet['id'])

        server = self.create_server(
            flavor_ref=CONF.compute.flavor_ref,
            image_ref=CONF.compute.image_ref,
            key_name=self.keypair['name'],
            networks=[{'uuid': network['id']}],
            security_groups=[{'name': self.secgroup['name']}])
        port = self.client.list_ports(
            network_id=network['id'],
            device_id=server['server']['id'])['ports'][0]
        private_ip = port['fixed_ips'][0]['ip_address']

        self.ping_ip_address(private_ip, should_succeed=False)

        self.admin_client.update_subnet(subnet['id'], leak_routes=True)

        self.ping_ip_address(private_ip, should_succeed=True)
        self.check_connectivity(private_ip,
                                CONF.validation.image_ssh_user,
                                self.keypair['private_key'])

        self.admin_client.update_subnet(subnet['id'], leak_routes=False)

        self.ping_ip_address(private_ip, should_succeed=False)
