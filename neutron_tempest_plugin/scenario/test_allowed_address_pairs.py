# Copyright 2026 Red Hat, Inc.
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

from tempest.lib.common.utils import data_utils
from tempest.lib import decorators

from neutron_tempest_plugin.common import ssh
from neutron_tempest_plugin import config
from neutron_tempest_plugin.scenario import base

CONF = config.CONF


class AllowedAddressPairTest(base.BaseTempestTestCase):
    credentials = ['primary', 'admin']
    required_extensions = ['router', 'allowed-address-pairs']

    @classmethod
    def resource_setup(cls):
        super().resource_setup()
        cls.network = cls.create_network()
        cls.subnet = cls.create_subnet(cls.network)
        cls.keypair = cls.create_keypair()
        cls.secgroup = cls.create_security_group(
            name=data_utils.rand_name('secgroup'))
        cls.create_loginable_secgroup_rule(secgroup_id=cls.secgroup['id'])
        cls.create_pingable_secgroup_rule(secgroup_id=cls.secgroup['id'])
        cls.router = cls.create_router_by_client()
        cls.create_router_interface(cls.router['id'], cls.subnet['id'])

    @decorators.idempotent_id('f0e25a6c-8091-4b36-a870-3a5c1c2b7e4d')
    def test_subnet_cidr_as_allowed_address_pair(self):
        port_1 = self.create_port(
            self.network,
            security_groups=[self.secgroup['id']],
            allowed_address_pairs=[
                {'ip_address': self.subnet['cidr']}])
        port_2 = self.create_port(
            self.network,
            security_groups=[self.secgroup['id']])

        server_1 = self.create_server(
            flavor_ref=CONF.compute.flavor_ref,
            image_ref=CONF.compute.image_ref,
            key_name=self.keypair['name'],
            networks=[{'port': port_1['id']}])
        server_2 = self.create_server(
            flavor_ref=CONF.compute.flavor_ref,
            image_ref=CONF.compute.image_ref,
            key_name=self.keypair['name'],
            networks=[{'port': port_2['id']}])

        fip = self.create_floatingip(port=port_1)
        ssh_client = ssh.Client(
            fip['floating_ip_address'],
            CONF.validation.image_ssh_user,
            pkey=self.keypair['private_key'])
        self.check_remote_connectivity(
            ssh_client,
            port_2['fixed_ips'][0]['ip_address'],
            servers=[server_1, server_2])
