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

from tempest.lib import decorators
from tempest.lib import exceptions

from neutron_tempest_plugin.api import base
from neutron_tempest_plugin import config

CONF = config.CONF


class LocalIPTestJSON(base.BaseNetworkTest):

    credentials = ['primary', 'admin']
    required_extensions = ['local_ip']

    @classmethod
    def resource_setup(cls):
        super(LocalIPTestJSON, cls).resource_setup()
        cls.ext_net_id = CONF.network.public_network_id

        # Create network and subnet
        cls.network = cls.create_network()
        cls.subnet = cls.create_subnet(cls.network)

    @decorators.idempotent_id('369257b0-521d-43f5-9482-50e18e87a472')
    def test_local_ip_lifecycle(self):
        port = self.create_port(self.network)
        lip_description = 'Test Local IP description'
        lip_name = 'test-local-ip'
        created_local_ip = self.create_local_ip(
            name=lip_name,
            description=lip_description,
            local_port_id=port['id'],
            local_ip_address=port['fixed_ips'][0]['ip_address'])
        self.assertEqual(self.network['id'], created_local_ip['network_id'])
        self.assertEqual(lip_description, created_local_ip['description'])
        self.assertEqual(lip_name, created_local_ip['name'])
        self.assertEqual(port['id'], created_local_ip['local_port_id'])
        self.assertEqual(port['fixed_ips'][0]['ip_address'],
                         created_local_ip['local_ip_address'])

        # Show created local_ip
        body = self.client.get_local_ip(created_local_ip['id'])
        local_ip = body['local_ip']

        self.assertEqual(lip_description, local_ip['description'])
        self.assertEqual(lip_name, local_ip['name'])

        # List local_ips
        body = self.client.list_local_ips()

        local_ip_ids = [lip['id'] for lip in body['local_ips']]
        self.assertIn(created_local_ip['id'], local_ip_ids)

        # Update local_ip
        updated_local_ip = self.client.update_local_ip(
                               created_local_ip['id'],
                               name='updated_local_ip')
        self.assertEqual('updated_local_ip',
                         updated_local_ip['local_ip']['name'])

        self.delete_local_ip(created_local_ip)
        self.assertRaises(exceptions.NotFound,
                          self.client.get_local_ip, created_local_ip['id'])

    @decorators.idempotent_id('e32df8ac-4e29-4adf-8057-46ae8684eff2')
    def test_create_local_ip_with_network(self):
        local_ip = self.create_local_ip(self.network['id'])
        self.assertEqual(self.network['id'], local_ip['network_id'])


class LocalIPAssociationTestJSON(base.BaseNetworkTest):

    required_extensions = ['local_ip']

    @classmethod
    def resource_setup(cls):
        super(LocalIPAssociationTestJSON, cls).resource_setup()
        cls.ext_net_id = CONF.network.public_network_id
        # Create network
        cls.network = cls.create_network()
        cls.subnet = cls.create_subnet(cls.network)

    @decorators.idempotent_id('602d2874-49be-4c72-8799-b20c95853b6b')
    def test_local_ip_association_lifecycle(self):
        local_ip = self.create_local_ip(self.network['id'])
        port = self.create_port(self.network)
        local_ip_association = self.create_local_ip_association(
            local_ip['id'],
            fixed_port_id=port['id'])
        self.assertEqual(local_ip['id'], local_ip_association['local_ip_id'])
        self.assertEqual(port['id'], local_ip_association['fixed_port_id'])

        # Test List Local IP Associations
        body = self.client.list_local_ip_associations(local_ip['id'])
        associations = body['port_associations']
        self.assertEqual(local_ip['id'], associations[0]['local_ip_id'])
        self.assertEqual(port['id'], associations[0]['fixed_port_id'])

        # Show
        body = self.client.get_local_ip_association(
            local_ip['id'], port['id'])
        association = body['port_association']
        self.assertEqual(local_ip['id'], association['local_ip_id'])
        self.assertEqual(port['id'], association['fixed_port_id'])

        # Delete
        self.client.delete_local_ip_association(local_ip['id'], port['id'])
        self.assertRaises(exceptions.NotFound,
                          self.client.get_local_ip_association,
                          local_ip['id'], port['id'])

    @decorators.idempotent_id('5d26edab-78d2-4cbd-9d0b-3c0b19f0f52d')
    def test_local_ip_association_with_two_ips_on_port(self):
        local_ip = self.create_local_ip(self.network['id'])
        s = self.subnet
        port = self.create_port(self.network)
        # request another IP on the same subnet
        port['fixed_ips'].append({'subnet_id': s['id']})
        updated = self.client.update_port(port['id'],
                                          fixed_ips=port['fixed_ips'])
        port = updated['port']
        local_ip_association = self.create_local_ip_association(
            local_ip['id'],
            fixed_port_id=port['id'],
            fixed_ip_address=port['fixed_ips'][0]['ip_address'])
        self.assertEqual(port['fixed_ips'][0]['ip_address'],
                         local_ip_association['fixed_ip'])
