# Copyright 2013 OpenStack Foundation
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

import netaddr
from tempest.common import utils
from tempest.lib.common.utils import data_utils
from tempest.lib import decorators

from neutron_tempest_plugin.api import base
from neutron_tempest_plugin import config

CONF = config.CONF


class FloatingIPTestJSON(base.BaseNetworkTest):

    required_extensions = ['router']

    @classmethod
    def resource_setup(cls):
        super(FloatingIPTestJSON, cls).resource_setup()
        cls.ext_net_id = CONF.network.public_network_id

        # Create network, subnet, router and add interface
        cls.network = cls.create_network()
        cls.subnet = cls.create_subnet(cls.network)
        cls.router = cls.create_router(data_utils.rand_name('router'),
                                       external_network_id=cls.ext_net_id)
        cls.create_router_interface(cls.router['id'], cls.subnet['id'])
        cls.port = list()
        # Create two ports one each for Creation and Updating of floatingIP
        for i in range(2):
            cls.create_port(cls.network)

    @decorators.idempotent_id('f6a0fb6c-cb64-4b81-b0d5-f41d8f69d22d')
    def test_blank_update_clears_association(self):
        # originally the floating IP had no attributes other than its
        # association, so an update with an empty body was a signal to
        # clear the association. This test ensures we maintain that behavior.
        body = self.create_floatingip(port=self.ports[0])
        self.assertEqual(self.ports[0]['id'], body['port_id'])
        body = self.client.update_floatingip(body['id'])['floatingip']
        self.assertFalse(body['port_id'])

    @decorators.idempotent_id('c72c1c0c-2193-4aca-eeee-b1442641ffff')
    @utils.requires_ext(extension="standard-attr-description",
                       service="network")
    def test_create_update_floatingip_description(self):
        body = self.create_floatingip(port=self.ports[0], description='d1')
        self.assertEqual('d1', body['description'])
        body = self.client.show_floatingip(body['id'])['floatingip']
        self.assertEqual('d1', body['description'])
        body = self.client.update_floatingip(body['id'], description='d2')
        self.assertEqual('d2', body['floatingip']['description'])
        body = self.client.show_floatingip(body['floatingip']['id'])
        self.assertEqual('d2', body['floatingip']['description'])
        # disassociate
        body = self.client.update_floatingip(body['floatingip']['id'],
                                             port_id=None)
        self.assertEqual('d2', body['floatingip']['description'])

    @decorators.idempotent_id('fd7161e1-2167-4686-a6ff-0f3df08001bb')
    @utils.requires_ext(extension="standard-attr-description",
                       service="network")
    def test_floatingip_update_extra_attributes_port_id_not_changed(self):
        port_id = self.ports[1]['id']
        body = self.create_floatingip(port_id=port_id, description='d1')
        self.assertEqual('d1', body['description'])
        body = self.client.show_floatingip(body['id'])['floatingip']
        self.assertEqual(port_id, body['port_id'])
        # Update description
        body = self.client.update_floatingip(body['id'], description='d2')
        self.assertEqual('d2', body['floatingip']['description'])
        # Floating IP association is not changed.
        self.assertEqual(port_id, body['floatingip']['port_id'])
        body = self.client.show_floatingip(body['floatingip']['id'])
        self.assertEqual('d2', body['floatingip']['description'])
        self.assertEqual(port_id, body['floatingip']['port_id'])
        # disassociate
        body = self.client.update_floatingip(body['floatingip']['id'],
                                             port_id=None)
        self.assertIsNone(body['floatingip']['port_id'])

    @decorators.idempotent_id('cecae820-ebaa-4f96-b386-6a9fbf25c552')
    @utils.requires_ext(extension="standard-attr-description",
                        service="network")
    @utils.requires_ext(extension="fip-port-details", service="network")
    def test_create_update_floatingip_port_details(self):

        body = self.create_floatingip(port=self.ports[0], description='d1')
        self._assert_port_details(self.ports[0], body)
        body = self.client.show_floatingip(body['id'])['floatingip']
        self._assert_port_details(self.ports[0], body)
        body = self.client.update_floatingip(body['id'], description='d2')
        self._assert_port_details(self.ports[0], body['floatingip'])
        # disassociate
        body = self.client.update_floatingip(body['floatingip']['id'],
                                             port_id=None)
        self.assertIn('port_details', body['floatingip'])
        self.assertIsNone(body['floatingip']['port_details'])

    def _assert_port_details(self, port, body):
        self.assertIn('port_details', body)
        port_details = body['port_details']
        self.assertEqual(port['name'], port_details['name'])
        self.assertEqual(port['network_id'], port_details['network_id'])
        self.assertEqual(port['mac_address'], port_details['mac_address'])
        self.assertEqual(port['admin_state_up'],
                         port_details['admin_state_up'])
        self.assertEqual(port['status'], port_details['status'])
        self.assertEqual(port['device_id'], port_details['device_id'])
        self.assertEqual(port['device_owner'], port_details['device_owner'])


class FloatingIPPoolTestJSON(base.BaseAdminNetworkTest):

    required_extensions = ['router']

    @decorators.idempotent_id('6c438332-4554-461c-9668-512ae09bf952')
    @utils.requires_ext(extension="floatingip-pools", service="network")
    def test_create_floatingip_from_specific_pool(self):
        network = self.create_network(client=self.admin_client, external=True)
        subnet1 = self.create_subnet(network, client=self.admin_client)
        subnet2 = self.create_subnet(network, client=self.admin_client)
        pools = self.client.list_floatingip_pools()["floatingip_pools"]

        def test_create_floatingip_from_subnet(pools, subnet):
            pool = None
            for p in pools:
                if p['network_id'] == subnet['network_id'] \
                        and p['subnet_id'] == subnet['id']:
                    pool = p
                    break

            self.assertTrue(pool)
            new_floatingip = self.create_floatingip(
                pool['network_id'], subnet_id=pool['subnet_id'])
            cidr = netaddr.IPNetwork(pool['cidr'])
            ip_address = netaddr.IPAddress(
                new_floatingip['floating_ip_address'])
            self.assertIn(ip_address, cidr)
            fip_id = new_floatingip['id']
            floatingip = self.client.get_floatingip(fip_id)['floatingip']
            self.assertEqual(new_floatingip['floating_ip_address'],
                             floatingip['floating_ip_address'])

        test_create_floatingip_from_subnet(pools, subnet1)
        test_create_floatingip_from_subnet(pools, subnet2)
