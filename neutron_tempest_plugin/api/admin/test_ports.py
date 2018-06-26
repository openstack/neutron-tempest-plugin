# Copyright 2018 Red Hat, Inc.
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
from tempest.lib import decorators

from neutron_tempest_plugin.api import base


class PortTestCasesAdmin(base.BaseAdminNetworkTest):

    @classmethod
    def resource_setup(cls):
        super(PortTestCasesAdmin, cls).resource_setup()
        cls.network = cls.create_network()
        cls.create_subnet(cls.network)

    @decorators.idempotent_id('dfe8cc79-18d9-4ae8-acef-3ec6bb719bb1')
    def test_update_mac_address(self):
        body = self.create_port(self.network)
        current_mac = body['mac_address']

        # Verify mac_address can be successfully updated.
        body = self.admin_client.update_port(body['id'],
                                             mac_address='12:34:56:78:be:6d')
        new_mac = body['port']['mac_address']
        self.assertNotEqual(current_mac, new_mac)
        self.assertEqual('12:34:56:78:be:6d', new_mac)

        # Verify that port update without specifying mac_address does not
        # change the mac address.
        body = self.admin_client.update_port(body['port']['id'],
                                             description='Port Description')
        self.assertEqual(new_mac, body['port']['mac_address'])

    @decorators.idempotent_id('dfe8cc79-18d9-4ae8-acef-3ec6bb719cc2')
    @utils.requires_ext(extension="port-mac-address-regenerate",
                        service="network")
    def test_regenerate_mac_address(self):
        body = self.create_port(self.network)
        current_mac = body['mac_address']
        body = self.admin_client.update_port(body['id'],
                                             mac_address=None)
        new_mac = body['port']['mac_address']
        self.assertNotEqual(current_mac, new_mac)
        self.assertTrue(netaddr.valid_mac(new_mac))
