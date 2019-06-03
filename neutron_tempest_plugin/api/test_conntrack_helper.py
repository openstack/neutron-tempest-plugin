# Copyright (c) 2019 Red Hat, Inc.
# All rights reserved.
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

# from tempest.common import utils
from tempest.lib.common.utils import data_utils
from tempest.lib import decorators
from tempest.lib import exceptions

from neutron_tempest_plugin.api import base
from neutron_tempest_plugin import config

CONF = config.CONF


class ConntrackHelperTestJSON(base.BaseNetworkTest):

    required_extensions = ['router', 'l3-conntrack-helper',
                           'expose-l3-conntrack-helper']

    @classmethod
    def resource_setup(cls):
        super(ConntrackHelperTestJSON, cls).resource_setup()
        cls.ext_net_id = CONF.network.public_network_id

        # Create network, subnet
        cls.network = cls.create_network()
        cls.subnet = cls.create_subnet(cls.network)

    @decorators.idempotent_id('6361c80e-902d-4c2a-88b4-ea8066507eee')
    def test_create_list_update_show_delete_conntrack_helper(self):
        # Create a router
        router = self.create_router(data_utils.rand_name('router'),
                                    external_network_id=self.ext_net_id)

        # Create conntrack helper
        created_cth = self.create_conntrack_helper(router['id'], helper='tftp',
                                                   protocol='udp', port=69)
        self.assertEqual('tftp', created_cth['helper'])
        self.assertEqual('udp', created_cth['protocol'])
        self.assertEqual(69, created_cth['port'])

        # List conntrack helpers
        conntrack_helpers = self.client.list_conntrack_helpers(
            router['id'])['conntrack_helpers']
        self.assertIn(created_cth['id'],
                      {cth['id'] for cth in conntrack_helpers})

        # Update conntrack helper
        updated_conntrack_helper = self.client.update_conntrack_helper(
            router['id'], created_cth['id'], port=6969)['conntrack_helper']
        self.assertEqual(updated_conntrack_helper['port'], 6969)

        # Show conntrack helper
        conntrack_helper = self.client.get_conntrack_helper(
            router['id'], created_cth['id'])['conntrack_helper']
        self.assertEqual('tftp', conntrack_helper['helper'])
        self.assertEqual('udp', conntrack_helper['protocol'])
        self.assertEqual(6969, conntrack_helper['port'])

        # Delete conntrack helper
        self.client.delete_conntrack_helper(router['id'], created_cth['id'])
        self.assertRaises(
            exceptions.NotFound,
            self.client.get_conntrack_helper, router['id'], created_cth['id'])

    @decorators.idempotent_id('0a6ae20c-3f66-423e-93c6-cfedd1c93b8d')
    def test_conntrack_helper_info_in_router_details(self):
        # Create a router
        router = self.create_router(data_utils.rand_name('router'),
                                    external_network_id=self.ext_net_id)

        # Ensure routerd does not have information about any conntrack helper
        router = self.client.show_router(router['id'])['router']
        self.assertEqual(0, len(router['conntrack_helpers']))

        # Now create conntrack helper and ensure it's visible in Router details
        cth = self.create_conntrack_helper(router['id'], helper='ftp',
                                           protocol='tcp', port=21)
        router = self.client.show_router(router['id'])['router']
        self.assertEqual(1, len(router['conntrack_helpers']))
        self.assertEqual('ftp', router['conntrack_helpers'][0]['helper'])
        self.assertEqual('tcp', router['conntrack_helpers'][0]['protocol'])
        self.assertEqual(21, router['conntrack_helpers'][0]['port'])

        # Delete conntrack_helper and ensure it's no longer in Router details
        self.client.delete_conntrack_helper(router['id'], cth['id'])
        router = self.client.show_router(router['id'])['router']
        self.assertEqual(0, len(router['conntrack_helpers']))

    @decorators.idempotent_id('134469d9-fb25-4165-adc8-f4747f07caf1')
    def test_2_conntrack_helpers_to_same_router(self):
        # Create a router
        router = self.create_router(data_utils.rand_name('router'),
                                    external_network_id=self.ext_net_id)

        cth_data = [{'helper': 'tftp', 'protocol': 'udp', 'port': 60},
                    {'helper': 'ftp', 'protocol': 'tcp', 'port': 21}]
        created_cths = []
        for cth in cth_data:
            created_cth = self.create_conntrack_helper(
                router_id=router['id'],
                helper=cth['helper'],
                protocol=cth['protocol'],
                port=cth['port'])
            self.assertEqual(cth['helper'], created_cth['helper'])
            self.assertEqual(cth['protocol'], created_cth['protocol'])
            self.assertEqual(cth['port'], created_cth['port'])
            created_cths.append(created_cth)

        # Check that conntrack helpers are in Router details
        router = self.client.show_router(router['id'])['router']
        self.assertEqual(len(cth_data), len(router['conntrack_helpers']))
        for cth in created_cths:
            expected_cth = cth.copy()
            expected_cth.pop('id')
            expected_cth.pop('client')
            expected_cth.pop('router_id')
            self.assertIn(expected_cth, router['conntrack_helpers'])

        # Test list of conntrack helpers
        conntrack_helpers = self.client.list_conntrack_helpers(
            router['id'])['conntrack_helpers']
        self.assertEqual(len(cth_data), len(conntrack_helpers))
