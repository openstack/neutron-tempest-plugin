# Copyright (c) 2026 Red Hat Inc.
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
from tempest.lib import exceptions as lib_exc

from neutron_tempest_plugin.api import base_pvlan_extension


class PVLANExtensionTestJSON(base_pvlan_extension.PVLANExtensionTestBase):
    """Tests the PVLAN extension API.

    Each test is independent and creates its own network resources.
    Class-level resource_cleanup removes any resources left registered
    in the test class lists.
    """

    @decorators.idempotent_id('a8f3c2e1-4b5d-4a6f-9c0e-1d2e3f4a5b6c')
    def test_network_pvlan_disabled_by_default(self):
        # Networks must not have PVLAN enabled by default.
        network = self.create_network(
            name=data_utils.rand_name('net-pvlan-'))
        self.create_subnet(network)
        self._assert_pvlan_disabled(network)
        # Create response must not enable PVLAN.
        self._assert_pvlan_disabled(self._show_network(network['id']))
        # Show response must match create response.

    @decorators.idempotent_id('f2a3b4c5-d6e7-4f8a-9b0c-1d2e3f4a5b6c')
    def test_create_port_pvlan_types(self):
        # Promiscuous, isolated, and community roles can be set on create.
        pvlan_net, _subnet = self.create_pvlan_network()

        prom_port = self.create_port(pvlan_net)
        self.assertEqual('promiscuous', prom_port['pvlan_type'])
        # Default role on a PVLAN network is promiscuous.
        self.assertIsNone(prom_port.get('pvlan_community'))
        # Community is unset when type is not community.
        self.assertEqual(
            'promiscuous', self._show_port(prom_port['id'])['pvlan_type'])
        # Show response must match create response.

        prom_port_explicit = self.create_port(
            pvlan_net, pvlan_type='promiscuous')
        self.assertEqual('promiscuous',
                         prom_port_explicit['pvlan_type'])
        # Explicit promiscuous type is accepted.

        isolated_port = self.create_port(
            pvlan_net, pvlan_type='isolated')
        self.assertEqual('isolated', isolated_port['pvlan_type'])
        # Isolated role is stored on create.
        self.assertIsNone(isolated_port.get('pvlan_community'))
        # Community name is not used for isolated ports.

        community_port = self.create_port(
            pvlan_net,
            pvlan_type='community',
            pvlan_community='community_1')
        self.assertEqual('community', community_port['pvlan_type'])
        # Community role is stored on create.
        self.assertEqual('community_1',
                         community_port['pvlan_community'])
        # Community name is stored with the port.

    @decorators.idempotent_id('b4c5d6e7-f8a9-4b0c-1d2e-3f4a5b6c7d8e')
    def test_update_port_isolated_to_community(self):
        # Port role can be changed from isolated to community.
        pvlan_net, _subnet = self.create_pvlan_network()
        isolated_port = self.create_port(
            pvlan_net, pvlan_type='isolated')

        updated_port = self.update_port(
            isolated_port,
            pvlan_type='community',
            pvlan_community='community_2')
        self.assertEqual('community', updated_port['pvlan_type'])
        # PUT response returns the updated role.
        self.assertEqual('community_2', updated_port['pvlan_community'])
        # PUT response returns the new community name.

        shown_port = self._show_port(isolated_port['id'])
        self.assertEqual('community', shown_port['pvlan_type'])
        # GET confirms the role change was persisted.
        self.assertEqual('community_2', shown_port['pvlan_community'])
        # GET confirms the community name was persisted.

    @decorators.idempotent_id('d6e7f8a9-b0c1-4d2e-3f4a-5b6c7d8e9f0a')
    def test_delete_pvlan_port_and_network(self):
        # PVLAN ports and networks can be deleted cleanly.
        pvlan_net, pvlan_subnet = self.create_pvlan_network()
        port = self.create_port(pvlan_net)

        self.client.delete_port(port['id'])
        self.ports.remove(port)
        self.assertRaises(
            lib_exc.NotFound, self._show_port, port['id'])
        # Port must no longer exist after delete.

        self.client.delete_subnet(pvlan_subnet['id'])
        self.subnets.remove(pvlan_subnet)

        self.delete_network(pvlan_net)
        self.networks.remove(pvlan_net)
        self.assertRaises(
            lib_exc.NotFound,
            self._show_network, pvlan_net['id'])
        # Network must no longer exist after delete.
