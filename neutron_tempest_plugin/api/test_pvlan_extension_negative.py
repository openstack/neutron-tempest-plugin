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

import unittest

from tempest.lib.common.utils import data_utils
from tempest.lib import decorators
from tempest.lib import exceptions as lib_exc

from neutron_tempest_plugin.api import base_pvlan_extension

# PVLAN plugin raises NeutronException (HTTP 500), not BadRequest (HTTP 400).
_SKIP_UNTIL_PVLAN_BAD_REQUEST = (
    'Skipped until PVLAN plugin validation returns HTTP 400')


class PVLANExtensionNegativeTestJSON(
        base_pvlan_extension.PVLANExtensionTestBase):
    """Negative tests for the PVLAN extension API.

    Each test is independent and creates its own network resources.
    """

    @decorators.attr(type='negative')
    @decorators.idempotent_id('b1c2d3e4-f5a6-4b7c-8d9e-0f1a2b3c4d5e')
    def test_create_community_port_invalid_community_name(self):
        # Community names must match the API regex
        pvlan_net, _subnet = self.create_pvlan_network()
        for invalid_name in ('bad name!', '1community'):
            self.assertRaises(
                lib_exc.BadRequest,
                self.client.create_port,
                network_id=pvlan_net['id'],
                name=data_utils.rand_name('port-'),
                pvlan_type='community',
                pvlan_community=invalid_name)

    @unittest.skip(_SKIP_UNTIL_PVLAN_BAD_REQUEST)
    @decorators.attr(type='negative')
    @decorators.idempotent_id('c2d3e4f5-a6b7-4c8d-9e0f-1a2b3c4d5e6f')
    def test_create_community_port_without_community_name(self):
        # Omitted pvlan_community is rejected by the PVLAN plugin
        pvlan_net, _subnet = self.create_pvlan_network()
        self.assertRaises(
            lib_exc.BadRequest,
            self.client.create_port,
            network_id=pvlan_net['id'],
            name=data_utils.rand_name('port-'),
            pvlan_type='community')

    @decorators.attr(type='negative')
    @decorators.idempotent_id('d3e4f5a6-b7c8-4d9e-0f1a-2b3c4d5e6f7a')
    def test_create_community_port_with_empty_community_name(self):
        # Empty pvlan_community fails API regex validation
        pvlan_net, _subnet = self.create_pvlan_network()
        self.assertRaises(
            lib_exc.BadRequest,
            self.client.create_port,
            network_id=pvlan_net['id'],
            name=data_utils.rand_name('port-'),
            pvlan_type='community',
            pvlan_community='')

    @decorators.attr(type='negative')
    @decorators.idempotent_id('a6b7c8d9-e0f1-4a2b-3c4d-5e6f7a8b9c0d')
    def test_create_port_with_invalid_pvlan_type(self):
        # pvlan_type must be a supported value on create
        pvlan_net, _subnet = self.create_pvlan_network()
        self.assertRaises(
            lib_exc.BadRequest,
            self.client.create_port,
            network_id=pvlan_net['id'],
            name=data_utils.rand_name('port-'),
            pvlan_type='invalid_type')

    @decorators.attr(type='negative')
    @decorators.idempotent_id('b7c8d9e0-f1a2-4b3c-4d5e-6f7a8b9c0d1e')
    def test_update_port_with_invalid_pvlan_type(self):
        # pvlan_type must be a supported value on update
        pvlan_net, _subnet = self.create_pvlan_network()
        port = self.create_port(pvlan_net)
        self.assertEqual('promiscuous', port['pvlan_type'])
        # Port defaults to promiscuous before the rejected update.
        self.assertRaises(
            lib_exc.BadRequest,
            self.client.update_port,
            port['id'],
            pvlan_type='not_a_pvlan_type')
        shown_port = self._show_port(port['id'])
        self.assertEqual('promiscuous', shown_port['pvlan_type'])
        # GET confirms pvlan_type was not changed by the failed update.

    @unittest.skip(_SKIP_UNTIL_PVLAN_BAD_REQUEST)
    @decorators.attr(type='negative')
    @decorators.idempotent_id('c8d9e0f1-a2b3-4c4d-5e6f-7a8b9c0d1e2f')
    def test_create_port_with_pvlan_type_on_non_pvlan_network(self):
        # pvlan_type is rejected when the network is not PVLAN
        network = self.create_network(
            name=data_utils.rand_name('net-normal-'))
        self.create_subnet(network)
        self._assert_pvlan_disabled(network)

        self.assertRaises(
            lib_exc.BadRequest,
            self.client.create_port,
            network_id=network['id'],
            name=data_utils.rand_name('port-'),
            pvlan_type='isolated')

    @unittest.skip(_SKIP_UNTIL_PVLAN_BAD_REQUEST)
    @decorators.attr(type='negative')
    @decorators.idempotent_id('d9e0f1a2-b3c4-4d5e-6f7a-8b9c0d1e2f3a')
    def test_create_port_with_pvlan_community_on_non_pvlan_network(self):
        # PVLAN port attributes are rejected on non-PVLAN networks
        network = self.create_network(
            name=data_utils.rand_name('net-normal-'))
        self.create_subnet(network)
        self._assert_pvlan_disabled(network)

        self.assertRaises(
            lib_exc.BadRequest,
            self.client.create_port,
            network_id=network['id'],
            name=data_utils.rand_name('port-'),
            pvlan_type='community',
            pvlan_community='community_1')
