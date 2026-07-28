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

from tempest.lib.common.utils import data_utils
from tempest.lib import decorators
from tempest.lib import exceptions as lib_exc

from neutron_tempest_plugin.api import test_ovn_bgp
from neutron_tempest_plugin import config

CONF = config.CONF


class SubnetOVNBGPNegativeTest(test_ovn_bgp.SubnetOVNBGPTestBase):

    @decorators.attr(type='negative')
    @decorators.idempotent_id('7437d2ca-7863-42ff-a25d-c91dddc692a7')
    def test_enable_leak_routes_no_router(self):
        network = self.create_network()
        subnet = self.create_subnet(network)
        self.assertRaises(
            lib_exc.BadRequest,
            self.admin_client.update_subnet,
            subnet['id'], leak_routes=True)

    @decorators.attr(type='negative')
    @decorators.idempotent_id('eeb94f6b-2e56-46e7-af80-04e2b2e417e3')
    def test_enable_leak_routes_router_no_external_gw(self):
        network = self.create_network()
        subnet = self.create_subnet(network)
        router = self.create_admin_router(data_utils.rand_name('router-bgp'))
        self.create_router_interface(
            router['id'], subnet['id'], client=self.admin_client)
        self.assertRaises(
            lib_exc.BadRequest,
            self.admin_client.update_subnet,
            subnet['id'], leak_routes=True)

    @decorators.attr(type='negative')
    @decorators.idempotent_id('06dffa36-d9c6-4dbf-b5d9-732598b64bd7')
    def test_enable_leak_routes_overlapping_cidr(self):
        _net1, subnet1, _router1 = self._create_leakable_topology(
            cidr='10.200.0.0/16')
        _net2, subnet2, _router2 = self._create_leakable_topology(
            cidr='10.200.1.0/24')
        self.admin_client.update_subnet(subnet1['id'], leak_routes=True)
        self.assertRaises(
            lib_exc.BadRequest,
            self.admin_client.update_subnet,
            subnet2['id'], leak_routes=True)

    @decorators.attr(type='negative')
    @decorators.idempotent_id('c735cdef-db66-4fef-abb3-3a879b5537d8')
    def test_enable_leak_routes_exact_same_cidr(self):
        _net1, subnet1, _router1 = self._create_leakable_topology(
            cidr='10.201.0.0/24')
        # Create second topology with same CIDR bypassing the base class
        # CIDR reservation that prevents duplicate CIDRs.
        network2 = self.create_network()
        subnet2 = self.admin_client.create_subnet(
            network_id=network2['id'],
            cidr='10.201.0.0/24',
            ip_version=4)['subnet']
        self.admin_subnets.append(subnet2)
        router2 = self.create_admin_router(
            data_utils.rand_name('router-bgp'),
            external_network_id=CONF.network.public_network_id)
        self.create_router_interface(
            router2['id'], subnet2['id'], client=self.admin_client)
        self.admin_client.update_subnet(subnet1['id'], leak_routes=True)
        self.assertRaises(
            lib_exc.BadRequest,
            self.admin_client.update_subnet,
            subnet2['id'], leak_routes=True)

    @decorators.attr(type='negative')
    @decorators.idempotent_id('5e425d39-dcf6-4184-b9a8-e0c787d30cc6')
    def test_create_subnet_with_leak_routes_rejected(self):
        network = self.create_network()
        self.assertRaises(
            lib_exc.BadRequest,
            self.admin_client.create_subnet,
            network_id=network['id'],
            cidr='10.202.0.0/24',
            ip_version=4,
            leak_routes=True)

    @decorators.attr(type='negative')
    @decorators.idempotent_id('c42d285f-ccce-4ffc-81ff-4280b0f9daeb')
    def test_non_admin_update_leak_routes(self):
        _network, subnet, _router = self._create_leakable_topology()
        self.assertRaises(
            lib_exc.Forbidden,
            self.client.update_subnet,
            subnet['id'], leak_routes=True)
