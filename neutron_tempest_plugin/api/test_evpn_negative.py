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
import testtools

from neutron_tempest_plugin.api import base_routers as base

VNI_MAX = 2**24 - 1


class RoutersEvpnNegativeTest(base.BaseRouterTest):
    # VNIs used in this class must not overlap with RoutersEvpnTest
    # because tempest may run both classes in parallel.
    required_extensions = ['router', 'evpn']
    credentials = ['admin', 'primary']

    @decorators.attr(type='negative')
    @decorators.idempotent_id('c6d5e4f3-2a1b-4c8d-9e0f-7a6b5c4d3e2f')
    def test_create_router_evpn_vni_non_admin_forbidden(self):
        name = data_utils.rand_name('evpn-router')
        with testtools.ExpectedException(lib_exc.Forbidden):
            self.client.create_router(name=name, evpn_vni=100)

    @decorators.attr(type='negative')
    @decorators.idempotent_id('d7e6f5a4-3b2c-5d9e-0f1a-8b7c6d5e4f3a')
    def test_update_router_evpn_vni_non_admin_badrequest(self):
        name = data_utils.rand_name('evpn-router')
        router = self.create_router(name)
        with testtools.ExpectedException(lib_exc.BadRequest):
            self.client.update_router(router['id'], evpn_vni=100)

    @decorators.attr(type='negative')
    @decorators.idempotent_id('e8f7a6b5-4c3d-6e0f-1a2b-9c8d7e6f5a4b')
    def test_create_router_evpn_vni_below_minimum(self):
        name = data_utils.rand_name('evpn-router')
        self.assertRaises(
            lib_exc.BadRequest,
            self.admin_client.create_router,
            name=name, evpn_vni=-1)

    @decorators.attr(type='negative')
    @decorators.idempotent_id('f9a8b7c6-5d4e-7f1a-2b3c-0d9e8f7a6b5c')
    def test_create_router_evpn_vni_above_maximum(self):
        name = data_utils.rand_name('evpn-router')
        self.assertRaises(
            lib_exc.BadRequest,
            self.admin_client.create_router,
            name=name, evpn_vni=VNI_MAX + 1)

    @decorators.attr(type='negative')
    @decorators.idempotent_id('a1b2c3d4-6e5f-8a7b-3c4d-1e0f9a8b7c6d')
    def test_create_router_evpn_vni_invalid_type(self):
        name = data_utils.rand_name('evpn-router')
        self.assertRaises(
            lib_exc.BadRequest,
            self.admin_client.create_router,
            name=name, evpn_vni='invalid')

    @decorators.attr(type='negative')
    @decorators.idempotent_id('b2c3d4e5-7f6a-9b8c-4d5e-2f1a0b9c8d7e')
    def test_update_router_evpn_vni_not_allowed(self):
        name = data_utils.rand_name('evpn-router')
        router = self._create_admin_router(name, evpn_vni=100)
        self.assertRaises(
            lib_exc.BadRequest,
            self.admin_client.update_router,
            router['id'], evpn_vni=200)

    @decorators.attr(type='negative')
    @decorators.idempotent_id('d4e5f6a7-8b9c-0d1e-6f7a-4b3c2d1e0f9a')
    def test_create_router_evpn_vni_duplicate_conflict(self):
        vni = 100
        name1 = data_utils.rand_name('evpn-router')
        self._create_admin_router(name1, evpn_vni=vni)
        name2 = data_utils.rand_name('evpn-router')
        self.assertRaises(
            lib_exc.Conflict,
            self._create_admin_router,
            name2, evpn_vni=vni)
