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

import threading

from neutron_lib import constants as nlib_const
from tempest.common import utils as tutils
from tempest.lib.common.utils import data_utils
from tempest.lib.common.utils import test_utils
from tempest.lib import decorators
from tempest.lib import exceptions as lib_exc

from neutron_tempest_plugin.api import base


class RoutersEvpnTest(base.BaseAdminNetworkTest):
    # VNIs used in this class must not overlap with RoutersEvpnNegativeTest
    # because tempest may run both classes in parallel.
    required_extensions = ['router', 'evpn']
    base_vni = 500

    @decorators.idempotent_id('a4f3c2b1-0d9e-4f8a-b7c6-5e4d3c2b1a09')
    def test_create_router_post_accepted_with_evpn_vni(self):
        name = data_utils.rand_name('evpn-router')
        router = self.create_admin_router(name, evpn_vni=self.base_vni)
        self.assertEqual(500, router['evpn_vni'])
        body = self.admin_client.show_router(router['id'])
        self.assertEqual(500, body['router']['evpn_vni'])

    @decorators.idempotent_id('b5e4d3c2-1f0a-5b9e-c8d7-6f5e4d3c2b1a')
    @tutils.requires_ext(extension='standard-attr-description',
                         service='network')
    def test_create_router_with_evpn_vni_and_description(self):
        name = data_utils.rand_name('evpn-router')
        desc = 'evpn router description'
        router = self.create_admin_router(
            name, description=desc, evpn_vni=self.base_vni + 1)
        self.assertEqual(501, router['evpn_vni'])
        self.assertEqual(desc, router['description'])


class AutoVniRoutersEvpnTest(base.BaseAdminNetworkTest):
    # All tests that auto-allocate VNIs (evpn_vni=0) live in this single
    # class. Tempest runs one class per worker, so they run sequentially and
    # do not conflict with the other test classes, which only use explicit
    # VNIs (100-103, 500-501 and the 1000+ scenario range).
    # The tests must not rely on how Neutron picks the VNI (e.g. lowest free
    # VNI), only on the API contract: the VNI is valid, unique and was not in
    # use when the router was created.
    required_extensions = ['router', 'evpn']

    # Routers are created per test (not with create_admin_router) and deleted
    # at the end of each test, to stay below the router quota of the admin
    # project and to leave the VNIs free for the next test.
    VNI_FREE_TIMEOUT = 60
    CONCURRENT_ROUTERS = 5

    def _used_vnis(self):
        routers = self.admin_client.list_routers(
            fields=['id', 'evpn_vni'])['routers']
        return {r['evpn_vni'] for r in routers if r.get('evpn_vni')}

    def _assert_new_auto_vni(self, vni, used):
        self.assertIsInstance(vni, int)
        self.assertGreaterEqual(vni, 1)
        self.assertLessEqual(vni, nlib_const.MAX_VXLAN_VNI)
        self.assertNotIn(vni, used)

    def _register_router_cleanup(self, router):
        self.addCleanup(self._try_delete_resource, self.delete_router,
                        router, self.admin_client)

    def _create_evpn_router(self, **kwargs):
        router = self._create_router_with_client(
            self.admin_client, data_utils.rand_name('evpn-router'), **kwargs)
        self._register_router_cleanup(router)
        return router

    def _create_auto_vni_router(self, **kwargs):
        return self._create_evpn_router(evpn_vni=0, **kwargs)

    def _delete_router_and_wait(self, router):
        self.delete_router(router, self.admin_client)

        def _is_gone():
            try:
                self.admin_client.show_router(router['id'])
            except lib_exc.NotFound:
                return True
            return False

        self.assertTrue(
            test_utils.call_until_true(_is_gone, self.VNI_FREE_TIMEOUT, 1),
            'Router %s was not deleted in %s seconds' % (
                router['id'], self.VNI_FREE_TIMEOUT))

    @decorators.idempotent_id('bc8cdf9f-e16b-4dfb-9195-161bdb700b47')
    def test_create_router_auto_vni(self):
        router = self._create_auto_vni_router()
        vni = router['evpn_vni']
        self.assertIsInstance(vni, int)
        self.assertGreaterEqual(vni, 1)
        self.assertLessEqual(vni, nlib_const.MAX_VXLAN_VNI)
        body = self.admin_client.show_router(router['id'])
        self.assertEqual(vni, body['router']['evpn_vni'])

    @decorators.idempotent_id('e48417aa-237f-42e5-a27f-54834ec04a78')
    def test_auto_vni_is_not_in_use(self):
        used = self._used_vnis()
        router = self._create_auto_vni_router()
        self._assert_new_auto_vni(router['evpn_vni'], used)

    @decorators.idempotent_id('0fc6a6cf-1db5-45db-9eaa-b8abc66e975e')
    def test_auto_vni_distinct_for_multiple_routers(self):
        vnis = []
        for _ in range(3):
            used = self._used_vnis()
            router = self._create_auto_vni_router()
            self._assert_new_auto_vni(router['evpn_vni'], used)
            vnis.append(router['evpn_vni'])
        self.assertEqual(3, len(set(vnis)))

    @decorators.idempotent_id('f6630f07-979a-4b45-99be-5d36182aed20')
    def test_delete_auto_vni_router_frees_vni_for_explicit_use(self):
        auto_router = self._create_auto_vni_router()
        vni = auto_router['evpn_vni']
        self._delete_router_and_wait(auto_router)
        self.assertNotIn(vni, self._used_vnis())

        self._create_evpn_router(evpn_vni=vni)
        self.assertIn(vni, self._used_vnis())

    @decorators.idempotent_id('0728d72c-1bd9-4b0f-8c35-48c22588977f')
    def test_auto_vni_concurrent_creation(self):
        count = self.CONCURRENT_ROUTERS
        used = self._used_vnis()

        barrier = threading.Barrier(count)
        routers = []
        errors = []

        def _create():
            try:
                barrier.wait(timeout=30)
                routers.append(self._create_router_with_client(
                    self.admin_client, data_utils.rand_name('evpn-router'),
                    evpn_vni=0))
            except Exception as exc:
                errors.append(exc)

        threads = [threading.Thread(target=_create) for _ in range(count)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        # Clean up every router that was created, even if a sibling failed.
        for router in routers:
            self._register_router_cleanup(router)

        self.assertEqual([], errors)
        vnis = [router['evpn_vni'] for router in routers]
        self.assertEqual(count, len(set(vnis)), 'Duplicated VNIs: %s' % vnis)
        for vni in vnis:
            self._assert_new_auto_vni(vni, used)
