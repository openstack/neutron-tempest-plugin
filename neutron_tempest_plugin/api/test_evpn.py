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

from tempest.common import utils as tutils
from tempest.lib.common.utils import data_utils
from tempest.lib import decorators

from neutron_tempest_plugin.api import base_routers as base


class RoutersEvpnTest(base.BaseRouterTest):
    # VNIs used in this class must not overlap with RoutersEvpnNegativeTest
    # because tempest may run both classes in parallel.
    required_extensions = ['router', 'evpn']

    @decorators.idempotent_id('a4f3c2b1-0d9e-4f8a-b7c6-5e4d3c2b1a09')
    def test_create_router_post_accepted_with_evpn_vni(self):
        name = data_utils.rand_name('evpn-router')
        router = self._create_admin_router(name, evpn_vni=500)
        self.assertEqual(500, router['evpn_vni'])
        body = self.admin_client.show_router(router['id'])
        self.assertEqual(500, body['router']['evpn_vni'])

    @decorators.idempotent_id('b5e4d3c2-1f0a-5b9e-c8d7-6f5e4d3c2b1a')
    @tutils.requires_ext(extension='standard-attr-description',
                         service='network')
    def test_create_router_with_evpn_vni_and_description(self):
        name = data_utils.rand_name('evpn-router')
        desc = 'evpn router description'
        router = self._create_admin_router(
            name, description=desc, evpn_vni=501)
        self.assertEqual(501, router['evpn_vni'])
        self.assertEqual(desc, router['description'])
