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


class RoutersTestHA(base.BaseRouterTest):

    required_extensions = ['router', 'l3-ha']
    HA_NETWORK_NAME_TEMPL = "HA network tenant %s"

    @classmethod
    def resource_setup(cls):
        # The check above will pass if api_extensions=all, which does
        # not mean "l3-ha" extension itself is present.
        # Instead, we have to check whether "ha" is actually present by using
        # admin credentials to create router with ha=True attribute
        # and checking for BadRequest exception and that the resulting router
        # has a high availability attribute.
        super(RoutersTestHA, cls).resource_setup()
        name = data_utils.rand_name('pretest-check')
        router = cls.admin_client.create_router(name)
        cls.admin_client.delete_router(router['router']['id'])
        if 'ha' not in router['router']:
            msg = "'ha' attribute not found. HA Possibly not enabled"
            raise cls.skipException(msg)

    @decorators.idempotent_id('8abc177d-14f1-4018-9f01-589b299cbee1')
    def test_ha_router_creation(self):
        """Test HA router creation

        Test uses administrative credentials to create a
        HA (High Availability) router using the ha=True.

        Acceptance
        The router is created and the "ha" attribute is set to True
        """
        name = data_utils.rand_name('router')
        router = self._create_admin_router(name, ha=True)
        self.assertTrue(router['ha'])

    @decorators.idempotent_id('97b5f7ef-2192-4fa3-901e-979cd5c1097a')
    def test_legacy_router_creation(self):
        """Test legacy router creation

        Test uses administrative credentials to create a
        SF (Single Failure) router using the ha=False.

        Acceptance
        The router is created and the "ha" attribute is
        set to False, thus making it a "Single Failure Router"
        as opposed to a "High Availability Router"
        """
        name = data_utils.rand_name('router')
        router = self._create_admin_router(name, ha=False)
        self.assertFalse(router['ha'])

    @decorators.idempotent_id('5a6bfe82-5b23-45a4-b027-5160997d4753')
    def test_legacy_router_update_to_ha(self):
        """Test legacy to HA router update

        Test uses administrative credentials to create a
        SF (Single Failure) router using the ha=False.
        Then it will "update" the router ha attribute to True

        Acceptance
        The router is created and the "ha" attribute is
        set to False. Once the router is updated, the ha
        attribute will be set to True
        """
        name = data_utils.rand_name('router')
        # router needs to be in admin state down in order to be upgraded to HA
        router = self._create_admin_router(name, ha=False,
                                           admin_state_up=False)
        self.assertFalse(router['ha'])
        router = self.admin_client.update_router(router['id'],
                                                 ha=True)
        self.assertTrue(router['router']['ha'])

    @decorators.idempotent_id('0d8c0c8f-3809-4acc-a2c8-e0941333ff6c')
    @tutils.requires_ext(extension="provider", service="network")
    def test_delete_ha_router_keeps_ha_network_segment_data(self):
        """Test deleting an HA router keeps correct segment data for network.

        Each tenant with HA router has an HA network. The HA network is a
        normal tenant network with segmentation data like type (vxlan) and
        segmenation id. This test makes sure that after an HA router is
        deleted, those segmentation data are kept in HA network. This tests
        regression of https://bugs.launchpad.net/neutron/+bug/1732543.
        """
        for i in range(2):
            router = self._create_admin_router(
                data_utils.rand_name('router%d' % i),
                ha=True)
        ha_net_name = self.HA_NETWORK_NAME_TEMPL % router['tenant_id']
        ha_network_pre_delete = self.admin_client.list_networks(
            name=ha_net_name)['networks'][0]
        segmentation_id = ha_network_pre_delete['provider:segmentation_id']
        self._delete_router(router['id'], self.admin_client)

        ha_network_post_delete = self.admin_client.show_network(
            ha_network_pre_delete['id'])['network']
        self.assertEqual(
            ha_network_post_delete['provider:segmentation_id'],
            segmentation_id)
