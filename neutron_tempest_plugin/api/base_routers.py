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

from tempest.lib import exceptions

from neutron_tempest_plugin.api import base


class BaseRouterTest(base.BaseAdminNetworkTest):
    # NOTE(salv-orlando): This class inherits from BaseAdminNetworkTest
    # as some router operations, such as enabling or disabling SNAT
    # require admin credentials by default

    def _cleanup_router(self, router, client=None):
        try:
            self.delete_router(router, client)
            self.routers.remove(router)
        except exceptions.NotFound:
            pass

    def _create_router(self, name, admin_state_up=False,
                       external_network_id=None, enable_snat=None,
                       client=None, **kwargs):
        # associate a cleanup with created routers to avoid quota limits
        client = client or self.client
        router = self._create_router_with_client(
            client, router_name=name, admin_state_up=admin_state_up,
            external_network_id=external_network_id, enable_snat=enable_snat,
            **kwargs)
        self.addCleanup(self._cleanup_router, router)
        return router

    def _create_admin_router(self, *args, **kwargs):
        router = self.create_admin_router(*args, **kwargs)
        self.addCleanup(
            self._cleanup_router, router, self.os_admin.network_client)
        return router

    def _delete_router(self, router_id, network_client=None):
        client = network_client or self.client
        client.delete_router(router_id)
        # Asserting that the router is not found in the list
        # after deletion
        list_body = self.client.list_routers()
        routers_list = list()
        for router in list_body['routers']:
            routers_list.append(router['id'])
        self.assertNotIn(router_id, routers_list)
