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

from neutron_tempest_plugin.api import base
from neutron_tempest_plugin import config

CONF = config.CONF


class SubnetOVNBGPTestBase(base.BaseAdminNetworkTest):
    required_extensions = ['ovn-bgp']
    credentials = ['primary', 'admin']

    def _create_leakable_topology(self, cidr=None):
        """Create a private network + subnet + router with external GW.

        This is the minimum topology required to enable leak_routes.
        Returns (network, subnet, router).
        """
        network = self.create_network()
        kwargs = {}
        if cidr:
            kwargs['cidr'] = cidr
            kwargs['ip_version'] = 4
        subnet = self.create_subnet(network, **kwargs)
        router = self.create_admin_router(
            data_utils.rand_name('router-bgp'),
            external_network_id=CONF.network.public_network_id)
        self.create_router_interface(
            router['id'], subnet['id'], client=self.admin_client)
        return network, subnet, router


class SubnetOVNBGPTest(SubnetOVNBGPTestBase):

    @decorators.idempotent_id('a58ca372-5a66-4896-9b70-dbdf568f6516')
    def test_leak_routes_default_false(self):
        network = self.create_network()
        subnet = self.create_subnet(network)
        body = self.admin_client.show_subnet(subnet['id'])
        self.assertFalse(body['subnet']['leak_routes'])

    @decorators.idempotent_id('4e4c7497-6d9a-4ec9-9fad-c00f09a29c3d')
    def test_update_subnet_enable_leak_routes(self):
        _network, subnet, _router = self._create_leakable_topology()
        self.admin_client.update_subnet(subnet['id'], leak_routes=True)
        body = self.admin_client.show_subnet(subnet['id'])
        self.assertTrue(body['subnet']['leak_routes'])

    @decorators.idempotent_id('7fc98034-8cdd-4d23-8725-4e241ad42a7a')
    def test_update_subnet_disable_leak_routes(self):
        _network, subnet, _router = self._create_leakable_topology()
        self.admin_client.update_subnet(subnet['id'], leak_routes=True)
        self.admin_client.update_subnet(subnet['id'], leak_routes=False)
        body = self.admin_client.show_subnet(subnet['id'])
        self.assertFalse(body['subnet']['leak_routes'])

    @decorators.idempotent_id('06edee0f-3083-406f-83e4-0df1a67bc490')
    def test_leak_routes_idempotent(self):
        _network, subnet, _router = self._create_leakable_topology()
        self.admin_client.update_subnet(subnet['id'], leak_routes=True)
        self.admin_client.update_subnet(subnet['id'], leak_routes=True)
        body = self.admin_client.show_subnet(subnet['id'])
        self.assertTrue(body['subnet']['leak_routes'])
