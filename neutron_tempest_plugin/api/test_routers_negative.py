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

from tempest.lib.common.utils import data_utils
from tempest.lib import decorators
from tempest.lib import exceptions as lib_exc
import testtools

from neutron_tempest_plugin.api import base_routers as base


class RoutersNegativeTestBase(base.BaseRouterTest):

    required_extensions = ['router']

    @classmethod
    def resource_setup(cls):
        super(RoutersNegativeTestBase, cls).resource_setup()
        cls.router = cls.create_router(data_utils.rand_name('router'))
        cls.network = cls.create_network()
        cls.subnet = cls.create_subnet(cls.network)


class RoutersNegativeTest(RoutersNegativeTestBase):

    @decorators.attr(type='negative')
    @decorators.idempotent_id('e3e751af-15a2-49cc-b214-a7154579e94f')
    def test_delete_router_in_use(self):
        # This port is deleted after a test by remove_router_interface.
        port = self.create_port(self.network)
        self.client.add_router_interface_with_port_id(
            self.router['id'], port['id'])
        with testtools.ExpectedException(lib_exc.Conflict):
            self.client.delete_router(self.router['id'])


class RoutersNegativePolicyTest(RoutersNegativeTestBase):

    credentials = ['admin', 'primary', 'alt']

    @decorators.attr(type='negative')
    @decorators.idempotent_id('159f576d-a423-46b5-b501-622694c02f6b')
    def test_add_interface_wrong_tenant(self):
        client2 = self.os_alt.network_client
        network = client2.create_network()['network']
        self.addCleanup(client2.delete_network, network['id'])
        subnet = self.create_subnet(network, client=client2)
        # This port is deleted after a test by remove_router_interface.
        port = client2.create_port(network_id=network['id'])['port']
        self.addCleanup(client2.delete_port, port['id'])
        with testtools.ExpectedException(lib_exc.NotFound):
            client2.add_router_interface_with_port_id(
                self.router['id'], port['id'])
        with testtools.ExpectedException(lib_exc.NotFound):
            client2.add_router_interface_with_subnet_id(
                self.router['id'], subnet['id'])


class DvrRoutersNegativeTest(RoutersNegativeTestBase):

    required_extensions = ['dvr']

    @decorators.attr(type='negative')
    @decorators.idempotent_id('4990b055-8fc7-48ab-bba7-aa28beaad0b9')
    def test_router_create_tenant_distributed_returns_forbidden(self):
        with testtools.ExpectedException(lib_exc.Forbidden):
            self.create_router(
                data_utils.rand_name('router'), distributed=True)


class DvrRoutersNegativeTestExtended(RoutersNegativeTestBase):

    required_extensions = ['dvr', 'router-admin-state-down-before-update']

    @decorators.attr(type='negative')
    @decorators.idempotent_id('5379fe06-e45e-4a4f-8b4a-9e28a924b451')
    def test_router_update_distributed_returns_exception(self):
        # create a centralized router
        router_args = {'tenant_id': self.client.tenant_id,
                       'distributed': False}
        router = self._create_admin_router(
            data_utils.rand_name('router'), admin_state_up=True,
            **router_args)
        self.assertTrue(router['admin_state_up'])
        self.assertFalse(router['distributed'])
        # attempt to set the router to distributed, catch BadRequest exception
        self.assertRaises(lib_exc.BadRequest,
                          self.admin_client.update_router,
                          router['id'],
                          distributed=True)

    @decorators.attr(type='negative')
    @decorators.idempotent_id('c277e945-3b39-442d-b149-e2e8cc6a2b40')
    def test_router_update_centralized_returns_exception(self):
        # create a centralized router
        router_args = {'tenant_id': self.client.tenant_id,
                       'distributed': False}
        router = self._create_admin_router(
            data_utils.rand_name('router'), admin_state_up=True,
            **router_args)
        self.assertTrue(router['admin_state_up'])
        self.assertFalse(router['distributed'])
        # take the router down to modify distributed->True
        update_body = self.admin_client.update_router(router['id'],
                                                      admin_state_up=False)
        self.assertFalse(update_body['router']['admin_state_up'])
        update_body = self.admin_client.update_router(router['id'],
                                                      distributed=True)
        self.assertTrue(update_body['router']['distributed'])
        # set admin_state_up=True
        update_body = self.admin_client.update_router(router['id'],
                                                      admin_state_up=True)
        self.assertTrue(update_body['router']['admin_state_up'])
        # attempt to set the router to centralized, catch BadRequest exception
        self.assertRaises(lib_exc.BadRequest,
                          self.admin_client.update_router,
                          router['id'],
                          distributed=False)


class HaRoutersNegativeTest(RoutersNegativeTestBase):

    required_extensions = ['l3-ha']

    @decorators.attr(type='negative')
    @decorators.idempotent_id('821b85b9-9c51-40f3-831f-bf223a7e0084')
    def test_router_create_tenant_ha_returns_forbidden(self):
        with testtools.ExpectedException(lib_exc.Forbidden):
            self.create_router(
                data_utils.rand_name('router'), ha=True)
