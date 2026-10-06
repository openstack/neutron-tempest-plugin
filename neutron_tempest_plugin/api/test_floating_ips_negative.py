# Copyright 2014 Hewlett-Packard Development Company, L.P.
# Copyright 2014 OpenStack Foundation
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

from oslo_utils import uuidutils
from tempest.lib.common.utils import data_utils
from tempest.lib import decorators
from tempest.lib import exceptions as lib_exc

from neutron_tempest_plugin.api import base
from neutron_tempest_plugin import config

CONF = config.CONF


class FloatingIPNegativeTestJSON(base.BaseNetworkTest):

    required_extensions = ['router']

    @classmethod
    def resource_setup(cls):
        super().resource_setup()
        cls.ext_net_id = CONF.network.public_network_id
        # Create a network with a subnet connected to a router.
        cls.network = cls.create_network()
        cls.subnet = cls.create_subnet(cls.network)
        cls.router = cls.create_router(data_utils.rand_name('router'))
        cls.create_router_interface(cls.router['id'], cls.subnet['id'])
        cls.port = cls.create_port(cls.network)

    @decorators.attr(type='negative')
    @decorators.idempotent_id('0b5b8797-6de7-4191-905c-a48b888eb429')
    def test_associate_floatingip_with_port_with_floatingip(self):
        net = self.create_network()
        subnet = self.create_subnet(net)
        r = self.create_router('test')
        self.create_router_interface(r['id'], subnet['id'])
        self.client.update_router(
            r['id'],
            external_gateway_info={
                'network_id': self.ext_net_id})
        self.addCleanup(self.client.update_router, self.router['id'],
                        external_gateway_info={})
        port = self.create_port(net)
        floating_ip1 = self.create_floatingip()
        floating_ip2 = self.create_floatingip()
        self.client.update_floatingip(floating_ip1['id'],
                                      port_id=port['id'])
        self.assertRaises(lib_exc.Conflict, self.client.update_floatingip,
                          floating_ip2['id'], port_id=port['id'])


class IndirectFloatingIPsNegativeTestJSON(
        base.IndirectFloatingIPAdminTestBase):

    @decorators.attr(type='negative')
    @decorators.idempotent_id('fb0bdc69-57df-48a5-9e30-7cc6b8b9a1a1')
    def test_floatingip_router_without_gateway_on_floating_network(self):
        other_external_network = self.create_network(external=True)
        self.create_subnet(other_external_network)
        port, router = self._create_indirect_topology(
            other_external_network['id'])

        self.assertRaises(
            lib_exc.Conflict,
            self.create_floatingip,
            port=port,
            router_id=router['id'])

    @decorators.attr(type='negative')
    @decorators.idempotent_id('f3c46ae0-a0cf-4a15-a7b1-8cb03dc29af7')
    def test_floatingip_without_router_id_on_isolated_network(self):
        port, _router = self._create_indirect_topology()

        self.assertRaises(
            lib_exc.NotFound,
            self.create_floatingip,
            port=port)

    @decorators.attr(type='negative')
    @decorators.idempotent_id('2d3f9f2c-25ee-4d1a-b24f-42728bc8ec5e')
    def test_floatingip_cannot_associate_isolated_network_port(self):
        network = self.create_network()
        self.create_subnet(network)
        port = self.create_port(network)
        floating_ip = self.create_floatingip()

        self.assertRaises(
            lib_exc.NotFound,
            self.client.update_floatingip,
            floating_ip['id'], port_id=port['id'])


class IndirectFloatingIPsPolicyNegativeTestJSON(
        base.IndirectFloatingIPAdminTestBase):

    credentials = ['primary', 'project_reader', 'admin']

    @classmethod
    def setup_clients(cls):
        super().setup_clients()
        cls.reader_client = cls.os_project_reader.network_client

    @decorators.attr(type='negative')
    @decorators.idempotent_id('dcf70f65-204d-4c73-9cab-68b283bc5e4f')
    def test_floatingip_create_router_id_forbidden_for_reader(self):
        port, outer_router = self._create_indirect_topology(
            outer_external_network_id=self.ext_net_id)

        self.assertRaises(
            lib_exc.Forbidden,
            self.reader_client.create_floatingip,
            self.ext_net_id,
            port_id=port['id'],
            router_id=outer_router['id'])

    @decorators.attr(type='negative')
    @decorators.idempotent_id('ee4e0695-4eef-4884-ad29-453ea8707558')
    def test_floatingip_update_router_id_forbidden_for_reader(self):
        port, router_a, router_b = self._create_dual_gateway_topology()

        floatingip = self.create_floatingip(
            port=port, router_id=router_a['id'])

        self.assertRaises(
            lib_exc.Forbidden,
            self.reader_client.update_floatingip,
            floatingip['id'],
            router_id=router_b['id'])


class IndirectFloatingIPsRouterIdNegativeTestJSON(
        base.IndirectFloatingIPAdminTestBase):

    credentials = ['primary', 'alt', 'admin']

    @classmethod
    def setup_clients(cls):
        super().setup_clients()
        cls.alt_client = cls.os_alt.network_client

    @decorators.attr(type='negative')
    @decorators.idempotent_id('7486fe3e-b445-4e84-a644-471b2194c3a5')
    def test_floatingip_create_with_nonexistent_router_id(self):
        port, _outer_router = self._create_indirect_topology(
            outer_external_network_id=self.ext_net_id)

        self.assertRaises(
            lib_exc.NotFound,
            self.create_floatingip,
            port=port,
            router_id=uuidutils.generate_uuid())

    @decorators.attr(type='negative')
    @decorators.idempotent_id('f9c26f5e-0572-4b3f-952d-28bed813b292')
    def test_floatingip_create_with_cross_project_router_id(self):
        port, _outer_router = self._create_indirect_topology(
            outer_external_network_id=self.ext_net_id)
        alt_router = self._create_router_with_client(
            self.alt_client,
            data_utils.rand_name('alt-gw-router'),
            external_network_id=self.ext_net_id)
        self.addCleanup(self.alt_client.delete_router, alt_router['id'])

        self.assertRaises(
            lib_exc.NotFound,
            self.create_floatingip,
            port=port,
            router_id=alt_router['id'])
