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


class IndirectFloatingIPsNegativeTestJSON(base.BaseAdminNetworkTest):

    credentials = ['primary', 'admin']
    required_extensions = ['router', 'floating-ip-router-writable']

    def _create_indirect_topology(self, outer_external_network_id=None):
        project_network = self.create_network()
        project_subnet = self.create_subnet(project_network)
        transit_network = self.create_network()
        self.create_subnet(transit_network)

        inner_router = self.create_router(data_utils.rand_name('inner-router'))
        outer_router = self.create_router(
            data_utils.rand_name('outer-router'),
            external_network_id=outer_external_network_id)
        self.create_router_interface(inner_router['id'], project_subnet['id'])

        inner_transit_port = self.create_port(transit_network)
        self.client.add_router_interface_with_port_id(
            inner_router['id'], inner_transit_port['id'])
        outer_transit_port = self.create_port(transit_network)
        self.client.add_router_interface_with_port_id(
            outer_router['id'], outer_transit_port['id'])

        return self.create_port(project_network), outer_router

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
