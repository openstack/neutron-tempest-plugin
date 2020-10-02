# Copyright 2020 OpenStack Foundation
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
from tempest.lib import exceptions

from neutron_tempest_plugin.api import base
from neutron_tempest_plugin import config

CONF = config.CONF


class PortForwardingNegativeTestJSON(base.BaseNetworkTest):
    required_extensions = ['router', 'floating-ip-port-forwarding']

    @classmethod
    def resource_setup(cls):
        super(PortForwardingNegativeTestJSON, cls).resource_setup()
        cls.ext_net_id = CONF.network.public_network_id

        # Create network, subnet, router and add interface
        cls.network = cls.create_network()
        cls.subnet = cls.create_subnet(cls.network)
        cls.router = cls.create_router(data_utils.rand_name('router'),
                                       external_network_id=cls.ext_net_id)
        cls.create_router_interface(cls.router['id'], cls.subnet['id'])

    @decorators.attr(type='negative')
    @decorators.idempotent_id('63c0d406-99d5-11ea-bb37-0242ac130002')
    def test_mapping_same_fip_and_external_port_to_different_dest(self):
        port1 = self.create_port(self.network)
        port2 = self.create_port(self.network)
        fip_for_pf = self.create_floatingip()

        self.create_port_forwarding(
            fip_for_pf['id'],
            internal_port_id=port1['id'],
            internal_ip_address=port1['fixed_ips'][0]['ip_address'],
            internal_port=1111, external_port=2222,
            protocol="tcp")

        self.assertRaises(
            exceptions.BadRequest,
            self.create_port_forwarding,
            fip_for_pf['id'],
            internal_port_id=port2['id'],
            internal_ip_address=port2['fixed_ips'][0]['ip_address'],
            internal_port=3333, external_port=2222,
            protocol="tcp")

    @decorators.attr(type='negative')
    @decorators.idempotent_id('0c229a4c-9f28-11ea-bb37-0242ac130002')
    def test_mapping_different_external_ports_to_the_same_destination(self):
        port = self.create_port(self.network)
        fip_for_pf = self.create_floatingip()

        self.create_port_forwarding(
            fip_for_pf['id'],
            internal_port_id=port['id'],
            internal_ip_address=port['fixed_ips'][0]['ip_address'],
            internal_port=1111, external_port=3333,
            protocol="tcp")

        self.assertRaises(
            exceptions.BadRequest,
            self.create_port_forwarding,
            fip_for_pf['id'],
            internal_port_id=port['id'],
            internal_ip_address=port['fixed_ips'][0]['ip_address'],
            internal_port=1111, external_port=5555,
            protocol="tcp")

    @decorators.attr(type='negative')
    @decorators.idempotent_id('e9d3ffb6-e5bf-421d-acaa-ee6010dfbf14')
    def test_out_of_range_ports(self):
        port = self.create_port(self.network)
        fip_for_pf = self.create_floatingip()

        pf_params = {
            'internal_port_id': port['id'],
            'internal_ip_address': port['fixed_ips'][0]['ip_address'],
            'internal_port': 1111,
            'external_port': 3333,
            'protocol': "tcp"}
        pf = self.create_port_forwarding(fip_for_pf['id'], **pf_params)

        # Check: Invalid input for external_port update
        self.assertRaises(
            exceptions.BadRequest,
            self.update_port_forwarding,
            fip_for_pf['id'], pf['id'], external_port=108343)

        # Check: Invalid input for internal_port update
        self.assertRaises(
            exceptions.BadRequest,
            self.update_port_forwarding,
            fip_for_pf['id'], pf['id'], internal_port=108343)

        # Check: Invalid input for external_port create
        pf_params['internal_port'] = 4444
        pf_params['external_port'] = 333333
        self.assertRaises(
            exceptions.BadRequest,
            self.create_port_forwarding, fip_for_pf['id'], **pf_params)

        # Check: Invalid input for internal_port create
        pf_params['internal_port'] = 444444
        pf_params['external_port'] = 3333
        self.assertRaises(
            exceptions.BadRequest,
            self.create_port_forwarding, fip_for_pf['id'], **pf_params)
