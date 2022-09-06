# Copyright 2022 Troila
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

from neutron_lib import constants
from tempest.lib.common.utils import data_utils
from tempest.lib import decorators
from tempest.lib import exceptions

from neutron_tempest_plugin.api import base
from neutron_tempest_plugin import config

CONF = config.CONF


class NDPProxyNegativeTestJSON(base.BaseAdminNetworkTest):

    credentials = ['primary', 'admin']
    required_extensions = ['router', 'l3-ndp-proxy', 'address-scope']

    @classmethod
    def resource_setup(cls):
        super(NDPProxyNegativeTestJSON, cls).resource_setup()
        address_scope = cls.create_address_scope(
            "test-as", **{'ip_version': constants.IP_VERSION_6})
        subnetpool = cls.create_subnetpool(
            "test-subnetpool",
            **{'address_scope_id': address_scope['id'],
               'default_prefixlen': 112,
               'prefixes': ['2001:abc::0/96']})
        # Create an external network and it's subnet
        ext_net = cls.create_network('test-ext-net', client=cls.admin_client,
                                     external=True)
        cls.create_subnet(
            ext_net, client=cls.admin_client,
            ip_version=constants.IP_VERSION_6,
            **{'subnetpool_id': subnetpool['id'], "cidr": "2001:abc::1:0/112"})
        # Create network, subnet, router and add interface
        cls.network = cls.create_network()
        cls.subnet = cls.create_subnet(
            cls.network, ip_version=constants.IP_VERSION_6,
            cidr='2002::abcd:0/112')
        cls.router = cls.create_router(
            data_utils.rand_name('router'),
            external_network_id=ext_net['id'])

    @decorators.attr(type='negative')
    @decorators.idempotent_id('a0897204-bb85-41cc-a5fd-5d0ab8116a07')
    def test_enable_ndp_proxy_without_external_gw(self):
        self.client.update_router(self.router['id'], external_gateway_info={})
        self.assertRaises(exceptions.Conflict,
            self.client.update_router,
            self.router['id'],
            enable_ndp_proxy=True)

    @decorators.attr(type='negative')
    @decorators.idempotent_id('26e534a0-3e47-4894-8cb5-20a078ce76a9')
    def test_create_ndp_proxy_with_subnet_not_connect_router(self):
        self.client.update_router(self.router['id'], enable_ndp_proxy=True)
        port = self.create_port(self.network)
        self.assertRaises(exceptions.Conflict,
            self.create_ndp_proxy,
            self.router['id'],
            port_id=port['id'])

    @decorators.attr(type='negative')
    @decorators.idempotent_id('a0d93fd6-1219-4b05-9db8-bdf02846c447')
    def test_create_ndp_proxy_with_different_address_scope(self):
        self.client.update_router(self.router['id'], enable_ndp_proxy=True)
        address_scope = self.create_address_scope(
            "test-as", ip_version=constants.IP_VERSION_6)
        subnet_pool = self.create_subnetpool(
            "test-sp", address_scope_id=address_scope['id'],
            prefixes=['2002::abc:0/112'], default_prefixlen=112)
        network = self.create_network()
        subnet = self.create_subnet(
            network, ip_version=constants.IP_VERSION_6,
            cidr="2002::abc:0/112", subnetpool_id=subnet_pool['id'],
            reserve_cidr=False)
        self.create_router_interface(self.router['id'], subnet['id'])
        port = self.create_port(network)
        self.assertRaises(exceptions.Conflict, self.create_ndp_proxy,
                          self.router['id'], port_id=port['id'])

    @decorators.attr(type='negative')
    @decorators.idempotent_id('f9a4e56d-3836-40cd-8c05-585b3f1e034a')
    def test_create_ndp_proxy_without_ipv6_address(self):
        self.client.update_router(
            self.router['id'], enable_ndp_proxy=True)
        subnet = self.create_subnet(
            self.network, ip_version=constants.IP_VERSION_4)
        self.create_router_interface(self.router['id'], subnet['id'])
        port = self.create_port(self.network)
        self.assertRaises(exceptions.Conflict,
                          self.create_ndp_proxy,
                          self.router['id'], port_id=port['id'])

    @decorators.attr(type='negative')
    @decorators.idempotent_id('e035b3af-ebf9-466d-9ef5-a73b063a1f56')
    def test_enable_ndp_proxy_and_unset_gateway(self):
        self.assertRaises(exceptions.Conflict,
                          self.client.update_router,
                          self.router['id'],
                          enable_ndp_proxy=True,
                          external_gateway_info={})

    @decorators.attr(type='negative')
    @decorators.idempotent_id('194b5ee7-4c59-4643-aabf-80a125c3f688')
    def test_enable_ndp_proxy_without_address_scope(self):
        extnet = self.create_network("extnet", client=self.admin_client,
                                     external=True)
        self.create_subnet(extnet, client=self.admin_client,
                           ip_version=constants.IP_VERSION_6,
                           cidr='2001:abc1::0/112')
        self.assertRaises(exceptions.Conflict,
                          self.client.create_router,
                          name=data_utils.rand_name('router'),
                          enable_ndp_proxy=True,
                          external_gateway_info={'network_id': extnet['id']})
        router = self.create_router(data_utils.rand_name('router'))
        self.assertRaises(exceptions.Conflict,
                          self.client.update_router,
                          router['id'], enable_ndp_proxy=True,
                          external_gateway_info={'network_id': extnet['id']})
