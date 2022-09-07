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


class NDPProxyTestJSON(base.BaseAdminNetworkTest):

    credentials = ['primary', 'admin']
    required_extensions = ['router', 'l3-ndp-proxy', 'address-scope']

    @classmethod
    def resource_setup(cls):
        super(NDPProxyTestJSON, cls).resource_setup()
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
            **{'subnetpool_id': subnetpool['id'], "cidr": "2001:abc::2:0/112"})
        cls.router = cls.create_router(data_utils.rand_name('router'),
                                       external_network_id=ext_net['id'],
                                       enable_ndp_proxy=True)
        cls.create_router_interface(cls.router['id'], cls.subnet['id'])

    @decorators.idempotent_id('481bc712-d504-4128-bffb-62d98b88886b')
    def test_ndp_proxy_lifecycle(self):
        port = self.create_port(self.network)
        np_description = 'Test ndp proxy description'
        np_name = 'test-ndp-proxy'

        #  Create ndp proxy
        created_ndp_proxy = self.create_ndp_proxy(
            name=np_name,
            description=np_description,
            router_id=self.router['id'],
            port_id=port['id'])
        self.assertEqual(self.router['id'], created_ndp_proxy['router_id'])
        self.assertEqual(port['id'], created_ndp_proxy['port_id'])
        self.assertEqual(np_description, created_ndp_proxy['description'])
        self.assertEqual(np_name, created_ndp_proxy['name'])
        self.assertEqual(port['fixed_ips'][0]['ip_address'],
                         created_ndp_proxy['ip_address'])

        # Show created ndp_proxy
        body = self.client.get_ndp_proxy(created_ndp_proxy['id'])
        ndp_proxy = body['ndp_proxy']
        self.assertEqual(np_description, ndp_proxy['description'])
        self.assertEqual(self.router['id'], ndp_proxy['router_id'])
        self.assertEqual(port['id'], ndp_proxy['port_id'])
        self.assertEqual(np_name, ndp_proxy['name'])
        self.assertEqual(port['fixed_ips'][0]['ip_address'],
                         ndp_proxy['ip_address'])

        # List ndp proxies
        body = self.client.list_ndp_proxies()
        ndp_proxy_ids = [np['id'] for np in body['ndp_proxies']]
        self.assertIn(created_ndp_proxy['id'], ndp_proxy_ids)

        # Update ndp proxy
        updated_ndp_proxy = self.client.update_ndp_proxy(
                               created_ndp_proxy['id'],
                               name='updated_ndp_proxy')
        self.assertEqual('updated_ndp_proxy',
                         updated_ndp_proxy['ndp_proxy']['name'])
        self.assertEqual(
            np_description, updated_ndp_proxy['ndp_proxy']['description'])
        self.assertEqual(self.router['id'],
                         updated_ndp_proxy['ndp_proxy']['router_id'])
        self.assertEqual(port['id'], updated_ndp_proxy['ndp_proxy']['port_id'])
        self.assertEqual(port['fixed_ips'][0]['ip_address'],
                         updated_ndp_proxy['ndp_proxy']['ip_address'])

        # Delete ndp proxy
        self.delete_ndp_proxy(created_ndp_proxy)
        self.assertRaises(exceptions.NotFound,
                          self.client.get_ndp_proxy, created_ndp_proxy['id'])
