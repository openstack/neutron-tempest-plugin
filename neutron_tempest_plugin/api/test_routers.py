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

import netaddr

from neutron_lib import constants as const

from tempest.common import utils as tutils
from tempest.lib.common.utils import data_utils
from tempest.lib import decorators
from tempest.lib import exceptions as lib_exc

from neutron_tempest_plugin.api import base
from neutron_tempest_plugin.api import base_routers
from neutron_tempest_plugin.common import utils
from neutron_tempest_plugin import config

CONF = config.CONF


class RoutersTest(base_routers.BaseRouterTest):

    required_extensions = ['router']

    @classmethod
    def resource_setup(cls):
        super(RoutersTest, cls).resource_setup()
        cls.tenant_cidr = (
            CONF.network.project_network_cidr
            if cls._ip_version == 4 else
            CONF.network.project_network_v6_cidr)

    @decorators.idempotent_id('c72c1c0c-2193-4aca-eeee-b1442640eeee')
    @tutils.requires_ext(extension="standard-attr-description",
                       service="network")
    def test_create_update_router_description(self):
        body = self.create_router(description='d1', router_name='test')
        self.assertEqual('d1', body['description'])
        body = self.client.show_router(body['id'])['router']
        self.assertEqual('d1', body['description'])
        body = self.client.update_router(body['id'], description='d2')
        self.assertEqual('d2', body['router']['description'])
        body = self.client.show_router(body['router']['id'])['router']
        self.assertEqual('d2', body['description'])

    @decorators.idempotent_id('847257cc-6afd-4154-b8fb-af49f5670ce8')
    @tutils.requires_ext(extension='ext-gw-mode', service='network')
    def test_create_router_with_default_snat_value(self):
        # Create a router with default snat rule
        name = data_utils.rand_name('router')
        router = self._create_router(
            name, external_network_id=CONF.network.public_network_id)
        self._verify_router_gateway(
            router['id'], {'network_id': CONF.network.public_network_id,
                           'enable_snat': True})

    @decorators.idempotent_id('ea74068d-09e9-4fd7-8995-9b6a1ace920f')
    @tutils.requires_ext(extension='ext-gw-mode', service='network')
    def test_create_router_with_snat_explicit(self):
        name = data_utils.rand_name('snat-router')
        # Create a router enabling snat attributes
        enable_snat_states = [False, True]
        for enable_snat in enable_snat_states:
            external_gateway_info = {
                'network_id': CONF.network.public_network_id,
                'enable_snat': enable_snat}
            router = self._create_admin_router(
                name, external_network_id=CONF.network.public_network_id,
                enable_snat=enable_snat)
            # Verify snat attributes after router creation
            self._verify_router_gateway(router['id'],
                                        exp_ext_gw_info=external_gateway_info)

    def _verify_router_gateway(self, router_id, exp_ext_gw_info=None):
        show_body = self.admin_client.show_router(router_id)
        actual_ext_gw_info = show_body['router']['external_gateway_info']
        if exp_ext_gw_info is None:
            self.assertIsNone(actual_ext_gw_info)
            return
        # Verify only keys passed in exp_ext_gw_info
        for k, v in exp_ext_gw_info.items():
            self.assertEqual(v, actual_ext_gw_info[k])

    def _verify_gateway_port(self, router_id):
        list_body = self.admin_client.list_ports(
            network_id=CONF.network.public_network_id,
            device_id=router_id)
        self.assertEqual(len(list_body['ports']), 1)
        gw_port = list_body['ports'][0]
        fixed_ips = gw_port['fixed_ips']
        self.assertGreaterEqual(len(fixed_ips), 1)
        public_net_body = self.admin_client.show_network(
            CONF.network.public_network_id)
        public_subnet_ids = public_net_body['network']['subnets']
        for fixed_ip in fixed_ips:
            self.assertIn(fixed_ip['subnet_id'],
                          public_subnet_ids)

    @decorators.idempotent_id('b386c111-3b21-466d-880c-5e72b01e1a33')
    @tutils.requires_ext(extension='ext-gw-mode', service='network')
    def test_update_router_set_gateway_with_snat_explicit(self):
        router = self._create_router(data_utils.rand_name('router'))
        self.admin_client.update_router_with_snat_gw_info(
            router['id'],
            external_gateway_info={
                'network_id': CONF.network.public_network_id,
                'enable_snat': True})
        self._verify_router_gateway(
            router['id'],
            {'network_id': CONF.network.public_network_id,
             'enable_snat': True})
        self._verify_gateway_port(router['id'])

    @decorators.idempotent_id('96536bc7-8262-4fb2-9967-5c46940fa279')
    @tutils.requires_ext(extension='ext-gw-mode', service='network')
    def test_update_router_set_gateway_without_snat(self):
        router = self._create_router(data_utils.rand_name('router'))
        self.admin_client.update_router_with_snat_gw_info(
            router['id'],
            external_gateway_info={
                'network_id': CONF.network.public_network_id,
                'enable_snat': False})
        self._verify_router_gateway(
            router['id'],
            {'network_id': CONF.network.public_network_id,
             'enable_snat': False})
        self._verify_gateway_port(router['id'])

    @decorators.idempotent_id('f2faf994-97f4-410b-a831-9bc977b64374')
    @tutils.requires_ext(extension='ext-gw-mode', service='network')
    def test_update_router_reset_gateway_without_snat(self):
        router = self._create_router(
            data_utils.rand_name('router'),
            external_network_id=CONF.network.public_network_id)
        self.admin_client.update_router_with_snat_gw_info(
            router['id'],
            external_gateway_info={
                'network_id': CONF.network.public_network_id,
                'enable_snat': False})
        self._verify_router_gateway(
            router['id'],
            {'network_id': CONF.network.public_network_id,
             'enable_snat': False})
        self._verify_gateway_port(router['id'])

    @decorators.idempotent_id('db3093b1-93b6-4893-be83-c4716c251b3e')
    def test_router_interface_status(self):
        network = self.create_network()
        subnet = self.create_subnet(network)
        # Add router interface with subnet id
        router = self._create_router(data_utils.rand_name('router'), True)
        intf = self.create_router_interface(router['id'], subnet['id'])

        def _status_active():
            return self.client.show_port(
                intf['port_id'])['port']['status'] == 'ACTIVE'

        utils.wait_until_true(_status_active, exception=AssertionError)

    @decorators.idempotent_id('c86ac3a8-50bd-4b00-a6b8-62af84a0765c')
    @tutils.requires_ext(extension='extraroute', service='network')
    def test_update_extra_route(self):
        self.network = self.create_network()
        self.name = self.network['name']
        self.subnet = self.create_subnet(self.network)
        # Add router interface with subnet id
        self.router = self._create_router(
            data_utils.rand_name('router-'), True)
        self.create_router_interface(self.router['id'], self.subnet['id'])
        self.addCleanup(
            self._delete_extra_routes,
            self.router['id'])
        # Update router extra route, second ip of the range is
        # used as next hop
        cidr = netaddr.IPNetwork(self.subnet['cidr'])
        next_hop = str(cidr[2])
        destination = str(self.subnet['cidr'])
        extra_route = self.client.update_extra_routes(self.router['id'],
                                                      next_hop, destination)
        self.assertEqual(1, len(extra_route['router']['routes']))
        self.assertEqual(destination,
                         extra_route['router']['routes'][0]['destination'])
        self.assertEqual(next_hop,
                         extra_route['router']['routes'][0]['nexthop'])
        show_body = self.client.show_router(self.router['id'])
        self.assertEqual(destination,
                         show_body['router']['routes'][0]['destination'])
        self.assertEqual(next_hop,
                         show_body['router']['routes'][0]['nexthop'])

    def _delete_extra_routes(self, router_id):
        self.client.delete_extra_routes(router_id)

    @decorators.idempotent_id('b29d1698-d603-11e9-9c66-079cc4aec539')
    @tutils.requires_ext(extension='extraroute-atomic', service='network')
    def test_extra_routes_atomic(self):
        self.network = self.create_network()
        self.subnet = self.create_subnet(self.network)
        self.router = self._create_router(
            data_utils.rand_name('router-'), True)
        self.create_router_interface(self.router['id'], self.subnet['id'])
        self.addCleanup(
            self._delete_extra_routes,
            self.router['id'])

        if self._ip_version == 6:
            dst = '2001:db8:%s::/64'
        else:
            dst = '10.0.%s.0/24'

        cidr = netaddr.IPNetwork(self.subnet['cidr'])

        routes = [
            {'destination': dst % 2, 'nexthop': cidr[2]},
        ]
        resp = self.client.add_extra_routes_atomic(
            self.router['id'], routes)
        self.assertEqual(1, len(resp['router']['routes']))

        routes = [
            {'destination': dst % 2, 'nexthop': cidr[2]},
            {'destination': dst % 3, 'nexthop': cidr[3]},
        ]
        resp = self.client.add_extra_routes_atomic(
            self.router['id'], routes)
        self.assertEqual(2, len(resp['router']['routes']))

        routes = [
            {'destination': dst % 3, 'nexthop': cidr[3]},
            {'destination': dst % 4, 'nexthop': cidr[4]},
        ]
        resp = self.client.remove_extra_routes_atomic(
            self.router['id'], routes)
        self.assertEqual(1, len(resp['router']['routes']))

        routes = [
            {'destination': dst % 2, 'nexthop': cidr[5]},
        ]
        resp = self.client.add_extra_routes_atomic(
            self.router['id'], routes)
        self.assertEqual(2, len(resp['router']['routes']))

        routes = [
            {'destination': dst % 2, 'nexthop': cidr[5]},
        ]
        resp = self.client.remove_extra_routes_atomic(
            self.router['id'], routes)
        self.assertEqual(1, len(resp['router']['routes']))

        routes = [
            {'destination': dst % 2, 'nexthop': cidr[2]},
            {'destination': dst % 3, 'nexthop': cidr[3]},
            {'destination': dst % 2, 'nexthop': cidr[5]},
        ]
        resp = self.client.remove_extra_routes_atomic(
            self.router['id'], routes)
        self.assertEqual(0, len(resp['router']['routes']))

    @decorators.idempotent_id('01f185d1-d1a6-4cf9-abf7-e0e1384c169c')
    def test_network_attached_with_two_routers(self):
        network = self.create_network(data_utils.rand_name('network1'))
        self.create_subnet(network)
        port1 = self.create_port(network)
        port2 = self.create_port(network)
        router1 = self._create_router(data_utils.rand_name('router1'))
        router2 = self._create_router(data_utils.rand_name('router2'))
        self.client.add_router_interface_with_port_id(
            router1['id'], port1['id'])
        self.client.add_router_interface_with_port_id(
            router2['id'], port2['id'])
        self.addCleanup(self.client.remove_router_interface_with_port_id,
                        router1['id'], port1['id'])
        self.addCleanup(self.client.remove_router_interface_with_port_id,
                        router2['id'], port2['id'])
        body = self.client.show_port(port1['id'])
        port_show1 = body['port']
        body = self.client.show_port(port2['id'])
        port_show2 = body['port']
        self.assertEqual(port_show1['network_id'], network['id'])
        self.assertEqual(port_show2['network_id'], network['id'])
        self.assertEqual(port_show1['device_id'], router1['id'])
        self.assertEqual(port_show2['device_id'], router2['id'])

    @decorators.idempotent_id('4f8a2a1e-7fe9-4d99-9bff-5dc0e78b7e06')
    def test_router_interface_update_and_remove_gateway_ip(self):
        network = self.create_network()
        subnet = self.create_subnet(network, allocation_pool_size=5)

        # Update the subnet gateway IP, using the next one. Because the
        # allocation pool is on the upper part of the CIDR, the lower IP
        # addresses are free. This operation must be allowed because the subnet
        # does not have yet a router port.
        gateway_ip = netaddr.IPAddress(subnet['gateway_ip'])
        self.client.update_subnet(subnet['id'], gateway_ip=str(gateway_ip + 1))

        router = self._create_router(data_utils.rand_name('router'), True)
        intf = self.create_router_interface(router['id'], subnet['id'])

        def _status_active():
            return self.client.show_port(
                intf['port_id'])['port']['status'] == 'ACTIVE'

        utils.wait_until_true(_status_active, exception=AssertionError)

        # The gateway update must raise a ``GatewayIpInUse`` exception because
        # there is an allocated router port.
        gateway_ip = netaddr.IPAddress(subnet['gateway_ip'])
        self.assertRaises(lib_exc.Conflict, self.client.update_subnet,
                          subnet['id'], gateway_ip=str(gateway_ip + 2))

        # The gateway deletion returns the same exception.
        gateway_ip = netaddr.IPAddress(subnet['gateway_ip'])
        self.assertRaises(lib_exc.Conflict, self.client.update_subnet,
                          subnet['id'], gateway_ip=None)


class ExternalGWMultihomingRoutersTest(base_routers.BaseRouterTest):

    @classmethod
    @tutils.requires_ext(extension="external-gateway-multihoming",
                         service="network")
    def setUpClass(cls):
        super().setUpClass()

    @decorators.idempotent_id('33e9a156-a83f-435f-90ee-1a49dc9c350d')
    def test_create_router_enable_default_route_ecmp(self):
        router1 = self._create_admin_router(data_utils.rand_name('router1'),
                                            enable_default_route_ecmp=True)
        router2 = self._create_admin_router(data_utils.rand_name('router2'),
                                            enable_default_route_ecmp=False)
        self.assertEqual(router1['enable_default_route_ecmp'], True)
        self.assertEqual(router2['enable_default_route_ecmp'], False)

    @decorators.idempotent_id('bfbad985-2df2-4cd9-9c32-819b5508c40e')
    def test_update_router_enable_default_route_ecmp(self):
        router = self._create_router(data_utils.rand_name('router'))
        updated_router = self.admin_client.update_router(
            router['id'],
            enable_default_route_ecmp=not router['enable_default_route_ecmp'])
        self.assertNotEqual(
            router['enable_default_route_ecmp'],
            updated_router['router']['enable_default_route_ecmp'])

    @decorators.idempotent_id('a22016a6-f118-4eb5-abab-7e241ae01848')
    def test_update_router_enable_default_route_bfd(self):
        router = self._create_router(data_utils.rand_name('router'))
        updated_router = self.admin_client.update_router(
            router['id'],
            enable_default_route_bfd=not router['enable_default_route_bfd'])
        self.assertNotEqual(
            router['enable_default_route_bfd'],
            updated_router['router']['enable_default_route_bfd'])

    @decorators.idempotent_id('842f6edb-e072-4805-bf11-04c25420776d')
    def test_create_router_enable_default_route_bfd(self):
        router1 = self._create_admin_router(data_utils.rand_name('router1'),
                                            enable_default_route_bfd=True)
        router2 = self._create_admin_router(data_utils.rand_name('router2'),
                                            enable_default_route_bfd=False)
        self.assertEqual(router1['enable_default_route_bfd'], True)
        self.assertEqual(router2['enable_default_route_bfd'], False)

    @decorators.idempotent_id('089fa304-3726-4120-9759-668e8ff1114c')
    def test_create_router_add_external_gateways_one(self):
        router = self._create_router(data_utils.rand_name('router'))
        self.assertEqual(len(router['external_gateways']), 0)

        res = self.admin_client.router_add_external_gateways(
            router['id'],
            [{'network_id': CONF.network.public_network_id,
              'enable_snat': False}])
        self.assertEqual(len(res['router']['external_gateways']), 1)
        self.assertEqual(
            res['router']['external_gateways'][0]['network_id'],
            CONF.network.public_network_id)

    @decorators.idempotent_id('60a1e7db-04ef-4a3a-9ff1-01a990d365fd')
    def test_create_router_add_external_gateways(self):
        router = self._create_router(data_utils.rand_name('router'))
        self.assertEqual(len(router['external_gateways']), 0)

        res = self.admin_client.router_add_external_gateways(
            router['id'],
            [
                {'network_id': CONF.network.public_network_id,
                 'enable_snat': False},
                {'network_id': CONF.network.public_network_id,
                 'enable_snat': False},
                {'network_id': CONF.network.public_network_id,
                 'enable_snat': False},
            ])
        self.assertEqual(len(res['router']['external_gateways']), 3)
        self.assertEqual(
            res['router']['external_gateway_info']['network_id'],
            res['router']['external_gateways'][0]['network_id'])
        self.assertEqual(
            res['router']['external_gateway_info']['external_fixed_ips'],
            res['router']['external_gateways'][0]['external_fixed_ips'])
        for n in range(0, 3):
            self.assertEqual(
                res['router']['external_gateways'][n]['network_id'],
                CONF.network.public_network_id)
            if n:
                self.assertNotEqual(
                    res['router']['external_gateways'][
                        n]['external_fixed_ips'],
                    res['router']['external_gateways'][
                        n - 1]['external_fixed_ips'])

    @decorators.idempotent_id('e49efc57-7b25-43a3-8e55-2d87a3759c57')
    def test_create_router_add_external_gateways_compat(self):
        router = self._create_router(
            data_utils.rand_name('router'),
            external_network_id=CONF.network.public_network_id,
            enable_snat=False,
            client=self.admin_client,
        )
        self.assertEqual(len(router['external_gateways']), 1)
        res = self.admin_client.router_add_external_gateways(
            router['id'],
            [{'network_id': CONF.network.public_network_id,
              'enable_snat': False}])
        self.assertEqual(len(res['router']['external_gateways']), 2)

    @decorators.idempotent_id('2a238eec-d9d5-435a-9013-d6e195ecd5d1')
    def test_create_router_remove_external_gateways_compat(self):
        router = self._create_router(
            data_utils.rand_name('router'),
            external_network_id=CONF.network.public_network_id,
            enable_snat=False,
            client=self.admin_client)
        self.assertEqual(len(router['external_gateways']), 1)
        res = self.admin_client.router_remove_external_gateways(
            router['id'],
            [{'network_id': CONF.network.public_network_id}])
        self.assertEqual(len(res['router']['external_gateways']), 0)

    @decorators.idempotent_id('03ab196a-dac0-4363-93e4-ea799246870b')
    def test_create_router_add_remove_external_gateways(self):
        router = self._create_router(data_utils.rand_name('router'))
        self.assertEqual(len(router['external_gateways']), 0)

        res = self.admin_client.router_add_external_gateways(
            router['id'],
            [
                {'network_id': CONF.network.public_network_id,
                 'enable_snat': False},
                {'network_id': CONF.network.public_network_id,
                 'enable_snat': False},
                {'network_id': CONF.network.public_network_id,
                 'enable_snat': False},
            ])
        self.assertEqual(len(res['router']['external_gateways']), 3)
        remove_gateways = [res['router']['external_gateways'][2]]
        res = self.client.router_remove_external_gateways(router['id'],
                                                          remove_gateways)
        self.assertEqual(len(res['router']['external_gateways']), 2)
        for n in range(0, 2):
            self.assertNotEqual(
                    res['router']['external_gateways'][
                        n]['external_fixed_ips'],
                    remove_gateways[0])

    @decorators.idempotent_id('17e94c9f-c59f-4e50-abd5-d1256460e311')
    def test_create_router_update_external_gateways(self):
        """Add three GW ports, delete last one, re-use IPs in update on second.

        NOTE(fnordahl): Main reason for IP re-use is to ensure we don't tread
        on allocations done by other tests.
        """
        router = self._create_router(data_utils.rand_name('router'))
        self.assertEqual(len(router['external_gateways']), 0)

        res = self.admin_client.router_add_external_gateways(
            router['id'],
            [
                {'network_id': CONF.network.public_network_id,
                 'enable_snat': False},
                {'network_id': CONF.network.public_network_id,
                 'enable_snat': False},
                {'network_id': CONF.network.public_network_id,
                 'enable_snat': False},
            ])
        self.assertEqual(len(res['router']['external_gateways']), 3)
        external_gateways = res['router']['external_gateways']
        remove_gateways = [external_gateways.pop(2)]
        res_remove_gws = self.client.router_remove_external_gateways(
            router['id'],
            remove_gateways)
        for n in range(0, 2):
            self.assertNotEqual(
                    res_remove_gws['router']['external_gateways'][
                        n]['external_fixed_ips'],
                    remove_gateways[0])

        external_gateways[1] = remove_gateways[0]
        res_update_gws = self.admin_client.router_update_external_gateways(
            router['id'],
            external_gateways)

        self.assertEqual(len(res_update_gws['router']['external_gateways']), 2)
        for n in range(0, 2):
            if res_update_gws['router']['external_gateways'][
                        n] == remove_gateways[0]:
                break
        else:
            self.fail('%s not in %s' % (
                remove_gateways[0],
                res_update_gws['router']['external_gateways']))


class RoutersIpV6Test(RoutersTest):
    _ip_version = 6


class DvrRoutersTest(base_routers.BaseRouterTest):

    required_extensions = ['dvr']

    @decorators.idempotent_id('141297aa-3424-455d-aa8d-f2d95731e00a')
    def test_create_distributed_router(self):
        name = data_utils.rand_name('router')
        router = self._create_admin_router(name, distributed=True)
        self.assertTrue(router['distributed'])


class DvrRoutersTestToCentralized(base_routers.BaseRouterTest):

    required_extensions = ['dvr', 'l3-ha']

    @decorators.idempotent_id('644d7a4a-01a1-4b68-bb8d-0c0042cb1729')
    def test_convert_distributed_router_back_to_centralized(self):
        # Convert a centralized router to distributed firstly
        router_args = {'tenant_id': self.client.project_id,
                       'distributed': False, 'ha': False}
        router = self._create_admin_router(
            data_utils.rand_name('router'), admin_state_up=False,
            **router_args)
        self.assertFalse(router['distributed'])
        self.assertFalse(router['ha'])
        update_body = self.admin_client.update_router(router['id'],
                                                      distributed=True)
        self.assertTrue(update_body['router']['distributed'])
        show_body = self.admin_client.show_router(router['id'])
        self.assertTrue(show_body['router']['distributed'])
        self.assertFalse(show_body['router']['ha'])
        # Then convert the distributed router back to centralized
        update_body = self.admin_client.update_router(router['id'],
                                                      distributed=False)
        self.assertFalse(update_body['router']['distributed'])
        show_body = self.admin_client.show_router(router['id'])
        self.assertFalse(show_body['router']['distributed'])
        self.assertFalse(show_body['router']['ha'])
        show_body = self.client.show_router(router['id'])
        self.assertNotIn('distributed', show_body['router'])
        self.assertNotIn('ha', show_body['router'])


class DvrRoutersTestUpdateDistributedExtended(base_routers.BaseRouterTest):

    required_extensions = ['dvr', 'l3-ha',
                           'router-admin-state-down-before-update']

    @decorators.idempotent_id('0ffb9973-0c1a-4b76-a1f2-060178057661')
    def test_convert_centralized_router_to_distributed_extended(self):
        router_args = {'tenant_id': self.client.project_id,
                       'distributed': False, 'ha': False}
        router = self._create_admin_router(
            data_utils.rand_name('router'), admin_state_up=True,
            **router_args)
        self.assertTrue(router['admin_state_up'])
        self.assertFalse(router['distributed'])
        # take router down to allow setting the router to distributed
        update_body = self.admin_client.update_router(router['id'],
                                                      admin_state_up=False)
        self.assertFalse(update_body['router']['admin_state_up'])
        # set the router to distributed
        update_body = self.admin_client.update_router(router['id'],
                                                      distributed=True)
        self.assertTrue(update_body['router']['distributed'])
        # bring the router back up
        update_body = self.admin_client.update_router(router['id'],
                                                      admin_state_up=True)
        self.assertTrue(update_body['router']['admin_state_up'])
        self.assertTrue(update_body['router']['distributed'])

    @decorators.idempotent_id('e9a8f55b-c535-44b7-8b0a-20af6a7c2921')
    def test_convert_distributed_router_to_centralized_extended(self):
        router_args = {'tenant_id': self.client.project_id,
                       'distributed': True, 'ha': False}
        router = self._create_admin_router(
            data_utils.rand_name('router'), admin_state_up=True,
            **router_args)
        self.assertTrue(router['admin_state_up'])
        self.assertTrue(router['distributed'])
        # take router down to allow setting the router to centralized
        update_body = self.admin_client.update_router(router['id'],
                                                      admin_state_up=False)
        self.assertFalse(update_body['router']['admin_state_up'])
        # set router to centralized
        update_body = self.admin_client.update_router(router['id'],
                                                      distributed=False)
        self.assertFalse(update_body['router']['distributed'])
        # bring router back up
        update_body = self.admin_client.update_router(router['id'],
                                                      admin_state_up=True)
        self.assertTrue(update_body['router']['admin_state_up'])
        self.assertFalse(update_body['router']['distributed'])


class HaRoutersTest(base_routers.BaseRouterTest):

    required_extensions = ['l3-ha']

    @decorators.idempotent_id('77db8eae-3aa3-4e61-bf2a-e739ce042e53')
    def test_convert_legacy_router(self):
        router = self._create_router(data_utils.rand_name('router'))
        self.assertNotIn('ha', router)
        update_body = self.admin_client.update_router(router['id'],
                                                      ha=True)
        self.assertTrue(update_body['router']['ha'])
        show_body = self.admin_client.show_router(router['id'])
        self.assertTrue(show_body['router']['ha'])
        show_body = self.client.show_router(router['id'])
        self.assertNotIn('ha', show_body['router'])


class RoutersSearchCriteriaTest(base.BaseSearchCriteriaTest):

    required_extensions = ['router']
    resource = 'router'

    @classmethod
    def resource_setup(cls):
        super(RoutersSearchCriteriaTest, cls).resource_setup()
        for name in cls.resource_names:
            cls.create_router(router_name=name)

    @decorators.idempotent_id('03a69efb-90a7-435b-bb5c-3add3612085a')
    def test_list_sorts_asc(self):
        self._test_list_sorts_asc()

    @decorators.idempotent_id('95913d30-ff41-4b17-9f44-5258c651e78c')
    def test_list_sorts_desc(self):
        self._test_list_sorts_desc()

    @decorators.idempotent_id('7f7d40b1-e165-4817-8dc5-02f8e2f0dff3')
    def test_list_pagination(self):
        self._test_list_pagination()

    @decorators.idempotent_id('a5b83e83-3d98-45bb-a2c7-0ee179ffd42c')
    def test_list_pagination_with_marker(self):
        self._test_list_pagination_with_marker()

    @decorators.idempotent_id('40804af8-c25d-45f8-b8a8-b4c70345215d')
    def test_list_pagination_with_href_links(self):
        self._test_list_pagination_with_href_links()

    @decorators.idempotent_id('77b9676c-d3cb-43af-a0e8-a5b8c6099e70')
    def test_list_pagination_page_reverse_asc(self):
        self._test_list_pagination_page_reverse_asc()

    @decorators.idempotent_id('3133a2c5-1bb9-4fc7-833e-cf9a1d160255')
    def test_list_pagination_page_reverse_desc(self):
        self._test_list_pagination_page_reverse_desc()

    @decorators.idempotent_id('8252e2f0-b3da-4738-8e25-f6f8d878a2da')
    def test_list_pagination_page_reverse_with_href_links(self):
        self._test_list_pagination_page_reverse_with_href_links()

    @decorators.idempotent_id('fb102124-20f8-4cb3-8c81-f16f5e41d192')
    def test_list_no_pagination_limit_0(self):
        self._test_list_no_pagination_limit_0()


class RoutersDeleteTest(base_routers.BaseRouterTest):
    """The only test in this class is a test that removes router!

    * We cannot delete common and mandatory resources (router in this case)
    * using the existing classes, as it will cause failure in other tests
    * running in parallel.
    """
    @classmethod
    def resource_setup(cls):
        super(RoutersDeleteTest, cls).resource_setup()
        cls.secgroup = cls.create_security_group(
            name=data_utils.rand_name("test_port_secgroup"))
        router_kwargs = {
            'router_name': data_utils.rand_name('router_to_delete'),
            'external_network_id': CONF.network.public_network_id}
        cls.router = cls.create_router(**router_kwargs)

    @decorators.idempotent_id('dbbc5c74-63c8-11eb-8881-74e5f9e2a801')
    def test_delete_router(self):
        # Create a port on tenant network and associate to the router.
        # Try to delete router. Expected result: "Conflict Error" is raised.
        network = self.create_network()
        subnet = self.create_subnet(network)
        self.create_router_interface(self.router['id'], subnet['id'])
        port = self.create_port(
            network, name=data_utils.rand_name("port"),
            security_groups=[self.secgroup['id']])
        self.create_floatingip(port=port)
        self.assertRaises(
            lib_exc.Conflict, self.client.delete_router, self.router['id'])
        # Delete the associated port
        # Try to delete router. Expected result: "Conflict Error" is raised.
        # Note: there are still interfaces in use.
        self.client.delete_port(port['id'])
        self.assertRaises(
            lib_exc.Conflict, self.client.delete_router, self.router['id'])
        # Delete the rest of the router's ports
        # Try to delete router. Expected result: "PASS"
        interfaces = [
            port for port in self.client.list_router_interfaces(
                self.router['id'])['ports']
            if port['device_owner'] in const.ROUTER_INTERFACE_OWNERS]
        for i in interfaces:
            try:
                self.assertRaises(
                    lib_exc.Conflict, self.client.delete_router,
                    self.router['id'])
                self.client.remove_router_interface_with_subnet_id(
                    self.router['id'], i['fixed_ips'][0]['subnet_id'])
            except lib_exc.NotFound:
                pass
        self.client.delete_router(self.router['id'])
