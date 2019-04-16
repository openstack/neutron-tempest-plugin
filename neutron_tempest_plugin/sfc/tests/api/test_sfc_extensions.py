# Copyright 2016 Futurewei. All rights reserved.
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

from tempest.lib.common.utils import data_utils
from tempest.lib import decorators

from neutron_tempest_plugin.sfc.tests.api import base


class SfcExtensionTestJSON(base.BaseSfcTest):
    """Tests the following operations in the Neutron API:

        List port chains
        Create port chain
        Update port chain
        Delete port chain
        Show port chain
        List port pair groups
        Create port pair group
        Update port pair group
        Delete port pair group
        Show port pair groups
        List port pairs
        Create port pair
        Update port pair
        Delete port pair
        Show port pair
        List Service Graphs
        Create Service Graph
        Update Service Graph
        Delete Service Graph
        Show Service Graphs
    """
    @decorators.idempotent_id('1a6067bf-b967-42a7-8b62-158a9ec185b4')
    def test_create_port_pair_different_ingress_egress(self):
        ingress_network = self.create_network()
        self.addCleanup(self.networks_client.delete_network,
                        ingress_network['id'])
        cidr = netaddr.IPNetwork('192.168.1.0/24')
        allocation_pools = {'allocation_pools': [{'start': str(cidr[2]),
                                                  'end': str(cidr[-2])}]}
        ingress_subnet = self.create_subnet(ingress_network, cidr=cidr,
                                            mask_bits=cidr.prefixlen,
                                            **allocation_pools)
        self.addCleanup(self.subnets_client.delete_subnet,
                        ingress_subnet['id'])
        egress_network = self.create_network()
        self.addCleanup(self.networks_client.delete_network,
                        egress_network['id'])
        cidr = netaddr.IPNetwork('192.168.2.0/24')
        allocation_pools = {'allocation_pools': [{'start': str(cidr[2]),
                                                  'end': str(cidr[-2])}]}
        egress_subnet = self.create_subnet(egress_network, cidr=cidr,
                                           mask_bits=cidr.prefixlen,
                                           **allocation_pools)
        self.addCleanup(self.subnets_client.delete_subnet,
                        egress_subnet['id'])
        router = self.admin_routers_client.create_router(
            name=data_utils.rand_name('router-'))['router']
        self.addCleanup(self.admin_routers_client.delete_router, router['id'])
        port_kwargs = {"binding:host_id": self.host_id}
        ingress = self._create_port(
            network=ingress_network, **port_kwargs)
        self.addCleanup(self._try_delete_port, ingress['id'])
        self.admin_routers_client.add_router_interface(
            router['id'], port_id=ingress['id'])
        self.addCleanup(self.admin_routers_client.remove_router_interface,
                        router['id'],
                        port_id=ingress['id'])
        egress = self._create_port(
            network=egress_network, **port_kwargs)
        self.addCleanup(self._try_delete_port, egress['id'])
        self.admin_routers_client.add_router_interface(
            router['id'], port_id=egress['id'])
        self.addCleanup(self.admin_routers_client.remove_router_interface,
                        router['id'],
                        port_id=egress['id'])
        pp = self._try_create_port_pair(
            ingress=ingress['id'],
            egress=egress['id'])
        pps = self.portpair_client.list_port_pairs()
        self.assertIn((
            pp['id'],
            pp['name'],
            pp['ingress'],
            pp['egress']
        ), [(
            m['id'],
            m['name'],
            m['ingress'],
            m['egress'],
        ) for m in pps['port_pairs']])

    @decorators.idempotent_id('264cc4b8-aa17-4cea-88bf-26400e9751d9')
    def test_list_port_pair(self):
        # List port pairs
        pp = self._try_create_port_pair()
        pps = self.portpair_client.list_port_pairs()
        self.assertIn((
            pp['id'],
            pp['name'],
            pp['ingress'],
            pp['egress']
        ), [(
            m['id'],
            m['name'],
            m['ingress'],
            m['egress'],
        ) for m in pps['port_pairs']])

    @decorators.idempotent_id('83018ad7-3666-4396-bf3a-288a2b6a0e7c')
    def test_show_port_pair(self):
        # show a created port pair
        created = self._try_create_port_pair()
        pp = self.portpair_client.show_port_pair(
            created['id'])
        for key, value in pp['port_pair'].items():
            self.assertEqual(created[key], value)

    @decorators.idempotent_id('69d21fa4-bdd5-4142-b1cc-6578037f605a')
    def test_update_port_pair(self):
        # Create port pair
        name1 = data_utils.rand_name('test')
        pp = self._try_create_port_pair(
            name=name1
        )
        pp_id = pp['id']

        # Update port pair
        name2 = data_utils.rand_name('test')
        body = self.portpair_client.update_port_pair(
            pp_id, name=name2)
        self.assertEqual(body['port_pair']['name'], name2)

    @decorators.idempotent_id('4fff9a4a-a98a-42bd-b3f4-483b93e6f297')
    def test_create_port_pair_group_empty_port_pairs(self):
        pg = self._try_create_port_pair_group(
            port_pairs=[])
        pgs = self.portpairgroup_client.list_port_pair_groups()
        self.assertIn((
            pg['id'],
            pg['name'],
            set(pg['port_pairs']),
        ), [(
            m['id'],
            m['name'],
            set(m['port_pairs'])
        ) for m in pgs['port_pair_groups']])

    @decorators.idempotent_id('1a1c98a0-ff54-4647-a798-011e902825fa')
    def test_create_port_pair_group_multi_port_pairs(self):
        pp1 = self._try_create_port_pair()
        pp2 = self._try_create_port_pair()
        pg = self._try_create_port_pair_group(
            port_pairs=[pp1['id'], pp2['id']])
        pgs = self.portpairgroup_client.list_port_pair_groups()
        self.assertIn((
            pg['id'],
            pg['name'],
            set(pg['port_pairs']),
        ), [(
            m['id'],
            m['name'],
            set(m['port_pairs'])
        ) for m in pgs['port_pair_groups']])

    @decorators.idempotent_id('e7d432c4-a7b4-444b-88cc-f420c5c1c29e')
    def test_list_port_pair_group(self):
        # List port pair groups
        pp = self._try_create_port_pair()
        pg = self._try_create_port_pair_group(port_pairs=[pp['id']])
        pgs = self.portpairgroup_client.list_port_pair_groups()
        self.assertIn((
            pg['id'],
            pg['name'],
            pg['port_pairs'],
        ), [(
            m['id'],
            m['name'],
            m['port_pairs']
        ) for m in pgs['port_pair_groups']])

    @decorators.idempotent_id('f12faa84-8dcb-4fbb-b03a-9ab05040a350')
    def test_show_port_pair_group(self):
        # show a created port pair group
        pp = self._try_create_port_pair()
        created = self._try_create_port_pair_group(port_pairs=[pp['id']])
        pg = self.portpairgroup_client.show_port_pair_group(
            created['id'])
        for key, value in pg['port_pair_group'].items():
            self.assertEqual(created[key], value)

    @decorators.idempotent_id('8991c2ef-71ba-4033-9037-5c8bf52a0c88')
    def test_update_port_pair_group(self):
        # Create port pair group
        pp = self._try_create_port_pair()
        name1 = data_utils.rand_name('test')
        pg = self._try_create_port_pair_group(
            name=name1, port_pairs=[pp['id']]
        )
        pg_id = pg['id']

        # Update port pair group
        name2 = data_utils.rand_name('test')
        body = self.portpairgroup_client.update_port_pair_group(
            pg_id, name=name2)
        self.assertEqual(body['port_pair_group']['name'], name2)

    @decorators.idempotent_id('d93d7ec3-f12e-4fad-b82b-759d358ff044')
    def test_create_port_chain_empty_flow_classifiers(self):
        # Create port chains
        pp = self._try_create_port_pair()
        pg = self._try_create_port_pair_group(port_pairs=[pp['id']])
        pc = self._try_create_port_chain(
            port_pair_groups=[pg['id']],
            flow_classifiers=[])
        pcs = self.portchain_client.list_port_chains()
        self.assertIn((
            pc['id'],
            pc['name'],
            pc['port_pair_groups'],
            pc['flow_classifiers']
        ), [(
            m['id'],
            m['name'],
            m['port_pair_groups'],
            m['flow_classifiers']
        ) for m in pcs['port_chains']])

    @decorators.idempotent_id('0c5ac396-6027-4bd1-af21-79fda6df9b77')
    def test_create_port_chain_multi_flowclassifiers(self):
        # Create port chains
        pp = self._try_create_port_pair()
        pg = self._try_create_port_pair_group(port_pairs=[pp['id']])
        fc1 = self._try_create_flowclassifier()
        fc2 = self._try_create_flowclassifier()
        pc = self._try_create_port_chain(
            port_pair_groups=[pg['id']],
            flow_classifiers=[fc1['id'], fc2['id']])
        pcs = self.portchain_client.list_port_chains()
        self.assertIn((
            pc['id'],
            pc['name'],
            set(pc['flow_classifiers'])
        ), [(
            m['id'],
            m['name'],
            set(m['flow_classifiers'])
        ) for m in pcs['port_chains']])

    @decorators.idempotent_id('81f0faba-49ae-435a-8454-566c1e0a929e')
    def test_create_port_chain_flowclassifiers_symmetric(self):
        # Create symmetric port chain
        router = self.admin_routers_client.create_router(
            name=data_utils.rand_name('router-'))['router']
        self.addCleanup(
            self.admin_routers_client.delete_router, router['id'])
        port_kwargs = {"binding:host_id": self.host_id}
        dst_port = self._create_port(
            network=self.network, **port_kwargs)
        self.addCleanup(self._try_delete_port, dst_port['id'])
        self.admin_routers_client.add_router_interface(
            router['id'], port_id=dst_port['id'])
        self.addCleanup(self.admin_routers_client.remove_router_interface,
                        router['id'],
                        port_id=dst_port['id'])
        pp = self._try_create_port_pair()
        pg = self._try_create_port_pair_group(port_pairs=[pp['id']])
        fc = self._try_create_flowclassifier(
            logical_destination_port=dst_port['id'])
        pc = self._try_create_port_chain(
            port_pair_groups=[pg['id']],
            flow_classifiers=[fc['id']],
            chain_parameters={'symmetric': True})
        pcs = self.portchain_client.list_port_chains()
        self.assertIn((
            pc['id'],
            pc['name'],
            pc['chain_parameters'],
            set(pc['flow_classifiers'])
        ), [(
            m['id'],
            m['name'],
            m['chain_parameters'],
            set(m['flow_classifiers'])
        ) for m in pcs['port_chains']])

    @decorators.idempotent_id('3f82c78f-e119-449f-bf6c-a964db45be3a')
    def test_create_port_chain_multi_port_pair_groups(self):
        # Create port chain
        pp1 = self._try_create_port_pair()
        pg1 = self._try_create_port_pair_group(port_pairs=[pp1['id']])
        pp2 = self._try_create_port_pair()
        pg2 = self._try_create_port_pair_group(port_pairs=[pp2['id']])
        fc = self._try_create_flowclassifier()
        pc = self._try_create_port_chain(
            port_pair_groups=[pg1['id'], pg2['id']],
            flow_classifiers=[fc['id']])
        pcs = self.portchain_client.list_port_chains()
        self.assertIn((
            pc['id'],
            pc['name'],
            pc['port_pair_groups'],
        ), [(
            m['id'],
            m['name'],
            m['port_pair_groups']
        ) for m in pcs['port_chains']])

    @decorators.idempotent_id('144629ec-7538-4595-93ea-89e28ba50724')
    def test_create_port_chain_port_pair_group_symmetric(self):
        # Create symmetric port chain with port_pair_group
        router = self.admin_routers_client.create_router(
            name=data_utils.rand_name('router-'))['router']
        self.addCleanup(
            self.admin_routers_client.delete_router, router['id'])
        port_kwargs = {"binding:host_id": self.host_id}
        dst_port = self._create_port(
            network=self.network, **port_kwargs)
        self.addCleanup(self._try_delete_port, dst_port['id'])
        self.admin_routers_client.add_router_interface(
            router['id'], port_id=dst_port['id'])
        self.addCleanup(self.admin_routers_client.remove_router_interface,
                        router['id'],
                        port_id=dst_port['id'])
        pp = self._try_create_port_pair()
        pg = self._try_create_port_pair_group(port_pairs=[pp['id']])
        fc = self._try_create_flowclassifier(
            logical_destination_port=dst_port['id'])
        pc = self._try_create_port_chain(
            port_pair_groups=[pg['id']],
            flow_classifiers=[fc['id']],
            chain_parameters={'symmetric': True})
        pcs = self.portchain_client.list_port_chains()
        self.assertIn((
            pc['id'],
            pc['name'],
            pc['port_pair_groups'],
            pc['chain_parameters']
        ), [(
            m['id'],
            m['name'],
            m['port_pair_groups'],
            m['chain_parameters']
        ) for m in pcs['port_chains']])

    @decorators.idempotent_id('83cfceba-f9d9-41e2-b27f-f919d8ff83a9')
    def test_list_port_chain(self):
        # List port chains
        pp = self._try_create_port_pair()
        pg = self._try_create_port_pair_group(port_pairs=[pp['id']])
        fc = self._try_create_flowclassifier()
        pc = self._try_create_port_chain(
            port_pair_groups=[pg['id']],
            flow_classifiers=[fc['id']])
        pcs = self.portchain_client.list_port_chains()
        self.assertIn((
            pc['id'],
            pc['name'],
            pc['port_pair_groups'],
            set(pc['flow_classifiers'])
        ), [(
            m['id'],
            m['name'],
            m['port_pair_groups'],
            set(m['flow_classifiers'])
        ) for m in pcs['port_chains']])

    @decorators.idempotent_id('0433ca11-dbc9-448d-8433-0df252e3d0cd')
    def test_show_port_chain(self):
        # show a created port chain
        pp = self._try_create_port_pair()
        pg = self._try_create_port_pair_group(port_pairs=[pp['id']])
        fc = self._try_create_flowclassifier()
        created = self._try_create_port_chain(
            port_pair_groups=[pg['id']],
            flow_classifiers=[fc['id']])
        pc = self.portchain_client.show_port_chain(
            created['id'])
        for key, value in pc['port_chain'].items():
            self.assertEqual(created[key], value)

    @decorators.idempotent_id('4ad641d3-823f-4b25-9438-68970593253d')
    def test_update_port_chain(self):
        # Create port chain
        pp = self._try_create_port_pair()
        pg = self._try_create_port_pair_group(port_pairs=[pp['id']])
        fc = self._try_create_flowclassifier()
        name1 = data_utils.rand_name('test')
        pc = self._try_create_port_chain(
            name=name1, port_pair_groups=[pg['id']],
            flow_classifiers=[fc['id']]
        )
        pc_id = pc['id']

        # Update port chain
        name2 = data_utils.rand_name('test')
        body = self.portchain_client.update_port_chain(
            pc_id, name=name2)
        self.assertEqual(body['port_chain']['name'], name2)
