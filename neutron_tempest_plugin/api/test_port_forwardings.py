# Copyright 2019 Red Hat, Inc.
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

from tempest.common import utils
from tempest.lib.common.utils import data_utils
from tempest.lib import decorators
from tempest.lib import exceptions

from neutron_tempest_plugin.api import base
from neutron_tempest_plugin import config

CONF = config.CONF


class PortForwardingTestJSON(base.BaseNetworkTest):

    required_extensions = ['router', 'floating-ip-port-forwarding']

    @classmethod
    def resource_setup(cls):
        super(PortForwardingTestJSON, cls).resource_setup()
        cls.ext_net_id = CONF.network.public_network_id

        # Create network, subnet, router and add interface
        cls.network = cls.create_network()
        cls.subnet = cls.create_subnet(cls.network)
        cls.router = cls.create_router(data_utils.rand_name('router'),
                                       external_network_id=cls.ext_net_id)
        cls.create_router_interface(cls.router['id'], cls.subnet['id'])

    @decorators.idempotent_id('829a446e-46bc-41ce-b442-6e428aeb3c19')
    def test_port_forwarding_life_cycle(self):
        fip = self.create_floatingip()
        port = self.create_port(self.network)
        # Create port forwarding for one TCP port
        created_pf = self.create_port_forwarding(
            fip['id'],
            internal_port_id=port['id'],
            internal_ip_address=port['fixed_ips'][0]['ip_address'],
            internal_port=1111, external_port=2222, protocol="tcp")
        self.assertEqual(1111, created_pf['internal_port'])
        self.assertEqual(2222, created_pf['external_port'])
        self.assertEqual('tcp', created_pf['protocol'])
        self.assertEqual(port['fixed_ips'][0]['ip_address'],
                         created_pf['internal_ip_address'])

        # Show created port forwarding
        body = self.client.get_port_forwarding(
            fip['id'], created_pf['id'])
        pf = body['port_forwarding']
        self.assertEqual(1111, pf['internal_port'])
        self.assertEqual(2222, pf['external_port'])
        self.assertEqual('tcp', pf['protocol'])
        self.assertEqual(port['fixed_ips'][0]['ip_address'],
                         pf['internal_ip_address'])

        # Update port forwarding
        body = self.client.update_port_forwarding(
            fip['id'], pf['id'], internal_port=3333)
        pf = body['port_forwarding']
        self.assertEqual(3333, pf['internal_port'])
        self.assertEqual(2222, pf['external_port'])
        self.assertEqual('tcp', pf['protocol'])
        self.assertEqual(port['fixed_ips'][0]['ip_address'],
                         pf['internal_ip_address'])

        # Now lets try to remove Floating IP with existing port forwarding,
        # this should fails
        self.assertRaises(exceptions.Conflict,
                          self.delete_floatingip, fip)

        # Delete port forwarding
        self.client.delete_port_forwarding(fip['id'], pf['id'])
        self.assertRaises(exceptions.NotFound,
                          self.client.get_port_forwarding,
                          fip['id'], pf['id'])

        # Now Floating IP should be deleted properly
        self.delete_floatingip(fip)
        self.assertRaises(exceptions.NotFound,
                          self.client.get_floatingip, fip['id'])

    @decorators.idempotent_id('aa842070-39ef-4b09-9df9-e723934f96f8')
    @utils.requires_ext(extension="expose-port-forwarding-in-fip",
                        service="network")
    def test_port_forwarding_info_in_fip_details(self):
        fip = self.create_floatingip()
        port = self.create_port(self.network)

        # Ensure that FIP don't have information about any port forwarding yet
        fip = self.client.show_floatingip(fip['id'])['floatingip']
        self.assertEqual(0, len(fip['port_forwardings']))

        # Now create port forwarding and ensure that it is visible in FIP's
        # details
        pf = self.create_port_forwarding(
            fip['id'],
            internal_port_id=port['id'],
            internal_ip_address=port['fixed_ips'][0]['ip_address'],
            internal_port=1111, external_port=2222, protocol="tcp")
        fip = self.client.show_floatingip(fip['id'])['floatingip']
        self.assertEqual(1, len(fip['port_forwardings']))
        self.assertEqual(1111, fip['port_forwardings'][0]['internal_port'])
        self.assertEqual(2222, fip['port_forwardings'][0]['external_port'])
        self.assertEqual('tcp', fip['port_forwardings'][0]['protocol'])
        self.assertEqual(port['fixed_ips'][0]['ip_address'],
                         fip['port_forwardings'][0]['internal_ip_address'])

        # Delete port forwarding and ensure that it's not in FIP's details
        # anymore
        self.client.delete_port_forwarding(fip['id'], pf['id'])
        fip = self.client.show_floatingip(fip['id'])['floatingip']
        self.assertEqual(0, len(fip['port_forwardings']))

    @decorators.idempotent_id('8202cded-7e82-4420-9585-c091105404f6')
    def test_associate_2_port_forwardings_to_floating_ip(self):
        fip = self.create_floatingip()
        forwardings_data = [(1111, 2222), (3333, 4444)]
        created_pfs = []
        for data in forwardings_data:
            internal_port = data[0]
            external_port = data[1]
            port = self.create_port(self.network)
            created_pf = self.create_port_forwarding(
                fip['id'],
                internal_port_id=port['id'],
                internal_ip_address=port['fixed_ips'][0]['ip_address'],
                internal_port=internal_port, external_port=external_port,
                protocol="tcp")
            self.assertEqual(internal_port, created_pf['internal_port'])
            self.assertEqual(external_port, created_pf['external_port'])
            self.assertEqual('tcp', created_pf['protocol'])
            self.assertEqual(port['fixed_ips'][0]['ip_address'],
                             created_pf['internal_ip_address'])
            created_pfs.append(created_pf)

        # Check that all PFs are visible in Floating IP details
        fip = self.client.show_floatingip(fip['id'])['floatingip']
        self.assertEqual(len(forwardings_data), len(fip['port_forwardings']))
        for pf in created_pfs:
            expected_pf = {
                'external_port': pf['external_port'],
                'internal_port': pf['internal_port'],
                'protocol': pf['protocol'],
                'internal_ip_address': pf['internal_ip_address']}
            self.assertIn(expected_pf, fip['port_forwardings'])

        # Test list of port forwardings
        port_forwardings = self.client.list_port_forwardings(
            fip['id'])['port_forwardings']
        self.assertEqual(len(forwardings_data), len(port_forwardings))
        for pf in created_pfs:
            expected_pf = pf.copy()
            expected_pf.pop('client')
            expected_pf.pop('floatingip_id')
            self.assertIn(expected_pf, port_forwardings)

    @decorators.idempotent_id('6a34e811-66d1-4f63-aa4d-9013f15deb62')
    def test_associate_port_forwarding_to_used_floating_ip(self):
        port_for_fip = self.create_port(self.network)
        fip = self.create_floatingip(port=port_for_fip)
        port = self.create_port(self.network)
        self.assertRaises(
            exceptions.Conflict,
            self.create_port_forwarding,
            fip['id'],
            internal_port_id=port['id'],
            internal_ip_address=port['fixed_ips'][0]['ip_address'],
            internal_port=1111, external_port=2222,
            protocol="tcp")

    @decorators.idempotent_id('4ca72d40-93e4-485f-a876-76caf33c1fe6')
    def test_associate_port_forwarding_to_port_with_fip(self):
        port = self.create_port(self.network)
        self.create_floatingip(port=port)
        fip_for_pf = self.create_floatingip()
        self.assertRaises(
            exceptions.Conflict,
            self.create_port_forwarding,
            fip_for_pf['id'],
            internal_port_id=port['id'],
            internal_ip_address=port['fixed_ips'][0]['ip_address'],
            internal_port=1111, external_port=2222,
            protocol="tcp")
