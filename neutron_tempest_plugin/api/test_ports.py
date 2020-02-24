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

import copy

from tempest.common import utils
from tempest.lib import decorators

from neutron_tempest_plugin.api import base


class PortsTestJSON(base.BaseNetworkTest):

    @classmethod
    def resource_setup(cls):
        super(PortsTestJSON, cls).resource_setup()
        cls.network = cls.create_network()

    def _confirm_dns_assignment(self, port):
        # NOTE(manjeets) port created with single subnet
        # would have only one dns_assignment
        dns_assignment = port['dns_assignment'][0]
        ip = port['fixed_ips'][0]['ip_address']
        if port['dns_name']:
            hostname = port['dns_name']
        else:
            hostname = 'host-%s' % ip.replace('.', '-')
        self.assertEqual(hostname, dns_assignment['hostname'])

        # To avoid hard coding the expected dns_domain value
        # in neutron.conf we just check that the fqdn starts
        # with correct hostname
        self.assertTrue(dns_assignment['fqdn'].startswith(hostname))
        self.assertEqual(ip, dns_assignment['ip_address'])

    @decorators.idempotent_id('c72c1c0c-2193-4aca-bbb4-b1442640bbbb')
    @utils.requires_ext(extension="standard-attr-description",
                       service="network")
    def test_create_update_port_description(self):
        body = self.create_port(self.network,
                                description='d1')
        self.assertEqual('d1', body['description'])
        body = self.client.list_ports(id=body['id'])['ports'][0]
        self.assertEqual('d1', body['description'])
        body = self.client.update_port(body['id'],
                                       description='d2')
        self.assertEqual('d2', body['port']['description'])
        body = self.client.list_ports(id=body['port']['id'])['ports'][0]
        self.assertEqual('d2', body['description'])

    @decorators.idempotent_id('539fbefe-fb36-48aa-9a53-8c5fbd44e492')
    @utils.requires_ext(extension="dns-integration",
                       service="network")
    def test_create_update_port_with_dns_name(self):
        # NOTE(manjeets) dns_domain is set to openstackgate.local
        # so dns_name for port can be set
        self.create_subnet(self.network)
        body = self.create_port(self.network, dns_name='d1')
        self.assertEqual('d1', body['dns_name'])
        self._confirm_dns_assignment(body)
        body = self.client.list_ports(id=body['id'])['ports'][0]
        self._confirm_dns_assignment(body)
        self.assertEqual('d1', body['dns_name'])
        body = self.client.update_port(body['id'],
                                       dns_name='d2')
        self.assertEqual('d2', body['port']['dns_name'])
        self._confirm_dns_assignment(body['port'])
        body = self.client.show_port(body['port']['id'])['port']
        self.assertEqual('d2', body['dns_name'])
        self._confirm_dns_assignment(body)

    @decorators.idempotent_id('435e89df-a8bb-4b41-801a-9f20d362d777')
    @utils.requires_ext(extension="dns-integration",
                       service="network")
    def test_create_update_port_with_no_dns_name(self):
        self.create_subnet(self.network)
        body = self.create_port(self.network)
        self.assertFalse(body['dns_name'])
        self._confirm_dns_assignment(body)
        port_body = self.client.show_port(body['id'])
        self.assertFalse(port_body['port']['dns_name'])
        self._confirm_dns_assignment(port_body['port'])

    @decorators.idempotent_id('dfe8cc79-18d9-4ae8-acef-3ec6bb719aa7')
    @utils.requires_ext(extension="dns-domain-ports",
                       service="network")
    def test_create_update_port_with_dns_domain(self):
        self.create_subnet(self.network)
        body = self.create_port(self.network, dns_name='d1',
                                dns_domain='test.org.')
        self.assertEqual('d1', body['dns_name'])
        self.assertEqual('test.org.', body['dns_domain'])
        self._confirm_dns_assignment(body)
        body = self.client.list_ports(id=body['id'])['ports'][0]
        self._confirm_dns_assignment(body)
        self.assertEqual('d1', body['dns_name'])
        self.assertEqual('test.org.', body['dns_domain'])
        body = self.client.update_port(body['id'],
                                       dns_name='d2', dns_domain='d.org.')
        self.assertEqual('d2', body['port']['dns_name'])
        self.assertEqual('d.org.', body['port']['dns_domain'])
        self._confirm_dns_assignment(body['port'])
        body = self.client.show_port(body['port']['id'])['port']
        self.assertEqual('d2', body['dns_name'])
        self.assertEqual('d.org.', body['dns_domain'])
        self._confirm_dns_assignment(body)

    @decorators.idempotent_id('c72c1c0c-2193-4aca-bbb4-b1442640c123')
    def test_change_dhcp_flag_then_create_port(self):
        s = self.create_subnet(self.network, enable_dhcp=False)
        self.create_port(self.network)
        self.client.update_subnet(s['id'], enable_dhcp=True)
        self.create_port(self.network)

    @decorators.idempotent_id('1d6d8683-8691-43c6-a7ba-c69723258726')
    def test_add_ips_to_port(self):
        s = self.create_subnet(self.network)
        port = self.create_port(self.network)
        # request another IP on the same subnet
        port['fixed_ips'].append({'subnet_id': s['id']})
        updated = self.client.update_port(port['id'],
                                          fixed_ips=port['fixed_ips'])
        subnets = [ip['subnet_id'] for ip in updated['port']['fixed_ips']]
        expected = [s['id'], s['id']]
        self.assertEqual(expected, subnets)

    @decorators.idempotent_id('9700828d-86eb-4f21-9fa3-da487a2d77f2')
    @utils.requires_ext(extension="uplink-status-propagation",
                        service="network")
    def test_create_port_with_propagate_uplink_status(self):
        body = self.create_port(self.network, propagate_uplink_status=True)
        self.assertTrue(body['propagate_uplink_status'])
        body = self.client.list_ports(id=body['id'])['ports'][0]
        self.assertTrue(body['propagate_uplink_status'])
        body = self.client.show_port(body['id'])['port']
        self.assertTrue(body['propagate_uplink_status'])

    @decorators.idempotent_id('c396a880-0c7b-409d-a80b-800a3d09bdc4')
    @utils.requires_ext(extension="uplink-status-propagation",
                        service="network")
    def test_create_port_without_propagate_uplink_status(self):
        body = self.create_port(self.network)
        self.assertFalse(body['propagate_uplink_status'])
        body = self.client.list_ports(id=body['id'])['ports'][0]
        self.assertFalse(body['propagate_uplink_status'])
        body = self.client.show_port(body['id'])['port']
        self.assertFalse(body['propagate_uplink_status'])


class PortsSearchCriteriaTest(base.BaseSearchCriteriaTest):

    resource = 'port'

    @classmethod
    def resource_setup(cls):
        super(PortsSearchCriteriaTest, cls).resource_setup()
        net = cls.create_network(network_name='port-search-test-net')
        for name in cls.resource_names:
            cls.create_port(net, name=name)

    @decorators.idempotent_id('9ab73df4-960a-4ae3-87d3-60992b8d3e2d')
    def test_list_sorts_asc(self):
        self._test_list_sorts_asc()

    @decorators.idempotent_id('b426671d-7270-430f-82ff-8f33eec93010')
    def test_list_sorts_desc(self):
        self._test_list_sorts_desc()

    @decorators.idempotent_id('a202fdc8-6616-45df-b6a0-463932de6f94')
    def test_list_pagination(self):
        self._test_list_pagination()

    @decorators.idempotent_id('f4723b8e-8186-4b9a-bf9e-57519967e048')
    def test_list_pagination_with_marker(self):
        self._test_list_pagination_with_marker()

    @decorators.idempotent_id('fcd02a7a-f07e-4d5e-b0ca-b58e48927a9b')
    def test_list_pagination_with_href_links(self):
        self._test_list_pagination_with_href_links()

    @decorators.idempotent_id('3afe7024-77ab-4cfe-824b-0b2bf4217727')
    def test_list_no_pagination_limit_0(self):
        self._test_list_no_pagination_limit_0()

    @decorators.idempotent_id('b8857391-dc44-40cc-89b7-2800402e03ce')
    def test_list_pagination_page_reverse_asc(self):
        self._test_list_pagination_page_reverse_asc()

    @decorators.idempotent_id('4e51e9c9-ceae-4ec0-afd4-147569247699')
    def test_list_pagination_page_reverse_desc(self):
        self._test_list_pagination_page_reverse_desc()

    @decorators.idempotent_id('74293e59-d794-4a93-be09-38667199ef68')
    def test_list_pagination_page_reverse_with_href_links(self):
        self._test_list_pagination_page_reverse_with_href_links()


class PortsTaggingOnCreationTestJSON(base.BaseNetworkTest):

    _tags = [
        ['tag-1', 'tag-2', 'tag-3'],
        ['tag-1', 'tag-2'],
        ['tag-1', 'tag-3'],
        []
    ]

    @classmethod
    def resource_setup(cls):
        super(PortsTaggingOnCreationTestJSON, cls).resource_setup()
        cls.network = cls.create_network()

    def _create_ports_in_bulk(self, ports):
        body = self.client.create_bulk_port(ports)
        for port in body['ports']:
            self.ports.append(port)
        return body

    def _create_ports_list(self):
        num_ports = len(self._tags)
        net_id = self.network['id']
        port = {'port': {'network_id': net_id,
                         'admin_state_up': True}}
        return [copy.deepcopy(port) for x in range(num_ports)]

    @decorators.idempotent_id('5cf26014-fdd3-4a6d-b94d-a05f0c55da89')
    @utils.requires_ext(extension="tag-ports-during-bulk-creation",
                        service="network")
    def test_tagging_ports_during_bulk_creation(self):
        ports = self._create_ports_list()
        ports_tags_map = {}
        for port, tags in zip(ports, self._tags):
            port['port']['tags'] = tags
            port['port']['name'] = '-'.join(tags)
            ports_tags_map[port['port']['name']] = tags
        body = self._create_ports_in_bulk(ports)
        for port in body['ports']:
            self.assertEqual(ports_tags_map[port['name']], port['tags'])

    @decorators.idempotent_id('33eda785-a08a-44a0-1bbb-fb50a2f1cd78')
    @utils.requires_ext(extension="tag-ports-during-bulk-creation",
                        service="network")
    def test_tagging_ports_during_bulk_creation_no_tags(self):
        ports = self._create_ports_list()
        body = self._create_ports_in_bulk(ports)
        for port in body['ports']:
            self.assertFalse(port['tags'])

    @decorators.idempotent_id('6baa43bf-88fb-8bca-6051-97ea1a5e8f4f')
    @utils.requires_ext(extension="tag-ports-during-bulk-creation",
                        service="network")
    def test_tagging_ports_during_creation(self):
        port = {'name': 'port', 'tags': self._tags[0]}
        body = self.create_port(self.network, **port)
        self.assertEqual(self._tags[0], body['tags'])
