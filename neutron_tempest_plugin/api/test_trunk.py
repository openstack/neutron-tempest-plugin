# Copyright 2016 Hewlett Packard Enterprise Development Company LP
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
from tempest.lib import exceptions as lib_exc

from neutron_tempest_plugin.api import base
from neutron_tempest_plugin import config


CONF = config.CONF


class TrunkTestJSONBase(base.BaseAdminNetworkTest):

    required_extensions = ['trunk']

    def setUp(self):
        base.BaseAdminNetworkTest.setUp(self)
        # This avoids problems due to user quotas
        self.resource_setup()
        self.addCleanup(self.resource_cleanup)

    @classmethod
    def is_type_driver_enabled(cls, type_driver):
        return (type_driver in
                CONF.neutron_plugin_options.available_type_drivers)

    @classmethod
    def _create_trunk_with_network_and_parent(cls, subports=None,
                                              parent_network_type=None,
                                              **kwargs):
        client = None
        network_kwargs = {}
        if parent_network_type:
            client = cls.admin_client
            network_kwargs = {"provider:network_type": parent_network_type,
                              "tenant_id": cls.client.tenant_id}
        network = cls.create_network(client=client, **network_kwargs)
        parent_port = cls.create_port(network)
        return cls.create_trunk(parent_port, subports, **kwargs)

    @classmethod
    def _show_trunk(cls, trunk):
        client = trunk.get('client') or cls.client
        return client.show_trunk(trunk['id'])['trunk']

    @classmethod
    def _update_trunk(cls, trunk, **kwargs):
        client = trunk.get('client') or cls.client
        return client.update_trunk(trunk['id'], **kwargs)['trunk']

    @classmethod
    def _list_trunks(cls):
        return cls.client.list_trunks()['trunks']


class TrunkTestJSON(TrunkTestJSONBase):

    def _test_create_trunk(self, subports):
        trunk = self._create_trunk_with_network_and_parent(subports)
        observed_trunk = self._show_trunk(trunk)
        self.assertEqual(trunk, dict(observed_trunk, client=trunk['client']))

    @decorators.idempotent_id('e1a6355c-4768-41f3-9bf8-0f1d192bd501')
    def test_create_trunk_empty_subports_list(self):
        self._test_create_trunk([])

    @decorators.idempotent_id('382dfa39-ca03-4bd3-9a1c-91e36d2e3796')
    def test_create_trunk_subports_not_specified(self):
        self._test_create_trunk(None)

    @decorators.idempotent_id('7de46c22-e2b6-4959-ac5a-0e624632ab32')
    def test_create_show_delete_trunk(self):
        trunk = self._create_trunk_with_network_and_parent()
        observed_trunk = self._show_trunk(trunk)
        self.assertEqual(trunk, dict(observed_trunk, client=trunk['client']))
        self.delete_trunk(trunk)
        self.assertRaises(lib_exc.NotFound, self._show_trunk, trunk)

    @decorators.idempotent_id('8d83a6ca-662d-45b8-8062-d513077296aa')
    @utils.requires_ext(extension="project-id", service="network")
    def test_show_trunk_has_project_id(self):
        trunk = self._create_trunk_with_network_and_parent()
        observed_trunk = self._show_trunk(trunk)
        for key in ['project_id', 'tenant_id']:
            self.assertIn(key, observed_trunk)
            self.assertEqual(self.client.tenant_id, observed_trunk[key])

    @decorators.idempotent_id('4ce46c22-a2b6-4659-bc5a-0ef2463cab32')
    def test_create_update_trunk(self):
        trunk = self._create_trunk_with_network_and_parent()
        observed_trunk = self._show_trunk(trunk)
        self.assertTrue(observed_trunk['admin_state_up'])
        self.assertEqual(trunk['revision_number'],
                         observed_trunk['revision_number'])
        self.assertEqual("", observed_trunk['name'])
        self.assertEqual("", observed_trunk['description'])
        updated_trunk = self._update_trunk(trunk, name='foo',
                                           admin_state_up=False)
        self.assertFalse(updated_trunk['admin_state_up'])
        self.assertEqual("foo", updated_trunk['name'])
        self.assertGreater(updated_trunk['revision_number'],
                           trunk['revision_number'])

    @decorators.idempotent_id('5ff46c22-a2b6-5559-bc5a-0ef2463cab32')
    def test_create_update_trunk_with_description(self):
        trunk = self._create_trunk_with_network_and_parent(
            description="foo description")
        self.assertEqual("foo description", trunk['description'])
        updated_trunk = self._update_trunk(trunk, description='')
        self.assertEqual('', updated_trunk['description'])

    @decorators.idempotent_id('73365f73-bed6-42cd-960b-ec04e0c99d85')
    def test_list_trunks(self):
        trunk1 = self._create_trunk_with_network_and_parent()
        trunk2 = self._create_trunk_with_network_and_parent()
        expected_trunks = {trunk1['id']: trunk1,
                           trunk2['id']: trunk2}
        observed_trunks = {trunk['id']: dict(trunk, client=self.client)
                           for trunk in self._list_trunks()
                           if trunk['id'] in expected_trunks}
        self.assertEqual(expected_trunks, observed_trunks)

    @decorators.idempotent_id('bb5fcead-09b5-484a-bbe6-46d1e06d6cc0')
    def test_add_subports(self):
        trunk = self._create_trunk_with_network_and_parent()
        network = self.create_network()
        port = self.create_port(network)
        subports = [{'port_id': port['id'],
                     'segmentation_type': 'vlan',
                     'segmentation_id': 2}]
        added_subports = self.client.add_subports(trunk['id'],
                                                  subports)['sub_ports']
        self.assertEqual(subports, added_subports)
        observed_trunk = self._show_trunk(trunk)
        self.assertEqual(subports, observed_trunk['sub_ports'])

    @decorators.idempotent_id('ee5fcead-1abf-483a-bce6-43d1e06d6aa0')
    def test_delete_trunk_with_subport_is_allowed(self):
        network = self.create_network()
        port = self.create_port(network)
        subports = [{'port_id': port['id'],
                     'segmentation_type': 'vlan',
                     'segmentation_id': 2}]
        trunk = self._create_trunk_with_network_and_parent(subports)
        self.client.delete_trunk(trunk['id'])

    @decorators.idempotent_id('96eea398-a03c-4c3e-a99e-864392c2ca53')
    def test_remove_subport(self):
        subport1 = {'port_id': self.create_port(self.create_network())['id'],
                    'segmentation_type': 'vlan',
                    'segmentation_id': 2}
        subport2 = {'port_id': self.create_port(self.create_network())['id'],
                    'segmentation_type': 'vlan',
                    'segmentation_id': 4}
        trunk = self._create_trunk_with_network_and_parent([subport1,
                                                            subport2])

        # Remove the subport and validate PUT response
        subports_after_remove = self.client.remove_subports(
            trunk['id'], [subport2])['sub_ports']
        self.assertEqual([subport1], subports_after_remove)

        # Validate the results of a subport list
        observed_trunk = self._show_trunk(trunk)
        self.assertEqual([subport1], observed_trunk['sub_ports'])

    @decorators.idempotent_id('bb5fcaad-09b5-484a-dde6-4cd1ea6d6ff0')
    def test_get_subports(self):
        network = self.create_network()
        port = self.create_port(network)
        subports = [{'port_id': port['id'],
                     'segmentation_type': 'vlan',
                     'segmentation_id': 2}]
        trunk = self._create_trunk_with_network_and_parent(subports)
        observed_subports = self.client.get_subports(trunk['id'])['sub_ports']
        self.assertEqual(subports, observed_subports)


class TrunkTestInheritJSONBase(TrunkTestJSONBase):

    required_extensions = ['provider', 'trunk']

    @classmethod
    def skip_checks(cls):
        super(TrunkTestInheritJSONBase, cls).skip_checks()
        if ("vlan" not in
                CONF.neutron_plugin_options.available_type_drivers):
            raise cls.skipException("VLAN type_driver is not enabled")
        if not CONF.neutron_plugin_options.provider_vlans:
            raise cls.skipException("No provider VLAN networks available")

    def create_provider_network(self):
        foo_net = CONF.neutron_plugin_options.provider_vlans[0]
        return self.create_network(name=data_utils.rand_name('vlan-net'),
                                   provider_network_type='vlan',
                                   provider_physical_network=foo_net)

    @decorators.idempotent_id('0f05d98e-41f5-4629-dada-9aee269c9602')
    def test_add_subport(self):
        parent_network = self.create_provider_network()
        parent_port = self.create_port(parent_network)
        subport_network1 = self.create_provider_network()
        segmentation_id1 = subport_network1['provider:segmentation_id']
        subport_network2 = self.create_provider_network()
        segmentation_id2 = subport_network2['provider:segmentation_id']
        subport1 = self.create_port(subport_network1)
        subport2 = self.create_port(subport_network2)
        subports = [{'port_id': subport1['id'],
                     'segmentation_type': 'inherit'},
                    {'port_id': subport2['id'],
                     'segmentation_type': 'inherit'}]

        trunk = self.create_trunk(parent_port, subports)

        expected_subports = [{'port_id': subport1['id'],
                              'segmentation_type': 'vlan',
                              'segmentation_id': segmentation_id1},
                             {'port_id': subport2['id'],
                              'segmentation_type': 'vlan',
                              'segmentation_id': segmentation_id2}]

        # Validate that subport got segmentation details from the network
        self.assertEqual(expected_subports, trunk['sub_ports'])


class TrunkTestMtusJSONBase(TrunkTestJSONBase):

    required_extensions = ['provider', 'trunk']

    @classmethod
    def skip_checks(cls):
        super(TrunkTestMtusJSONBase, cls).skip_checks()
        if not all(cls.is_type_driver_enabled(t) for t in ['gre', 'vxlan']):
            msg = "Either vxlan or gre type driver not enabled."
            raise cls.skipException(msg)

    def setUp(self):
        super(TrunkTestMtusJSONBase, self).setUp()

        # VXLAN autocomputed MTU (1450) is smaller than that of GRE (1458)
        self.smaller_mtu_net = self.create_network(
            name=data_utils.rand_name('vxlan-net'),
            provider_network_type='vxlan')

        self.larger_mtu_net = self.create_network(
            name=data_utils.rand_name('gre-net'),
            provider_network_type='gre')

        self.smaller_mtu_port = self.create_port(self.smaller_mtu_net)
        self.smaller_mtu_port_2 = self.create_port(self.smaller_mtu_net)
        self.larger_mtu_port = self.create_port(self.larger_mtu_net)


class TrunkTestMtusJSON(TrunkTestMtusJSONBase):

    @decorators.idempotent_id('0f05d98e-41f5-4629-ac29-9aee269c9602')
    def test_create_trunk_with_mtu_greater_than_subport(self):
        subports = [{'port_id': self.smaller_mtu_port['id'],
                     'segmentation_type': 'vlan',
                     'segmentation_id': 2}]

        self.create_trunk(self.larger_mtu_port, subports)

    @decorators.idempotent_id('2004c5c6-e557-4c43-8100-c820ad4953e8')
    def test_add_subport_with_mtu_greater_than_subport(self):
        subports = [{'port_id': self.smaller_mtu_port['id'],
                     'segmentation_type': 'vlan',
                     'segmentation_id': 2}]

        trunk = self.create_trunk(self.larger_mtu_port)
        self.client.add_subports(trunk['id'], subports)

    @decorators.idempotent_id('22725101-f4bc-4e00-84ec-4e02cd7e0500')
    def test_create_trunk_with_mtu_equal_to_subport(self):
        subports = [{'port_id': self.smaller_mtu_port['id'],
                     'segmentation_type': 'vlan',
                     'segmentation_id': 2}]

        self.create_trunk(self.smaller_mtu_port_2, subports)

    @decorators.idempotent_id('175b05ae-66ad-44c7-857a-a12d16f1058f')
    def test_add_subport_with_mtu_equal_to_trunk(self):
        subports = [{'port_id': self.smaller_mtu_port['id'],
                     'segmentation_type': 'vlan',
                     'segmentation_id': 2}]

        trunk = self.create_trunk(self.smaller_mtu_port_2)
        self.client.add_subports(trunk['id'], subports)


class TrunksSearchCriteriaTest(base.BaseSearchCriteriaTest):

    required_extensions = ['trunk']
    resource = 'trunk'

    @classmethod
    def resource_setup(cls):
        super(TrunksSearchCriteriaTest, cls).resource_setup()
        net = cls.create_network(network_name='trunk-search-test-net')
        for name in cls.resource_names:
            parent_port = cls.create_port(net)
            cls.create_trunk(parent_port, name=name)

    @decorators.idempotent_id('fab73df4-960a-4ae3-87d3-60992b8d3e2d')
    def test_list_sorts_asc(self):
        self._test_list_sorts_asc()

    @decorators.idempotent_id('a426671d-7270-430f-82ff-8f33eec93010')
    def test_list_sorts_desc(self):
        self._test_list_sorts_desc()

    @decorators.idempotent_id('b202fdc8-6616-45df-b6a0-463932de6f94')
    def test_list_pagination(self):
        self._test_list_pagination()

    @decorators.idempotent_id('c4723b8e-8186-4b9a-bf9e-57519967e048')
    def test_list_pagination_with_marker(self):
        self._test_list_pagination_with_marker()

    @decorators.idempotent_id('dcd02a7a-f07e-4d5e-b0ca-b58e48927a9b')
    def test_list_pagination_with_href_links(self):
        self._test_list_pagination_with_href_links()

    @decorators.idempotent_id('eafe7024-77ab-4cfe-824b-0b2bf4217727')
    def test_list_no_pagination_limit_0(self):
        self._test_list_no_pagination_limit_0()

    @decorators.idempotent_id('f8857391-dc44-40cc-89b7-2800402e03ce')
    def test_list_pagination_page_reverse_asc(self):
        self._test_list_pagination_page_reverse_asc()

    @decorators.idempotent_id('ae51e9c9-ceae-4ec0-afd4-147569247699')
    def test_list_pagination_page_reverse_desc(self):
        self._test_list_pagination_page_reverse_desc()

    @decorators.idempotent_id('b4293e59-d794-4a93-be09-38667199ef68')
    def test_list_pagination_page_reverse_with_href_links(self):
        self._test_list_pagination_page_reverse_with_href_links()
