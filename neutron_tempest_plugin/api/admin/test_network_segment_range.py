# Copyright (c) 2019, Intel Corporation.
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

TEST_SEGMENT_RANGE_MINIMUM_ID = 1100
TEST_SEGMENT_RANGE_MAXIMUM_ID = 1105


class NetworkSegmentRangeTestBase(base.BaseAdminNetworkTest):

    required_extensions = ['network-segment-range']

    @classmethod
    def skip_checks(cls):
        super(NetworkSegmentRangeTestBase, cls).skip_checks()

    @classmethod
    def resource_setup(cls):
        super(NetworkSegmentRangeTestBase, cls).resource_setup()
        network_type = "vxlan"
        physical_network = ""
        minimum = TEST_SEGMENT_RANGE_MINIMUM_ID
        maximum = TEST_SEGMENT_RANGE_MAXIMUM_ID
        cls._network_segment_range_data = {
            'network_type': network_type, 'physical_network': physical_network,
            'minimum': minimum, 'maximum': maximum}

    def _create_network_segment_range(self, name=None,
                                      shared=False, project_id=None,
                                      network_type=None, physical_network=None,
                                      minimum=None, maximum=None):
        name = name or data_utils.rand_name('test_network_segment_range')

        if shared:
            project_id = ""
        else:
            test_project = data_utils.rand_name('test_project')
            test_description = data_utils.rand_name('desc')
            project_id = self.create_project(
                name=test_project,
                description=test_description)['id']

        network_type = (network_type or
                        self._network_segment_range_data['network_type'])
        physical_network = (
            physical_network or
            self._network_segment_range_data['physical_network'])
        minimum = minimum or self._network_segment_range_data['minimum']
        maximum = maximum or self._network_segment_range_data['maximum']

        network_segment_range = self.create_network_segment_range(
            name=name, shared=shared, project_id=project_id,
            network_type=network_type, physical_network=physical_network,
            minimum=minimum, maximum=maximum)
        # _delete_network_segment_range will ensure that the network segment
        # range is really removed
        self.addCleanup(self._delete_network_segment_range,
                        network_segment_range['id'])

        return network_segment_range

    def _delete_network_segment_range(self, network_segment_range_id):
        # Deletes a network segment range and verifies if it is deleted or not
        self.admin_client.delete_network_segment_range(
            network_segment_range_id)
        # Asserting that the network segment range is not found in list after
        # deletion
        labels = self.admin_client.list_network_segment_ranges(
            id=network_segment_range_id)
        list_range_ids = [r['id'] for r in labels['network_segment_ranges']]
        self.assertNotIn(network_segment_range_id, list_range_ids)


class NetworkSegmentRangeTestJson(NetworkSegmentRangeTestBase):
    """Test Network Segment Range

    Tests the following operations in the Neutron API using the REST client for
    Neutron:

        List, Show, Create, Update, Delete Network Segment Range
    """

    @decorators.idempotent_id('44a1ece1-d85d-4253-92f8-4efc318a6d8e')
    def test_create_update_delete_network_segment_range(self):
        # Creates a network segment range
        network_segment_range = self._create_network_segment_range()
        self.assertIsNotNone(network_segment_range['id'])
        self.assertFalse(network_segment_range['default'])
        self.assertFalse(network_segment_range['shared'])
        self.assertEqual('vxlan', network_segment_range['network_type'])
        self.assertEqual(TEST_SEGMENT_RANGE_MINIMUM_ID,
                         network_segment_range['minimum'])
        self.assertEqual(TEST_SEGMENT_RANGE_MAXIMUM_ID,
                         network_segment_range['maximum'])
        # Updates a network segment range
        updated_minimum = TEST_SEGMENT_RANGE_MINIMUM_ID - 50
        updated_maximum = TEST_SEGMENT_RANGE_MAXIMUM_ID + 50
        body = self.admin_client.update_network_segment_range(
            network_segment_range['id'], name='new-range-name',
            minimum=updated_minimum, maximum=updated_maximum)
        updated_network_segment_range = body['network_segment_range']
        self.assertEqual('new-range-name',
                         updated_network_segment_range['name'])
        self.assertEqual(updated_minimum,
                         updated_network_segment_range['minimum'])
        self.assertEqual(updated_maximum,
                         updated_network_segment_range['maximum'])

    @decorators.idempotent_id('5e118fef-a139-4886-8250-07e73d2cbe7a')
    def test_update_network_segment_range_failed_with_existing_range_impacted(
            self):
        # Creates a network segment range
        network_segment_range = self._create_network_segment_range()
        project_id = network_segment_range['project_id']
        # Creates a network
        name = data_utils.rand_name('test_network_for_' + project_id)
        network = self.create_network(
            name, client=self.admin_client, project_id=project_id)
        # Updates a network segment range
        updated_maximum = TEST_SEGMENT_RANGE_MAXIMUM_ID + 50
        self.assertRaises(lib_exc.Conflict,
                          self.admin_client.update_network_segment_range,
                          network_segment_range['id'],
                          name='new-range-name',
                          minimum=network['provider:segmentation_id'],
                          maximum=updated_maximum)
        # network needs to be deleted otherwise the range deletion will fail
        # because the segment is in use (assigned to the network created)
        self.admin_client.delete_network(network['id'])

    @decorators.idempotent_id('0019de49-c0ea-4554-af57-18ad4ae30195')
    def test_create_network_with_tenant_specific_network_segment_range(self):
        # Creates a network segment range
        network_segment_range = self._create_network_segment_range()
        project_id = network_segment_range['project_id']
        # Creates a set of networks
        network_ids = []
        for _ in range(TEST_SEGMENT_RANGE_MAXIMUM_ID -
                       TEST_SEGMENT_RANGE_MINIMUM_ID + 1):
            name = data_utils.rand_name('test_network_for_' + project_id)
            network = self.create_network(
                name, client=self.admin_client, project_id=project_id)

            observed_network = self.admin_client.show_network(
                network['id'])['network']
            network_ids.append(network['id'])
            self.assertTrue(
                TEST_SEGMENT_RANGE_MINIMUM_ID <=
                observed_network['provider:segmentation_id'] <=
                TEST_SEGMENT_RANGE_MAXIMUM_ID)
        # networks need to be deleted otherwise the range deletion will fail
        # because the segments are in use (assigned to the networks created)
        for network_id in network_ids:
            self.admin_client.delete_network(network_id)

    @decorators.idempotent_id('2129a26b-a97b-43d6-b0b2-04253c6046f8')
    def test_create_network_with_default_network_segment_range(self):
        # Creates a set of networks without creating a network segment range,
        # i.e. using default network segment ranges only.
        network_ids = []
        for _ in range(5):
            name = data_utils.rand_name('test_network')
            network = self.create_network(name)

            self.assertEqual(name, network['name'])

            observed_network = self.admin_client.show_network(
                network['id'])['network']
            network_ids.append(network['id'])
            self.assertEqual(name, observed_network['name'])
            # default vxlan network segment range: 1-2000
            self.assertTrue(
                1 <= observed_network['provider:segmentation_id'] <= 2000)
        # networks need to be deleted otherwise the range deletion will fail
        # because the segments are in use (assigned to the networks created)
        for network_id in network_ids:
            self.admin_client.delete_network(network_id)

    def _compare_segment_ranges(self, reference, observed):
        self.assertEqual(reference['id'], observed['id'])
        self.assertEqual(reference['name'], observed['name'])
        self.assertFalse(observed['default'])
        self.assertFalse(observed['shared'])
        self.assertEqual(reference['project_id'], observed['project_id'])
        self.assertEqual(reference['network_type'], observed['network_type'])
        self.assertEqual(reference['minimum'], observed['minimum'])
        self.assertEqual(reference['maximum'], observed['maximum'])

    @decorators.idempotent_id('54fa26c9-37b5-4df4-a934-a705f29920fc')
    def test_show_network_segment_range(self):
        # Creates a network segment range
        network_segment_range = self._create_network_segment_range()
        # Verifies the details of a network segment range
        body = self.admin_client.show_network_segment_range(
            network_segment_range['id'])
        observed_range = body['network_segment_range']
        self._compare_segment_ranges(network_segment_range, observed_range)

    @decorators.idempotent_id('17139cc1-4826-4bf9-9c39-85b74894d938')
    def test_list_network_segment_ranges(self):
        # Creates a network segment range
        network_segment_range = self._create_network_segment_range()
        # Verify network segment range lists
        body = self.admin_client.list_network_segment_ranges(id=33)
        list_range_ids = [r['id'] for r in body['network_segment_ranges']]
        self.assertNotIn(network_segment_range['id'], list_range_ids)

        body = self.admin_client.list_network_segment_ranges(
            id=network_segment_range['id'])
        self.assertEqual(1, len(body['network_segment_ranges']))
        observed_range = body['network_segment_ranges'][0]
        self._compare_segment_ranges(network_segment_range, observed_range)

    @decorators.idempotent_id('42959544-9956-4b0c-aec6-d56533323924')
    def test_delete_network_segment_range_failed_with_segment_referenced(
            self):
        # Creates a network segment range
        network_segment_range = self._create_network_segment_range()
        project_id = network_segment_range['project_id']
        # Creates a network
        name = data_utils.rand_name('test_network_for_' + project_id)
        network = self.create_network(
            name, client=self.admin_client, project_id=project_id)
        # Deletes a network segment range
        self.assertRaises(lib_exc.Conflict,
                          self.admin_client.delete_network_segment_range,
                          network_segment_range['id'])
        # network needs to be deleted otherwise the range deletion will fail
        # because the segment is in use (assigned to the network created)
        self.admin_client.delete_network(network['id'])
