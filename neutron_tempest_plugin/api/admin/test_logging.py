# Copyright 2017 Fujitsu Limited.
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
import testscenarios

from neutron_tempest_plugin.api import base

load_tests = testscenarios.load_tests_apply_scenarios


class LoggingTestJSON(base.BaseAdminNetworkTest):

    required_extensions = ['logging', 'standard-attr-description']

    @decorators.idempotent_id('8d2e1ba5-455b-4519-a88e-e587002faba6')
    def test_log_lifecycle(self):
        name = data_utils.rand_name('test-log')
        description = data_utils.rand_name('test-log-desc')
        log = self.create_log(name=name, description=description,
                              resource_type='security_group', enabled=True)

        # Test 'show log'
        retrieved_log = self.admin_client.show_log(log['id'])['log']
        self.assertEqual(name, retrieved_log['name'])
        self.assertEqual(description, retrieved_log['description'])
        self.assertEqual('security_group', retrieved_log['resource_type'])
        self.assertTrue(retrieved_log['enabled'])

        # Test 'list logs'
        logs = self.admin_client.list_logs()['logs']
        logs_ids = [log_object['id'] for log_object in logs]
        self.assertIn(log['id'], logs_ids)

        # Test 'update log'
        update_description = data_utils.rand_name('test-log')
        self.admin_client.update_log(log['id'],
                                     description=update_description,
                                     enabled=False)
        retrieved_log = self.admin_client.show_log(log['id'])['log']
        self.assertEqual(update_description, retrieved_log['description'])
        self.assertFalse(retrieved_log['enabled'])

        # Test 'delete log'
        self.admin_client.delete_log(log['id'])
        self.assertRaises(exceptions.NotFound,
                          self.admin_client.show_log, log['id'])

    @decorators.idempotent_id('1af6cdab-0eb0-4e13-8027-d89cf1c7a87a')
    def test_list_supported_logging_types(self):
        # List supported logging types
        # Since returned logging types depends on loaded backend drivers
        # this test is checking only if returned keys are same as expected keys
        expected_log_keys = ['type']

        log_types = self.admin_client.list_loggable_resources()
        actual_list_log_types = log_types['loggable_resources']

        # Verify that only required fields present in logging types
        for log_type in actual_list_log_types:
            self.assertEqual(tuple(expected_log_keys), tuple(log_type.keys()))
