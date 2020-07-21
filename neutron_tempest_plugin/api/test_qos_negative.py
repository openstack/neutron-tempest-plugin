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

from neutron_lib.api.definitions import qos as qos_apidef
from neutron_lib.db import constants as db_const
from tempest.lib.common.utils import data_utils
from tempest.lib import decorators
from tempest.lib import exceptions as lib_exc

from neutron_tempest_plugin.api import base

LONG_NAME_NG = 'z' * (db_const.NAME_FIELD_SIZE + 1)
LONG_DESCRIPTION_NG = 'z' * (db_const.LONG_DESCRIPTION_FIELD_SIZE + 1)
LONG_TENANT_ID_NG = 'z' * (db_const.PROJECT_ID_FIELD_SIZE + 1)


class QosNegativeTestJSON(base.BaseAdminNetworkTest):

    required_extensions = [qos_apidef.ALIAS]

    @decorators.attr(type='negative')
    @decorators.idempotent_id('b9dce555-d3b3-11e5-950a-54ee757c77da')
    def test_add_policy_with_too_long_name(self):
        self.assertRaises(lib_exc.BadRequest,
                          self.client.create_qos_policy,
                          LONG_NAME_NG, 'test policy desc1', False)

    @decorators.attr(type='negative')
    @decorators.idempotent_id('b9dce444-d3b3-11e5-950a-54ee747c99db')
    def test_add_policy_with_too_long_description(self):
        self.assertRaises(lib_exc.BadRequest,
                          self.client.create_qos_policy,
                          'test-policy', LONG_DESCRIPTION_NG, False)

    @decorators.attr(type='negative')
    @decorators.idempotent_id('b9dce444-d3b3-11e5-950a-54ee757c77dc')
    def test_add_policy_with_too_long_tenant_id(self):
        self.assertRaises(lib_exc.BadRequest,
                          self.client.create_qos_policy,
                          'test-policy', 'test policy desc1',
                          False, LONG_TENANT_ID_NG)

    @decorators.attr(type='negative')
    @decorators.idempotent_id('0e85f3e4-7a93-4187-b847-8f4e835aae1b')
    def test_update_policy_with_too_long_name(self):
        policy = self.create_qos_policy(name='test', description='test policy',
                                        shared=False)
        self.assertRaises(lib_exc.BadRequest,
                          self.client.update_qos_policy, policy['id'],
                          name=LONG_NAME_NG)

    @decorators.attr(type='negative')
    @decorators.idempotent_id('925c7eaf-474b-4a02-a4ba-76a9f82bc45a')
    def test_update_policy_with_too_long_description(self):
        policy = self.create_qos_policy(name='test', description='test policy',
                                        shared=False)
        self.assertRaises(lib_exc.BadRequest,
                          self.client.update_qos_policy, policy['id'],
                          description=LONG_DESCRIPTION_NG)


class QosBandwidthLimitRuleNegativeTestJSON(base.BaseAdminNetworkTest):

    required_extensions = [qos_apidef.ALIAS]

    @decorators.attr(type='negative')
    @decorators.idempotent_id('e9ce8042-c828-4cb9-b1f1-85bd35e6553a')
    def test_rule_update_rule_nonexistent_policy(self):
        non_exist_id = data_utils.rand_name('qos_policy')
        policy = self.create_qos_policy(name='test-policy',
                                        description='test policy',
                                        shared=False)
        rule = self.create_qos_bandwidth_limit_rule(policy_id=policy['id'],
                                                    max_kbps=1,
                                                    max_burst_kbps=1)
        self.assertRaises(
            lib_exc.NotFound,
            self.admin_client.update_bandwidth_limit_rule,
            non_exist_id, rule['id'], max_kbps=200, max_burst_kbps=1337)

    @decorators.attr(type='negative')
    @decorators.idempotent_id('a2c72066-0c32-4f28-be7f-78fa721588b6')
    def test_rule_update_rule_nonexistent_rule(self):
        non_exist_id = data_utils.rand_name('qos_rule')
        policy = self.create_qos_policy(name='test-policy',
                                        description='test policy',
                                        shared=False)
        self.assertRaises(
            lib_exc.NotFound,
            self.admin_client.update_bandwidth_limit_rule,
            policy['id'], non_exist_id, max_kbps=200, max_burst_kbps=1337)
