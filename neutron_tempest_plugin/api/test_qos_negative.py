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
from neutron_lib import constants as n_constants
from neutron_lib.db import constants as db_const
from neutron_lib.services.qos import constants as qos_consts
from tempest.common import utils
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
        policy = self.create_qos_policy(
            name=data_utils.rand_name('test', 'policy'),
            description='test policy',
            shared=False)
        self.assertRaises(lib_exc.BadRequest,
                          self.client.update_qos_policy, policy['id'],
                          name=LONG_NAME_NG)

    @decorators.attr(type='negative')
    @decorators.idempotent_id('925c7eaf-474b-4a02-a4ba-76a9f82bc45a')
    def test_update_policy_with_too_long_description(self):
        policy = self.create_qos_policy(
            name=data_utils.rand_name('test', 'policy'),
            description='test policy',
            shared=False)
        self.assertRaises(lib_exc.BadRequest,
                          self.client.update_qos_policy, policy['id'],
                          description=LONG_DESCRIPTION_NG)

    @decorators.attr(type='negative')
    @decorators.idempotent_id('88b54ab0-804b-446c-bc19-8e54222d70ef')
    def test_get_non_existent_qos_policy(self):
        non_exist_id = data_utils.rand_name('qos_policy')
        self.assertRaises(lib_exc.NotFound,
                          self.admin_client.show_qos_policy, non_exist_id)

    @decorators.attr(type='negative')
    @decorators.idempotent_id('21050859-1284-4bf5-b05a-13846f83988f')
    def test_update_non_existent_qos_policy(self):
        non_exist_id = data_utils.rand_name('qos_policy')
        self.assertRaises(lib_exc.NotFound,
                          self.admin_client.update_qos_policy, non_exist_id,
                          shared=False)

    @decorators.attr(type='negative')
    @decorators.idempotent_id('09e435b7-44d3-4f9d-8aa8-c295d46b5866')
    def test_delete_non_existent_qos_policy(self):
        non_exist_id = data_utils.rand_name('qos_policy')
        self.assertRaises(lib_exc.NotFound,
                          self.admin_client.delete_qos_policy, non_exist_id)


class QosRuleNegativeBaseTestJSON(base.BaseAdminNetworkTest):

    required_extensions = [qos_apidef.ALIAS]

    def _test_rule_update_rule_nonexistent_policy(self, create_params,
                                                  update_params):
        non_exist_id = data_utils.rand_name('qos_policy')
        policy = self.create_qos_policy(
            name=data_utils.rand_name('test', 'policy'),
            description='test policy',
            shared=False)
        rule = self.rule_create_m(policy['id'], **create_params)
        if "minimum_bandwidth_rule" in rule.keys():
            rule_id = rule['minimum_bandwidth_rule']['id']
        if "minimum_packet_rate_rule" in rule.keys():
            rule_id = rule['minimum_packet_rate_rule']['id']
        if "bandwidth_limit_rule" in rule.keys():
            rule_id = rule['bandwidth_limit_rule']['id']
        if "dscp_mark" in rule.keys():
            rule_id = rule['id']
        self.assertRaises(
            lib_exc.NotFound,
            self.rule_update_m,
            non_exist_id, rule_id, **update_params)

    def _test_rule_create_rule_non_existent_policy(self, create_params):
        non_exist_id = data_utils.rand_name('qos_policy')
        self.assertRaises(
            lib_exc.NotFound,
            self.rule_create_m,
            non_exist_id, **create_params)

    def _test_rule_update_rule_nonexistent_rule(self, update_params):
        non_exist_id = data_utils.rand_name('qos_rule')
        policy = self.create_qos_policy(name='test-policy',
                                        description='test policy',
                                        shared=False)
        self.assertRaises(
            lib_exc.NotFound,
            self.rule_update_m,
            policy['id'], non_exist_id, **update_params)


class QosBandwidthLimitRuleNegativeTestJSON(QosRuleNegativeBaseTestJSON):

    @classmethod
    def setup_clients(cls):
        super(QosBandwidthLimitRuleNegativeTestJSON, cls).setup_clients()
        cls.qos_bw_limit_rule_client = \
            cls.os_admin.qos_limit_bandwidth_rules_client

    @classmethod
    def resource_setup(cls):
        cls.rule_create_m = \
            cls.qos_bw_limit_rule_client.create_limit_bandwidth_rule
        cls.rule_update_m = \
            cls.qos_bw_limit_rule_client.update_limit_bandwidth_rule
        super(QosBandwidthLimitRuleNegativeTestJSON, cls).resource_setup()

    @decorators.attr(type='negative')
    @decorators.idempotent_id('e9ce8042-c828-4cb9-b1f1-85bd35e6553a')
    def test_rule_update_rule_nonexistent_policy(self):
        create_params = {'max_kbps': 1, 'max_burst_kbps': 1}
        update_params = {'max_kbps': 200, 'max_burst_kbps': 1337}
        self._test_rule_update_rule_nonexistent_policy(
            create_params, update_params)

    @decorators.attr(type='negative')
    @decorators.idempotent_id('1b592566-745f-4e15-a439-073afe341244')
    def test_rule_create_rule_non_existent_policy(self):
        create_params = {'max_kbps': 200, 'max_burst_kbps': 300}
        self._test_rule_create_rule_non_existent_policy(create_params)

    @decorators.attr(type='negative')
    @decorators.idempotent_id('a2c72066-0c32-4f28-be7f-78fa721588b6')
    def test_rule_update_rule_nonexistent_rule(self):
        update_params = {'max_kbps': 200, 'max_burst_kbps': 1337}
        self._test_rule_update_rule_nonexistent_rule(update_params)


class QosMinimumBandwidthRuleNegativeTestJSON(QosRuleNegativeBaseTestJSON):

    @classmethod
    def resource_setup(cls):
        cls.rule_create_m = cls.os_admin.qos_minimum_bandwidth_rules_client.\
            create_minimum_bandwidth_rule
        cls.rule_update_m = cls.os_admin.qos_minimum_bandwidth_rules_client.\
            update_minimum_bandwidth_rule
        super(QosMinimumBandwidthRuleNegativeTestJSON, cls).resource_setup()

    @decorators.attr(type='negative')
    @decorators.idempotent_id('08b8455b-4d4f-4119-bad3-9357085c3a80')
    def test_rule_update_rule_nonexistent_policy(self):
        create_params = {'min_kbps': 1}
        update_params = {'min_kbps': 200}
        self._test_rule_update_rule_nonexistent_policy(
            create_params, update_params)

    @decorators.attr(type='negative')
    @decorators.idempotent_id('5a714a4a-bfbc-4cf9-b0c0-13fd185204f7')
    def test_rule_create_rule_non_existent_policy(self):
        create_params = {'min_kbps': 200}
        self._test_rule_create_rule_non_existent_policy(create_params)

    @decorators.attr(type='negative')
    @decorators.idempotent_id('8470cbe0-8ca5-46ab-9c66-7cf69301b121')
    def test_rule_update_rule_nonexistent_rule(self):
        update_params = {'min_kbps': 200}
        self._test_rule_update_rule_nonexistent_rule(update_params)


class QosMinimumPpsRuleNegativeTestJSON(QosRuleNegativeBaseTestJSON):

    @classmethod
    @utils.requires_ext(service='network',
                        extension='port-resource-request-groups')
    def resource_setup(cls):
        cls.rule_create_m = cls.os_admin.qos_minimum_packet_rate_rules_client.\
            create_minimum_packet_rate_rule
        cls.rule_update_m = cls.os_admin.qos_minimum_packet_rate_rules_client.\
            update_minimum_packet_rate_rule
        super(QosMinimumPpsRuleNegativeTestJSON, cls).resource_setup()

    @decorators.attr(type='negative')
    @decorators.idempotent_id('ddd16824-3e10-11ec-928d-5b1ef3fb9f43')
    def test_rule_update_rule_nonexistent_policy(self):
        create_params = {qos_consts.DIRECTION: n_constants.EGRESS_DIRECTION,
                         qos_consts.MIN_KPPS: 1}
        update_params = {qos_consts.MIN_KPPS: 200}
        self._test_rule_update_rule_nonexistent_policy(
            create_params, update_params)

    @decorators.attr(type='negative')
    @decorators.idempotent_id('de4f5540-3e10-11ec-9700-4bf3629b843e')
    def test_rule_create_rule_non_existent_policy(self):
        create_params = {qos_consts.DIRECTION: n_constants.EGRESS_DIRECTION,
                         qos_consts.MIN_KPPS: 200}
        self._test_rule_create_rule_non_existent_policy(create_params)

    @decorators.attr(type='negative')
    @decorators.idempotent_id('deb914ee-3e10-11ec-b3dc-03e52f9269c9')
    def test_rule_update_rule_nonexistent_rule(self):
        update_params = {qos_consts.MIN_KPPS: 200}
        self._test_rule_update_rule_nonexistent_rule(update_params)


class QosDscpRuleNegativeTestJSON(QosRuleNegativeBaseTestJSON):

    @classmethod
    def resource_setup(cls):
        cls.rule_create_m = cls.create_qos_dscp_marking_rule
        cls.rule_update_m = cls.admin_client.update_dscp_marking_rule
        super(QosDscpRuleNegativeTestJSON, cls).resource_setup()

    @decorators.attr(type='negative')
    @decorators.idempotent_id('d47d5fbe-3e98-476f-b2fd-97818175dea5')
    def test_rule_update_rule_nonexistent_policy(self):
        create_params = {'dscp_mark': 26}
        update_params = {'dscp_mark': 16}
        self._test_rule_update_rule_nonexistent_policy(
            create_params, update_params)

    @decorators.attr(type='negative')
    @decorators.idempotent_id('07d17f09-3dc4-4c24-9bb1-49081a153c5a')
    def test_rule_create_rule_non_existent_policy(self):
        create_params = {'dscp_mark': 16}
        self._test_rule_create_rule_non_existent_policy(create_params)

    @decorators.attr(type='negative')
    @decorators.idempotent_id('9c0bd085-5a7a-496f-a984-50dc631a64f2')
    def test_rule_update_rule_nonexistent_rule(self):
        update_params = {'dscp_mark': 16}
        self._test_rule_update_rule_nonexistent_rule(update_params)
