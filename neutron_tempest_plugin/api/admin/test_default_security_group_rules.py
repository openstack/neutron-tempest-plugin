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
import random

from neutron_lib import constants
from tempest.lib import decorators
from tempest.lib import exceptions as lib_exc

from neutron_tempest_plugin.api import base

RULE_KEYWORDS_TO_CHECK = [
    'direction', 'remote_group_id', 'remote_address_group_id', 'description',
    'protocol', 'port_range_min', 'port_range_max', 'ethertype',
    'remote_ip_prefix', 'used_in_default_sg', 'used_in_non_default_sg'
]


class DefaultSecurityGroupRuleTest(base.BaseAdminNetworkTest):
    required_extensions = ['security-groups-default-rules']

    credentials = ['primary', 'admin']

    @classmethod
    def setup_clients(cls):
        super(DefaultSecurityGroupRuleTest, cls).setup_clients()
        cls.admin_client = cls.os_admin.network_client

    def _filter_not_relevant_rule_keys(self, rule, expected_keys=None):
        expected_keys = expected_keys or RULE_KEYWORDS_TO_CHECK
        new_rule = {}
        for k in rule.keys():
            if k in expected_keys:
                new_rule[k] = rule[k]
        return new_rule

    def _filter_not_relevant_rules_keys(self, rules, keys=None):
        keys = keys or RULE_KEYWORDS_TO_CHECK
        return [self._filter_not_relevant_rule_keys(r, keys) for r in rules]

    def _assert_rules_exists(self, expected_rules, actual_rules):
        for expected_rule in expected_rules:
            self.assertIn(expected_rule, actual_rules)

    @decorators.idempotent_id('2f3d3070-e9fa-4127-a33f-f1532fd89108')
    def test_legacy_default_sg_rules_created_by_default(self):
        expected_legacy_template_rules = [
            {
                'direction': 'egress',
                'ethertype': 'IPv4',
                'remote_group_id': None,
                'protocol': None,
                'remote_ip_prefix': None,
                'remote_address_group_id': None,
                'port_range_max': None,
                'port_range_min': None,
                'used_in_default_sg': True,
                'used_in_non_default_sg': True,
                'description': 'Legacy default SG rule for egress traffic'
            }, {
                'remote_group_id': 'PARENT',
                'direction': 'ingress',
                'ethertype': 'IPv6',
                'protocol': None,
                'remote_ip_prefix': None,
                'remote_address_group_id': None,
                'port_range_max': None,
                'port_range_min': None,
                'used_in_default_sg': True,
                'used_in_non_default_sg': False,
                'description': 'Legacy default SG rule for ingress traffic'
            }, {
                'remote_group_id': 'PARENT',
                'direction': 'ingress',
                'ethertype': 'IPv4',
                'protocol': None,
                'remote_ip_prefix': None,
                'remote_address_group_id': None,
                'port_range_max': None,
                'port_range_min': None,
                'used_in_default_sg': True,
                'used_in_non_default_sg': False,
                'description': 'Legacy default SG rule for ingress traffic'
            }, {
                'direction': 'egress',
                'ethertype': 'IPv6',
                'remote_group_id': None,
                'protocol': None,
                'remote_ip_prefix': None,
                'remote_address_group_id': None,
                'port_range_max': None,
                'port_range_min': None,
                'used_in_default_sg': True,
                'used_in_non_default_sg': True,
                'description': 'Legacy default SG rule for egress traffic'
            }
        ]
        sg_rules_template = (
            self.admin_client.list_default_security_group_rules()[
                'default_security_group_rules'
            ])
        self._assert_rules_exists(
            expected_legacy_template_rules,
            self._filter_not_relevant_rules_keys(sg_rules_template))

    @decorators.idempotent_id('df98f969-ff2d-4597-9765-f5d4f81f775f')
    def test_default_security_group_rule_lifecycle(self):
        tcp_port = random.randint(constants.PORT_RANGE_MIN,
                                  constants.PORT_RANGE_MAX)
        rule_args = {
            'direction': 'ingress',
            'ethertype': 'IPv4',
            'protocol': 'tcp',
            'port_range_max': tcp_port,
            'port_range_min': tcp_port,
            'used_in_default_sg': False,
            'used_in_non_default_sg': True,
            'description': (
                'Allow tcp connections over IPv4 on port %s' % tcp_port)
        }
        expected_rule = {
            'remote_group_id': None,
            'direction': 'ingress',
            'ethertype': 'IPv4',
            'protocol': 'tcp',
            'port_range_min': tcp_port,
            'port_range_max': tcp_port,
            'remote_ip_prefix': None,
            'remote_address_group_id': None,
            'used_in_default_sg': False,
            'used_in_non_default_sg': True,
            'description': (
                'Allow tcp connections over IPv4 on port %s' % tcp_port)
        }
        created_rule_template = self.create_default_security_group_rule(
            **rule_args)
        self.assertDictEqual(
            expected_rule,
            self._filter_not_relevant_rule_keys(created_rule_template)
        )
        observed_rule_template = (
            self.admin_client.get_default_security_group_rule(
                created_rule_template['id'])
        )['default_security_group_rule']
        self.assertDictEqual(
            expected_rule,
            self._filter_not_relevant_rule_keys(observed_rule_template)
        )

        self.admin_client.delete_default_security_group_rule(
            created_rule_template['id']
        )
        self.assertRaises(
            lib_exc.NotFound,
            self.admin_client.get_default_security_group_rule,
            created_rule_template['id']
        )

    @decorators.idempotent_id('6c5a2f41-5899-47f4-9daf-4f8ddbbd3ad5')
    def test_create_duplicate_default_security_group_rule_different_templates(
            self):
        tcp_port = random.randint(constants.PORT_RANGE_MIN,
                                  constants.PORT_RANGE_MAX)
        rule_args = {
            'direction': 'ingress',
            'ethertype': 'IPv4',
            'protocol': 'tcp',
            'port_range_max': tcp_port,
            'port_range_min': tcp_port,
            'used_in_default_sg': True,
            'used_in_non_default_sg': True}
        self.create_default_security_group_rule(**rule_args)

        # Now, even if 'used_in_non_default_sg' will be different error should
        # be returned as 'used_in_default_sg' is the same
        new_rule_args = copy.copy(rule_args)
        new_rule_args['used_in_non_default_sg'] = False
        self.assertRaises(
            lib_exc.Conflict,
            self.admin_client.create_default_security_group_rule,
            **new_rule_args)

        # Same in the opposite way: even if 'used_in_default_sg' will be
        # different error should be returned as 'used_in_non_default_sg'
        # is the same
        new_rule_args = copy.copy(rule_args)
        new_rule_args['used_in_default_sg'] = False
        self.assertRaises(
            lib_exc.Conflict,
            self.admin_client.create_default_security_group_rule,
            **new_rule_args)

    @decorators.idempotent_id('e4696607-1a13-48eb-8912-ee1e742d9471')
    def test_create_same_default_security_group_rule_for_different_templates(
            self):
        tcp_port = random.randint(constants.PORT_RANGE_MIN,
                                  constants.PORT_RANGE_MAX)
        expected_rules = [{
            'remote_group_id': None,
            'direction': 'ingress',
            'ethertype': 'IPv4',
            'protocol': 'tcp',
            'remote_ip_prefix': None,
            'remote_address_group_id': None,
            'port_range_max': tcp_port,
            'port_range_min': tcp_port,
            'used_in_default_sg': True,
            'used_in_non_default_sg': False,
            'description': ''
        }, {
            'remote_group_id': None,
            'direction': 'ingress',
            'ethertype': 'IPv4',
            'protocol': 'tcp',
            'remote_ip_prefix': None,
            'remote_address_group_id': None,
            'port_range_max': tcp_port,
            'port_range_min': tcp_port,
            'used_in_default_sg': False,
            'used_in_non_default_sg': True,
            'description': ''
        }]

        default_sg_rule_args = {
            'direction': 'ingress',
            'ethertype': 'IPv4',
            'protocol': 'tcp',
            'port_range_max': tcp_port,
            'port_range_min': tcp_port,
            'used_in_default_sg': True,
            'used_in_non_default_sg': False}
        self.create_default_security_group_rule(**default_sg_rule_args)

        custom_sg_rule_args = {
            'direction': 'ingress',
            'ethertype': 'IPv4',
            'protocol': 'tcp',
            'port_range_max': tcp_port,
            'port_range_min': tcp_port,
            'used_in_default_sg': False,
            'used_in_non_default_sg': True}
        self.create_default_security_group_rule(**custom_sg_rule_args)

        sg_rules_template = (
            self.admin_client.list_default_security_group_rules()[
                'default_security_group_rules'
            ])
        self._assert_rules_exists(
            expected_rules,
            self._filter_not_relevant_rules_keys(sg_rules_template))

    def _validate_security_group_rules(self, sg, is_default_sg):
        keys_to_check = [
            'remote_group_id', 'direction', 'ethertype', 'protocol',
            'remote_ip_prefix', 'remote_address_group_id', 'port_range_min',
            'port_range_max']

        if is_default_sg:
            sg_rules_template = (
                self.admin_client.list_default_security_group_rules(
                    used_in_default_sg=True)['default_security_group_rules'])
        else:
            sg_rules_template = (
                self.admin_client.list_default_security_group_rules(
                    used_in_non_default_sg=True
                )['default_security_group_rules'])
        # NOTE(slaweq): We need to replace "PARENT" keyword in
        # the "remote_group_id" attribute of every default sg rule template
        # with actual SG ID
        for rule in sg_rules_template:
            if rule['remote_group_id'] == 'PARENT':
                rule['remote_group_id'] = sg['id']

        self._assert_rules_exists(
            self._filter_not_relevant_rules_keys(
                sg_rules_template, keys_to_check),
            self._filter_not_relevant_rules_keys(
                sg['security_group_rules'], keys_to_check))

    @decorators.idempotent_id('29feedb1-6f04-4a1f-a778-2fae2c7b7dc8')
    def test_security_group_rules_created_from_default_sg_rules_template(
            self):
        """Test if default SG and custom new SG have got proper SG rules.

        This test creates new project and checks if its default SG has SG
        rules matching default SG rules for that kind of SG.
        Next it creates new SG for the same project and checks if that SG also
        have proper SG rules based on the default SG rules template.
        """

        project = self.create_project()
        # First check rules for default SG created automatically for each
        # project
        default_sg = self.admin_client.list_security_groups(
            tenant_id=project['id'], name='default')['security_groups'][0]
        self._validate_security_group_rules(default_sg, is_default_sg=True)

        # And now create different SG for same project and check SG rules for
        # such additional SG
        sg = self.create_security_group(project=project)
        self._validate_security_group_rules(sg, is_default_sg=False)
