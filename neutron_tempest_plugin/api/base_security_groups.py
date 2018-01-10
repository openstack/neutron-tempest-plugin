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

from neutron_lib import constants
from tempest.lib.common.utils import data_utils

from neutron_tempest_plugin.api import base


# NOTE(yamamoto): The list of protocols here is what we had in Ocata.
# (neutron-lib 1.1.0)
# Why don't we just use neutron_lib.constants.IP_PROTOCOL_MAP etc here?
# Tempest is branchless and thus supposed to work against older deployments.
# Also, it's supposed to work against other implementations, which might not
# support the same set as the reference implementation. Ideally SG can have
# a way to discover the set of usable protocols. But for now, we need to be
# conservative.

V4_PROTOCOL_NAMES = {
    'ah',
    'dccp',
    'egp',
    'esp',
    'gre',
    'icmp',
    'igmp',
    'ospf',
    'pgm',
    'rsvp',
    'sctp',
    'tcp',
    'udp',
    'udplite',
    'vrrp',
}
V4_PROTOCOL_INTS = set(v for k, v in constants.IP_PROTOCOL_MAP.items() if
                       k in V4_PROTOCOL_NAMES)
V6_PROTOCOL_LEGACY = set([constants.PROTO_NAME_IPV6_ICMP_LEGACY])
V6_PROTOCOL_NAMES = {
    'ipv6-encap',
    'ipv6-frag',
    'ipv6-icmp',
    'ipv6-nonxt',
    'ipv6-opts',
    'ipv6-route',
}
V6_PROTOCOL_INTS = set(v for k, v in constants.IP_PROTOCOL_MAP.items() if
                       k in (V6_PROTOCOL_NAMES | V6_PROTOCOL_LEGACY))


class BaseSecGroupTest(base.BaseNetworkTest):

    def _create_security_group(self, **kwargs):
        # Create a security group
        name = data_utils.rand_name('secgroup-')
        group_create_body = self.client.create_security_group(name=name,
                                                              **kwargs)
        self.addCleanup(self._delete_security_group,
                        group_create_body['security_group']['id'])
        self.assertEqual(group_create_body['security_group']['name'], name)
        return group_create_body, name

    def _delete_security_group(self, secgroup_id):
        self.client.delete_security_group(secgroup_id)
        # Asserting that the security group is not found in the list
        # after deletion
        list_body = self.client.list_security_groups()
        secgroup_list = list()
        for secgroup in list_body['security_groups']:
            secgroup_list.append(secgroup['id'])
        self.assertNotIn(secgroup_id, secgroup_list)

    def _create_security_group_rule(self, **kwargs):
        rule_create_body = self.client.create_security_group_rule(**kwargs)
        # List rules and verify created rule is in response
        rule_list_body = (
            self.client.list_security_group_rules())
        rule_list = [rule['id']
                     for rule in rule_list_body['security_group_rules']]
        self.assertIn(rule_create_body['security_group_rule']['id'],
                      rule_list)
        self.addCleanup(self._delete_security_group_rule,
                        rule_create_body['security_group_rule']['id'])
        return rule_create_body

    def _show_security_group_rule(self, **kwargs):
        show_rule_body = self.client.show_security_group_rule(kwargs['id'])
        for key, value in kwargs.items():
            self.assertEqual(value,
                             show_rule_body['security_group_rule'][key],
                             "%s does not match." % key)

    def _delete_security_group_rule(self, secgroup_rule_id):
        self.client.delete_security_group_rule(secgroup_rule_id)
        rule_list_body = self.client.list_security_group_rules()
        rule_list = [rule['id']
                     for rule in rule_list_body['security_group_rules']]
        self.assertNotIn(secgroup_rule_id, rule_list)

    def _test_create_show_delete_security_group_rule(self, **kwargs):
        # The security group rule is deleted by the cleanup call in
        # _create_security_group_rule.
        rule_create_body = (
            self._create_security_group_rule(**kwargs)['security_group_rule'])
        self._show_security_group_rule(
            id=rule_create_body['id'],
            protocol=rule_create_body['protocol'],
            direction=rule_create_body['direction'],
            ethertype=rule_create_body['ethertype'])
