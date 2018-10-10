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
from tempest.lib import decorators

from neutron_tempest_plugin.api import base
from neutron_tempest_plugin.api import base_security_groups


class SecGroupTest(base.BaseNetworkTest):

    required_extensions = ['security-group']

    @decorators.idempotent_id('bfd128e5-3c92-44b6-9d66-7fe29d22c802')
    def test_create_list_update_show_delete_security_group(self):
        security_group = self.create_security_group()

        # List security groups and verify if created group is there in response
        security_groups = self.client.list_security_groups()['security_groups']
        self.assertIn(security_group['id'],
                      {sg['id'] for sg in security_groups})

        # Update the security group
        new_name = data_utils.rand_name('security')
        new_description = data_utils.rand_name('security-description')
        updated_security_group = self.client.update_security_group(
            security_group['id'], name=new_name,
            description=new_description)['security_group']

        # Verify if security group is updated
        self.assertEqual(updated_security_group['name'], new_name)
        self.assertEqual(updated_security_group['description'],
                         new_description)

        # Show details of the updated security group
        observed_security_group = self.client.show_security_group(
            security_group['id'])['security_group']
        self.assertEqual(observed_security_group['name'], new_name)
        self.assertEqual(observed_security_group['description'],
                         new_description)

    @decorators.idempotent_id('7c0ecb10-b2db-11e6-9b14-000c29248b0d')
    def test_create_bulk_sec_groups(self):
        # Creates 2 sec-groups in one request
        sec_nm = [data_utils.rand_name('secgroup'),
                  data_utils.rand_name('secgroup')]
        body = self.client.create_bulk_security_groups(sec_nm)
        created_sec_grps = body['security_groups']
        self.assertEqual(2, len(created_sec_grps))
        for secgrp in created_sec_grps:
            self.addCleanup(self.client.delete_security_group,
                            secgrp['id'])
            self.assertIn(secgrp['name'], sec_nm)
            self.assertIsNotNone(secgrp['id'])


class SecGroupProtocolTest(base.BaseNetworkTest):

    protocol_names = base_security_groups.V4_PROTOCOL_NAMES
    protocol_ints = base_security_groups.V4_PROTOCOL_INTS

    @decorators.idempotent_id('282e3681-aa6e-42a7-b05c-c341aa1e3cdf')
    def test_security_group_rule_protocol_names(self):
        self._test_security_group_rule_protocols(protocols=self.protocol_names)

    @decorators.idempotent_id('66e47f1f-20b6-4417-8839-3cc671c7afa3')
    def test_security_group_rule_protocol_ints(self):
        self._test_security_group_rule_protocols(protocols=self.protocol_ints)

    def _test_security_group_rule_protocols(self, protocols):
        security_group = self.create_security_group()
        for protocol in protocols:
            self._test_security_group_rule(
                security_group=security_group,
                protocol=str(protocol),
                direction=constants.INGRESS_DIRECTION,
                ethertype=self.ethertype)

    def _test_security_group_rule(self, security_group, **kwargs):
        security_group_rule = self.create_security_group_rule(
            security_group=security_group, **kwargs)
        observed_security_group_rule = self.client.show_security_group_rule(
            security_group_rule['id'])['security_group_rule']
        for key, value in kwargs.items():
            self.assertEqual(value, security_group_rule[key],
                             "{!r} does not match.".format(key))
            self.assertEqual(value, observed_security_group_rule[key],
                             "{!r} does not match.".format(key))


class SecGroupProtocolIPv6Test(SecGroupProtocolTest):

    _ip_version = constants.IP_VERSION_6
    protocol_names = base_security_groups.V6_PROTOCOL_NAMES
    protocol_ints = base_security_groups.V6_PROTOCOL_INTS
    protocol_legacy_names = base_security_groups.V6_PROTOCOL_LEGACY

    @decorators.idempotent_id('c7d17b41-3b4e-4add-bb3b-6af59baaaffa')
    def test_security_group_rule_protocol_legacy_names(self):
        self._test_security_group_rule_protocols(
            protocols=self.protocol_legacy_names)
