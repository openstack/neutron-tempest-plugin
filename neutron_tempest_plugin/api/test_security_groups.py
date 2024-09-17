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

import random

from neutron_lib import constants
from tempest.lib.common.utils import data_utils
from tempest.lib.common.utils import test_utils
from tempest.lib import decorators
from tempest.lib import exceptions
import testtools

from neutron_tempest_plugin.api import base
from neutron_tempest_plugin.api import base_security_groups
from oslo_log import log

LOG = log.getLogger(__name__)


class BaseSecGroupTest(base.BaseAdminNetworkTest):

    required_extensions = ['security-group']

    def _test_create_list_update_show_delete_security_group(self):
        sg_kwargs = {}
        if self.stateless_sg:
            sg_kwargs['stateful'] = False
        security_group = self.create_security_group(**sg_kwargs)

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

    def _test_show_security_group_contains_all_rules(self):
        sg_kwargs = {}
        if self.stateless_sg:
            sg_kwargs['stateful'] = False
        security_group = self.create_security_group(**sg_kwargs)
        protocol = random.choice(list(base_security_groups.V4_PROTOCOL_NAMES))
        security_group_rule = self.create_security_group_rule(
            security_group=security_group,
            project={'id': self.admin_client.project_id},
            client=self.admin_client,
            protocol=protocol,
            direction=constants.INGRESS_DIRECTION)

        observed_security_group = self.client.show_security_group(
            security_group['id'])['security_group']
        observerd_security_group_rules_ids = [
            sgr['id'] for sgr in
            observed_security_group['security_group_rules']]
        self.assertIn(
            security_group_rule['id'], observerd_security_group_rules_ids)

    def _test_list_security_group_rules_contains_all_rules(self):
        """Test list security group rules.

        This test checks if all SG rules which belongs to the tenant OR
        which belongs to the tenant's security group are listed.
        """
        sg_kwargs = {}
        if self.stateless_sg:
            sg_kwargs['stateful'] = False
        security_group = self.create_security_group(**sg_kwargs)
        protocol = random.choice(list(base_security_groups.V4_PROTOCOL_NAMES))
        security_group_rule = self.create_security_group_rule(
            security_group=security_group,
            project={'id': self.admin_client.project_id},
            client=self.admin_client,
            protocol=protocol,
            direction=constants.INGRESS_DIRECTION)

        # Create also other SG with some custom rule to check that regular user
        # can't see this rule
        sg_kwargs = {
            'project': {'id': self.admin_client.project_id},
            'client': self.admin_client
        }
        if self.stateless_sg:
            sg_kwargs['stateful'] = False
        admin_security_group = self.create_security_group(**sg_kwargs)
        admin_security_group_rule = self.create_security_group_rule(
            security_group=admin_security_group,
            project={'id': self.admin_client.project_id},
            client=self.admin_client,
            protocol=protocol,
            direction=constants.INGRESS_DIRECTION)

        rules = self.client.list_security_group_rules()['security_group_rules']
        rules_ids = [rule['id'] for rule in rules]
        self.assertIn(security_group_rule['id'], rules_ids)
        self.assertNotIn(admin_security_group_rule['id'], rules_ids)

    def _test_create_bulk_sec_groups(self):
        # Creates 2 sec-groups in one request
        sec_nm = [data_utils.rand_name('secgroup'),
                  data_utils.rand_name('secgroup')]
        body = self.client.create_bulk_security_groups(
            sec_nm, stateless=self.stateless_sg)
        created_sec_grps = body['security_groups']
        self.assertEqual(2, len(created_sec_grps))
        for secgrp in created_sec_grps:
            self.addCleanup(self.client.delete_security_group,
                            secgrp['id'])
            self.assertIn(secgrp['name'], sec_nm)
            self.assertIsNotNone(secgrp['id'])

    def _test_create_sec_groups_with_the_same_name(self):
        same_name_sg_number = 5
        sg_name = 'sg_zahlabut'
        sg_names = [sg_name] * same_name_sg_number
        sg_kwargs = {}
        if self.stateless_sg:
            sg_kwargs['stateful'] = False
        for name in sg_names:
            sg_kwargs['name'] = name
            self.create_security_group(**sg_kwargs)
        sec_groups = [item['id'] for item in
                      self.client.list_security_groups(
                          name=sg_name)['security_groups']]
        self.assertEqual(
            same_name_sg_number, len(set(sec_groups)),
            'Failed - expected number of groups with the same name'
            ' is: {}'.format(same_name_sg_number))


class StatefulSecGroupTest(BaseSecGroupTest):

    stateless_sg = False

    @decorators.idempotent_id('bfd128e5-3c92-44b6-9d66-7fe29d22c802')
    def test_create_list_update_show_delete_security_group(self):
        self._test_create_list_update_show_delete_security_group()

    @decorators.idempotent_id('1fff0d57-bb6c-4528-9c1d-2326dce1c087')
    def test_show_security_group_contains_all_rules(self):
        self._test_show_security_group_contains_all_rules()

    @decorators.idempotent_id('b5923b1a-4d33-44e1-af25-088dcb55b02b')
    def test_list_security_group_rules_contains_all_rules(self):
        self._test_list_security_group_rules_contains_all_rules()

    @decorators.idempotent_id('7c0ecb10-b2db-11e6-9b14-000c29248b0d')
    def test_create_bulk_sec_groups(self):
        self._test_create_bulk_sec_groups()

    @decorators.idempotent_id('e93f33d8-57ea-11eb-b69b-74e5f9e2a801')
    def test_create_sec_groups_with_the_same_name(self):
        self._test_create_sec_groups_with_the_same_name()


class StatelessSecGroupTest(BaseSecGroupTest):

    required_extensions = ['security-group', 'stateful-security-group']
    stateless_sg = True

    @decorators.idempotent_id('0214d58a-2177-47e1-af83-dcd45c024829')
    def test_create_list_update_show_delete_security_group(self):
        self._test_create_list_update_show_delete_security_group()

    @decorators.idempotent_id('ddbc0e4c-840f-44ab-8718-0b95b7c7b575')
    def test_show_security_group_contains_all_rules(self):
        self._test_show_security_group_contains_all_rules()

    @decorators.idempotent_id('cdf3a63a-08fe-4091-bab4-62180847990f')
    def test_list_security_group_rules_contains_all_rules(self):
        self._test_list_security_group_rules_contains_all_rules()

    @decorators.idempotent_id('b33e612e-65f0-467b-9bf2-b5b2ce67f72f')
    def test_create_bulk_sec_groups(self):
        self._test_create_bulk_sec_groups()

    @decorators.idempotent_id('a6896935-db18-413d-95f5-4f465e0e2209')
    def test_create_sec_groups_with_the_same_name(self):
        self._test_create_sec_groups_with_the_same_name()

    @decorators.idempotent_id('0a6c1476-3d1a-11ec-b0ec-0800277ac3d9')
    def test_stateless_security_group_update(self):
        security_group = self.create_security_group(stateful=True)

        # List security groups and verify if created group is there in response
        security_groups = self.client.list_security_groups()['security_groups']
        found = False
        for sg in security_groups:
            if sg['id'] == security_group['id']:
                found = True
                break
        self.assertTrue(found)
        self.assertTrue(sg['stateful'])

        # Switch to stateless
        updated_security_group = self.client.update_security_group(
            security_group['id'], stateful=False)['security_group']

        # Verify if security group is updated
        self.assertFalse(updated_security_group['stateful'])

        observed_security_group = self.client.show_security_group(
            security_group['id'])['security_group']
        self.assertFalse(observed_security_group['stateful'])

        # Switch back to stateful
        updated_security_group = self.client.update_security_group(
            security_group['id'], stateful=True)['security_group']

        # Verify if security group is stateful again
        self.assertTrue(updated_security_group['stateful'])

        observed_security_group = self.client.show_security_group(
            security_group['id'])['security_group']
        self.assertTrue(observed_security_group['stateful'])


class BaseSecGroupQuota(base.BaseAdminNetworkTest):

    def setUp(self):
        super().setUp()
        # NOTE(slaweq): we don't know exactly how many rule templates may be
        # created in the neutron db and used for every SG so, as in this test
        # class we are checking quotas of SG, not SG rules, lets set quota for
        # SG rules to -1
        self._set_sg_rules_quota(-1)

    def _create_max_allowed_sg_amount(self):
        sg_amount = self._get_sg_amount()
        sg_quota = self._get_sg_quota()
        sg_to_create = sg_quota - sg_amount
        self._create_security_groups(sg_to_create)

    def _create_security_groups(self, amount):
        for _ in range(amount):
            sg = self.create_security_group()
            self.addCleanup(self.delete_security_group, sg)

    def _increase_sg_quota(self):
        sg_quota = self._get_sg_quota()
        new_sg_quota = 2 * sg_quota
        self._set_sg_quota(new_sg_quota)
        self.assertEqual(self._get_sg_quota(), new_sg_quota,
                         "Security group quota wasn't changed correctly")

    def _decrease_sg_quota(self):
        sg_quota = self._get_sg_quota()
        new_sg_quota = sg_quota // 2
        self._set_sg_quota(new_sg_quota)
        self.assertEqual(self._get_sg_quota(), new_sg_quota,
                         "Security group quota wasn't changed correctly")

    def _set_quota(self, val, resource):
        res_quota = self._get_quota(resource)
        project_id = self.client.project_id
        self.admin_client.update_quotas(project_id, **{resource: val,
                                                       'force': True})
        self.addCleanup(self.admin_client.update_quotas,
                        project_id, **{resource: res_quota, 'force': True})

    def _get_quota(self, resource):
        project_id = self.client.project_id
        quotas = self.admin_client.show_quotas(project_id)
        return quotas['quota'][resource]

    def _set_sg_quota(self, val):
        return self._set_quota(val, 'security_group')

    def _get_sg_quota(self):
        return self._get_quota('security_group')

    def _get_sg_amount(self):
        project_id = self.client.project_id
        filter_query = {'project_id': project_id}
        security_groups = self.client.list_security_groups(**filter_query)
        return len(security_groups['security_groups'])

    def _set_sg_rules_quota(self, val):
        return self._set_quota(val, 'security_group_rule')


class SecGroupQuotaTest(BaseSecGroupQuota):

    credentials = ['primary', 'admin']
    required_extensions = ['security-group', 'quotas']

    @decorators.idempotent_id('1826aa02-090d-4717-b43a-50ee449b02e7')
    def test_sg_quota_values(self):
        values = [-1, 0, 10, 2147483647]
        for value in values:
            self._set_sg_quota(value)
            self.assertEqual(value, self._get_sg_quota())

    @decorators.idempotent_id('df7981fb-b83a-4779-b13e-65494ef44a72')
    def test_max_allowed_sg_amount(self):
        self._create_max_allowed_sg_amount()
        self.assertEqual(self._get_sg_quota(), self._get_sg_amount())

    @decorators.idempotent_id('623d909c-6ef8-43d6-93ee-97086e2651e8')
    def test_sg_quota_increased(self):
        self._create_max_allowed_sg_amount()
        self._increase_sg_quota()
        self._create_max_allowed_sg_amount()
        self.assertEqual(self._get_sg_quota(), self._get_sg_amount(),
                         "Amount of security groups doesn't match quota")

    @decorators.idempotent_id('ba95676c-8d9a-4482-b4ec-74d51a4602a6')
    def test_sg_quota_decrease_less_than_created(self):
        self._create_max_allowed_sg_amount()
        self._decrease_sg_quota()

    @decorators.idempotent_id('d43cf1a7-aa7e-4c41-9340-627a1a6ab961')
    def test_create_sg_when_quota_disabled(self):
        sg_amount = self._get_sg_amount()
        self._set_sg_quota(-1)
        self._create_security_groups(10)
        new_sg_amount = self._get_sg_amount()
        self.assertGreater(new_sg_amount, sg_amount)


class BaseSecGroupRulesQuota(base.BaseAdminNetworkTest):

    def _create_max_allowed_sg_rules_amount(self, port_index=1):
        sg_rules_amount = self._get_sg_rules_amount()
        sg_rules_quota = self._get_sg_rules_quota()
        sg_rules_to_create = sg_rules_quota - sg_rules_amount
        port_index += sg_rules_to_create
        self._create_security_group_rules(sg_rules_to_create,
                                          port_index=port_index)

    def _create_security_group_rules(self, amount, port_index=1):
        for i in range(amount):
            ingress_rule = self.create_security_group_rule(**{
                'project_id': self.client.project_id,
                'direction': 'ingress',
                'port_range_max': port_index + i,
                'port_range_min': port_index + i,
                'protocol': 'tcp'})
            self.addCleanup(
                self.client.delete_security_group_rule, ingress_rule['id'])

    def _increase_sg_rules_quota(self):
        sg_rules_quota = self._get_sg_rules_quota()
        new_sg_rules_quota = 2 * sg_rules_quota
        self._set_sg_rules_quota(new_sg_rules_quota)
        self.assertGreater(self._get_sg_rules_quota(), sg_rules_quota,
                           "Security group rule quota wasnt changed correctly")
        return new_sg_rules_quota

    def _decrease_sg_rules_quota(self):
        sg_rules_quota = self._get_sg_rules_quota()
        new_sg_rules_quota = sg_rules_quota // 2
        self._set_sg_rules_quota(new_sg_rules_quota)
        return new_sg_rules_quota

    def _set_sg_rules_quota(self, val):
        project_id = self.client.project_id
        self.admin_client.update_quotas(project_id,
                                        **{'security_group_rule': val,
                                           'force': True})
        LOG.info('Trying to update security group rule quota {} '.format(val))

    def _get_sg_rules_quota(self):
        project_id = self.client.project_id
        quotas = self.admin_client.show_quotas(project_id)
        return quotas['quota']['security_group_rule']

    def _get_sg_rules_amount(self):
        project_id = self.client.project_id
        filter_query = {'project_id': project_id}
        security_group_rules = self.client.list_security_group_rules(
                **filter_query)
        return len(security_group_rules['security_group_rules'])


class SecGroupRulesQuotaTest(BaseSecGroupRulesQuota):

    credentials = ['primary', 'admin']
    required_extensions = ['security-group', 'quotas']

    def setUp(self):
        super(SecGroupRulesQuotaTest, self).setUp()
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        self.admin_client.reset_quotas, self.client.project_id)
        self._set_sg_rules_quota(10)

    @decorators.idempotent_id('77ec038c-5638-11ea-8e2d-0242ac130003')
    def test_sg_rules_quota_increased(self):
        """Test security group rules quota increased.

        This test checks if it is possible to increase the SG rules Quota
        value and creates security group rules according to new quota value.
        """
        self._create_max_allowed_sg_rules_amount()
        new_quota = self._increase_sg_rules_quota()
        port_index = new_quota
        self._create_max_allowed_sg_rules_amount(port_index)
        quota_set = self._get_sg_rules_quota()
        self.assertEqual(quota_set, self._get_sg_rules_amount(),
                         "Amount of security groups rules doesn't match quota")

    @decorators.idempotent_id('37508c8d-270b-4b93-8007-72876a1fec38')
    def test_sg_rules_quota_values(self):
        """Test security group rules quota values.

        This test checks if it is possible to change the SG rules Quota
        values, different values.
        """
        sg_rules_quota = self._get_sg_rules_quota()
        project_id = self.client.project_id
        self.addCleanup(self.admin_client.update_quotas,
                        project_id, **{'security_group_rule': sg_rules_quota,
                                       'force': True})
        values = [-1, 0, 10, 2147483647]
        for value in values:
            self._set_sg_rules_quota(value)
            self.assertEqual(value, self._get_sg_rules_quota())

    @decorators.idempotent_id('4459e066-d9c8-4a13-9e98-018f95ce2dbf')
    def test_create_sg_rules_when_quota_disabled(self):
        sg_rules_amount = self._get_sg_rules_amount()
        self._set_sg_rules_quota(-1)
        self._create_security_group_rules(10, port_index=100)
        new_sg_rules_amount = self._get_sg_rules_amount()
        self.assertGreater(new_sg_rules_amount, sg_rules_amount)

    @decorators.idempotent_id('3fc39bd6-3132-4e6f-a09c-456fb18d600c')
    def test_sg_rules_quota_decrease_less_than_created(self):
        self._create_max_allowed_sg_rules_amount()
        new_quota = self._decrease_sg_rules_quota()
        self.assertEqual(self._get_sg_rules_quota(), new_quota)


class BaseSecGroupProtocolTest(base.BaseNetworkTest):

    protocol_names = base_security_groups.V4_PROTOCOL_NAMES
    protocol_ints = base_security_groups.V4_PROTOCOL_INTS

    def _test_security_group_rule_protocols(self, protocols):
        sg_kwargs = {}
        if self.stateless_sg:
            sg_kwargs['stateful'] = False
        security_group = self.create_security_group(**sg_kwargs)
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


class StatefulSecGroupProtocolTest(BaseSecGroupProtocolTest):
    stateless_sg = False

    @decorators.idempotent_id('282e3681-aa6e-42a7-b05c-c341aa1e3cdf')
    def test_security_group_rule_protocol_names(self):
        self._test_security_group_rule_protocols(protocols=self.protocol_names)

    @decorators.idempotent_id('66e47f1f-20b6-4417-8839-3cc671c7afa3')
    def test_security_group_rule_protocol_ints(self):
        self._test_security_group_rule_protocols(protocols=self.protocol_ints)


class StatelessSecGroupProtocolTest(BaseSecGroupProtocolTest):
    required_extensions = ['security-group', 'stateful-security-group']
    stateless_sg = True

    @decorators.idempotent_id('3a065cdd-99bd-409f-a08e-385c6674bec2')
    def test_security_group_rule_protocol_names(self):
        self._test_security_group_rule_protocols(protocols=self.protocol_names)

    @decorators.idempotent_id('b0332b5d-6fac-49d5-a79d-ae4fe62600f7')
    def test_security_group_rule_protocol_ints(self):
        self._test_security_group_rule_protocols(protocols=self.protocol_ints)


class BaseSecGroupProtocolIPv6Test(BaseSecGroupProtocolTest):

    _ip_version = constants.IP_VERSION_6
    protocol_names = base_security_groups.V6_PROTOCOL_NAMES
    protocol_ints = base_security_groups.V6_PROTOCOL_INTS

    def _test_security_group_rule_protocol_legacy_icmpv6(self):
        # These legacy protocols can be used to create security groups,
        # but they could be shown either with their passed protocol name,
        # or a canonical-ized version, depending on the neutron version.
        # So we check against a list of possible values.
        # TODO(haleyb): Remove once these legacy names are deprecated
        protocols = {constants.PROTO_NAME_IPV6_ICMP_LEGACY:
                     constants.PROTO_NAME_IPV6_ICMP,
                     constants.PROTO_NAME_ICMP:
                     constants.PROTO_NAME_IPV6_ICMP}
        for key, value in protocols.items():
            self._test_security_group_rule_legacy(
                protocol_list=[str(key), str(value)],
                protocol=str(key),
                direction=constants.INGRESS_DIRECTION,
                ethertype=self.ethertype)

    def _test_security_group_rule_legacy(self, protocol_list, **kwargs):
        sg_kwargs = {}
        if self.stateless_sg:
            sg_kwargs['stateful'] = False
        security_group = self.create_security_group(**sg_kwargs)
        security_group_rule = self.create_security_group_rule(
            security_group=security_group, **kwargs)
        observed_security_group_rule = self.client.show_security_group_rule(
            security_group_rule['id'])['security_group_rule']
        for key, value in kwargs.items():
            if key == 'protocol':
                self.assertIn(security_group_rule[key], protocol_list,
                              "{!r} does not match.".format(key))
                self.assertIn(observed_security_group_rule[key], protocol_list,
                              "{!r} does not match.".format(key))
            else:
                self.assertEqual(value, security_group_rule[key],
                                 "{!r} does not match.".format(key))
                self.assertEqual(value, observed_security_group_rule[key],
                                 "{!r} does not match.".format(key))


class StatefulSecGroupProtocolIPv6Test(BaseSecGroupProtocolIPv6Test):
    stateless_sg = False

    @decorators.idempotent_id('c7d17b41-3b4e-4add-bb3b-6af59baaaffa')
    def test_security_group_rule_protocol_legacy_icmpv6(self):
        self._test_security_group_rule_protocol_legacy_icmpv6()


class StatelessSecGroupProtocolIPv6Test(BaseSecGroupProtocolIPv6Test):
    required_extensions = ['security-group', 'stateful-security-group']
    stateless_sg = True

    @decorators.idempotent_id('a034814e-0fa5-4437-8e6f-0d2eebd668b3')
    def test_security_group_rule_protocol_legacy_icmpv6(self):
        self._test_security_group_rule_protocol_legacy_icmpv6()


class RbacSharedSecurityGroupTest(base.BaseAdminNetworkTest):

    force_tenant_isolation = True
    credentials = ['primary', 'alt', 'admin']
    required_extensions = ['security-group', 'rbac-security-groups']

    @classmethod
    def resource_setup(cls):
        super(RbacSharedSecurityGroupTest, cls).resource_setup()
        cls.client2 = cls.os_alt.network_client

    def _create_security_group(self):
        return self.create_security_group(
            name=data_utils.rand_name('test-sg'),
            project={'id': self.admin_client.project_id})

    def _make_admin_sg_shared_to_project_id(self, project_id):
        sg = self._create_security_group()
        rbac_policy = self.admin_client.create_rbac_policy(
            object_type='security_group',
            object_id=sg['id'],
            action='access_as_shared',
            target_tenant=project_id,
        )['rbac_policy']
        return {'security_group': sg, 'rbac_policy': rbac_policy}

    @decorators.idempotent_id('2a41eb8f-2a35-11e9-bae9-acde48001122')
    def test_policy_target_update(self):
        res = self._make_admin_sg_shared_to_project_id(
            self.client.project_id)
        # change to client2
        update_res = self.admin_client.update_rbac_policy(
            res['rbac_policy']['id'], target_tenant=self.client2.project_id)
        self.assertEqual(self.client2.project_id,
                         update_res['rbac_policy']['target_tenant'])
        # make sure everything else stayed the same
        res['rbac_policy'].pop('target_tenant')
        update_res['rbac_policy'].pop('target_tenant')
        self.assertEqual(res['rbac_policy'], update_res['rbac_policy'])

    @decorators.idempotent_id('2a619a8a-2a35-11e9-90d9-acde48001122')
    def test_port_presence_prevents_policy_rbac_policy_deletion(self):
        res = self._make_admin_sg_shared_to_project_id(
            self.client2.project_id)
        sg_id = res['security_group']['id']
        net = self.create_network(client=self.client2)
        port = self.client2.create_port(
            network_id=net['id'],
            security_groups=[sg_id])['port']

        # a port with shared sg should prevent the deletion of an
        # rbac-policy required for it to be shared
        with testtools.ExpectedException(exceptions.Conflict):
            self.admin_client.delete_rbac_policy(res['rbac_policy']['id'])

        # cleanup
        self.client2.delete_port(port['id'])
        self.admin_client.delete_rbac_policy(res['rbac_policy']['id'])

    @decorators.idempotent_id('2a81795c-2a35-11e9-9d86-acde48001122')
    def test_regular_client_shares_to_another_regular_client(self):
        # owned by self.admin_client
        sg = self._create_security_group()
        with testtools.ExpectedException(exceptions.NotFound):
            self.client.show_security_group(sg['id'])
        rbac_policy = self.admin_client.create_rbac_policy(
            object_type='security_group', object_id=sg['id'],
            action='access_as_shared',
            target_tenant=self.client.project_id)['rbac_policy']
        self.client.show_security_group(sg['id'])

        self.assertIn(rbac_policy,
                      self.admin_client.list_rbac_policies()['rbac_policies'])
        # ensure that 'client2' can't see the rbac-policy sharing the
        # sg to it because the rbac-policy belongs to 'client'
        self.assertNotIn(rbac_policy['id'], [p['id'] for p in
                         self.client2.list_rbac_policies()['rbac_policies']])

    @decorators.idempotent_id('2a9fd480-2a35-11e9-9cb6-acde48001122')
    def test_filter_fields(self):
        sg = self._create_security_group()
        self.admin_client.create_rbac_policy(
            object_type='security_group', object_id=sg['id'],
            action='access_as_shared', target_tenant=self.client2.project_id)
        field_args = (('id',), ('id', 'action'), ('object_type', 'object_id'),
                      ('project_id', 'target_tenant'))
        for fields in field_args:
            res = self.admin_client.list_rbac_policies(fields=fields)
            self.assertEqual(set(fields), set(res['rbac_policies'][0].keys()))

    @decorators.idempotent_id('2abf8f9e-2a35-11e9-85f7-acde48001122')
    def test_rbac_policy_show(self):
        res = self._make_admin_sg_shared_to_project_id(
            self.client.project_id)
        p1 = res['rbac_policy']
        p2 = self.admin_client.create_rbac_policy(
            object_type='security_group',
            object_id=res['security_group']['id'],
            action='access_as_shared',
            target_tenant='*')['rbac_policy']

        self.assertEqual(
            p1, self.admin_client.show_rbac_policy(p1['id'])['rbac_policy'])
        self.assertEqual(
            p2, self.admin_client.show_rbac_policy(p2['id'])['rbac_policy'])

    @decorators.idempotent_id('2adf6bd7-2a35-11e9-9c62-acde48001122')
    def test_filter_rbac_policies(self):
        sg = self._create_security_group()
        rbac_pol1 = self.admin_client.create_rbac_policy(
            object_type='security_group', object_id=sg['id'],
            action='access_as_shared',
            target_tenant=self.client2.project_id)['rbac_policy']
        rbac_pol2 = self.admin_client.create_rbac_policy(
            object_type='security_group', object_id=sg['id'],
            action='access_as_shared',
            target_tenant=self.admin_client.project_id)['rbac_policy']
        res1 = self.admin_client.list_rbac_policies(id=rbac_pol1['id'])[
            'rbac_policies']
        res2 = self.admin_client.list_rbac_policies(id=rbac_pol2['id'])[
            'rbac_policies']
        self.assertEqual(1, len(res1))
        self.assertEqual(1, len(res2))
        self.assertEqual(rbac_pol1['id'], res1[0]['id'])
        self.assertEqual(rbac_pol2['id'], res2[0]['id'])

    @decorators.idempotent_id('2aff3900-2a35-11e9-96b3-acde48001122')
    def test_regular_client_blocked_from_sharing_anothers_policy(self):
        sg = self._make_admin_sg_shared_to_project_id(
            self.client.project_id)['security_group']
        with testtools.ExpectedException(exceptions.BadRequest):
            self.client.create_rbac_policy(
                object_type='security_group', object_id=sg['id'],
                action='access_as_shared',
                target_tenant=self.client2.project_id)

        # make sure the rbac-policy is invisible to the tenant for which it's
        # being shared
        self.assertFalse(self.client.list_rbac_policies()['rbac_policies'])


class SecGroupSearchCriteriaTest(base.BaseSearchCriteriaTest):

    required_extensions = ['security-group']
    resource = 'security-group'

    @classmethod
    def resource_setup(cls):
        super(SecGroupSearchCriteriaTest, cls).resource_setup()
        cls.security_group = cls.create_security_group()
        for name in cls.resource_names:
            cls.create_security_group(name=name)

    @decorators.idempotent_id('0064aa80-8a29-442d-a8de-9101af8210fa')
    def test_list_sorts_by_name_asc(self):
        self._test_list_sorts_asc()

    @decorators.idempotent_id('35e86832-53cd-4e63-97ec-31a2413da591')
    def test_list_sorts_by_name_desc(self):
        self._test_list_sorts_desc()

    @decorators.idempotent_id('b9654cdc-80bc-43f8-844e-dfe88fd2f125')
    def test_list_pagination(self):
        self._test_list_pagination()

    @decorators.idempotent_id('5c78bd57-e6e9-4e71-a05c-9c4082a3f139')
    def test_list_no_pagination_limit_0(self):
        self._test_list_no_pagination_limit_0()


class SecGroupNormalizedCidrTest(base.BaseNetworkTest):

    required_extensions = ['security-group', 'security-groups-normalized-cidr']

    @decorators.idempotent_id('f87bb108-205c-4f06-a378-81a26f71b829')
    def test_normalized_cidr_in_rule(self):
        security_group = self.create_security_group()
        rule = self.create_security_group_rule(
            security_group=security_group,
            direction=constants.INGRESS_DIRECTION,
            remote_ip_prefix='10.0.0.34/24')
        self.assertEqual('10.0.0.0/24', rule['normalized_cidr'])
        self.assertEqual('10.0.0.34/24', rule['remote_ip_prefix'])

        rule = self.create_security_group_rule(
            security_group=security_group,
            remote_group_id=security_group['id'],
            direction=constants.INGRESS_DIRECTION)
        self.assertIsNone(rule['normalized_cidr'])
        self.assertIsNone(rule['remote_ip_prefix'])
