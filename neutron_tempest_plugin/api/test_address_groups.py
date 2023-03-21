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
from oslo_log import log
from tempest.lib.common.utils import data_utils
from tempest.lib import decorators
from tempest.lib import exceptions
import testtools

from neutron_tempest_plugin.api import base
from neutron_tempest_plugin.api import base_security_groups

LOG = log.getLogger(__name__)


ADDRESS_GROUP_NAME = 'test-address-group'


class AddressGroupTest(base.BaseAdminNetworkTest):

    credentials = ['primary', 'admin']
    required_extensions = ['address-group']

    @decorators.idempotent_id('496fef1b-22ce-483b-ab93-d28bf46954b0')
    def test_address_group_lifecycle(self):
        ag_description = "Test AG description"
        ag_name = data_utils.rand_name(ADDRESS_GROUP_NAME)
        addresses = ['10.10.10.3/32', '192.168.0.10/24', '2001:db8::f00/64']
        expected_addresses = [
            '10.10.10.3/32', '192.168.0.0/24', '2001:db8::/64']
        ag = self.create_address_group(
            description=ag_description,
            name=ag_name,
            addresses=addresses)
        self.assertEqual(ag_description, ag['description'])
        self.assertEqual(ag_name, ag['name'])
        self.assertListEqual(
            sorted(expected_addresses), sorted(ag['addresses']))

        new_description = 'New AG description'
        updated_ag = self.client.update_address_group(
            ag['id'], description=new_description)['address_group']
        self.assertEqual(new_description, updated_ag['description'])
        self.assertEqual(ag_name, updated_ag['name'])
        self.assertListEqual(
            sorted(expected_addresses), sorted(updated_ag['addresses']))

        self.client.delete_address_group(ag['id'])
        with testtools.ExpectedException(exceptions.NotFound):
            self.client.show_address_group(ag['id'])

    @decorators.idempotent_id('8a42029a-40eb-4b44-a7cf-38500046f9b8')
    def test_address_group_create_with_wrong_address(self):
        with testtools.ExpectedException(exceptions.BadRequest):
            self.create_address_group(
                name=data_utils.rand_name(ADDRESS_GROUP_NAME),
                addresses=['10.20.30.40'])

        with testtools.ExpectedException(exceptions.BadRequest):
            self.create_address_group(
                name=data_utils.rand_name(ADDRESS_GROUP_NAME),
                addresses=['this is bad IP address'])

    @decorators.idempotent_id('27c03921-bb12-4b9a-b32e-7083bc90ff1f')
    def test_edit_addresses_in_address_group(self):
        addresses = ['10.10.10.3/32', '192.168.0.10/24', '2001:db8::f00/64']
        expected_addresses = [
            '10.10.10.3/32', '192.168.0.0/24', '2001:db8::/64']
        ag = self.create_address_group(
            name=data_utils.rand_name(ADDRESS_GROUP_NAME),
            addresses=addresses)
        self.assertListEqual(
            sorted(expected_addresses), sorted(ag['addresses']))

        added_addresses = ['10.20.30.40/32']
        self.client.add_addresses_to_address_group(
            ag['id'], addresses=added_addresses)
        updated_ag = self.client.show_address_group(ag['id'])['address_group']
        expected_addresses += added_addresses
        self.assertListEqual(
            sorted(expected_addresses), sorted(updated_ag['addresses']))

        removed_addresses = [expected_addresses.pop(0)]
        self.client.remove_addresses_from_address_group(
            ag['id'], addresses=removed_addresses)
        updated_ag = self.client.show_address_group(ag['id'])['address_group']
        self.assertListEqual(
            sorted(expected_addresses), sorted(updated_ag['addresses']))

    @decorators.idempotent_id('feec6747-b4b8-49e3-8cff-817d3f097f2c')
    def test_add_wrong_address_to_address_group(self):
        addresses = ['10.10.10.3/32', '192.168.0.10/24', '2001:db8::f00/64']
        expected_addresses = [
            '10.10.10.3/32', '192.168.0.0/24', '2001:db8::/64']
        ag = self.create_address_group(
            name=data_utils.rand_name(ADDRESS_GROUP_NAME),
            addresses=addresses)
        self.assertListEqual(
            sorted(expected_addresses), sorted(ag['addresses']))
        with testtools.ExpectedException(exceptions.BadRequest):
            self.client.add_addresses_to_address_group(
                ag['id'], addresses=['this is bad IP address'])
        updated_ag = self.client.show_address_group(ag['id'])['address_group']
        self.assertListEqual(
            sorted(expected_addresses), sorted(updated_ag['addresses']))

    @decorators.idempotent_id('74f6fd4c-257b-4725-887b-470e96960e24')
    def test_remove_wrong_address_from_address_group(self):
        addresses = ['10.10.10.3/32', '192.168.0.10/24', '2001:db8::f00/64']
        expected_addresses = [
            '10.10.10.3/32', '192.168.0.0/24', '2001:db8::/64']
        ag = self.create_address_group(
            name=data_utils.rand_name(ADDRESS_GROUP_NAME),
            addresses=addresses)
        self.assertListEqual(
            sorted(expected_addresses), sorted(ag['addresses']))
        with testtools.ExpectedException(exceptions.NotFound):
            self.client.remove_addresses_from_address_group(
                ag['id'], addresses=['10.200.200.200'])
        updated_ag = self.client.show_address_group(ag['id'])['address_group']
        self.assertListEqual(
            sorted(expected_addresses), sorted(updated_ag['addresses']))

        with testtools.ExpectedException(exceptions.BadRequest):
            self.client.remove_addresses_from_address_group(
                ag['id'], addresses=['this is bad IP address'])
        updated_ag = self.client.show_address_group(ag['id'])['address_group']
        self.assertListEqual(
            sorted(expected_addresses), sorted(updated_ag['addresses']))


class RbacSharedAddressGroupTest(base.BaseAdminNetworkTest):

    force_tenant_isolation = True
    credentials = ['primary', 'alt', 'admin']
    required_extensions = ['security-group', 'address-group',
                           'rbac-address-group']

    @classmethod
    def resource_setup(cls):
        super(RbacSharedAddressGroupTest, cls).resource_setup()
        cls.client2 = cls.os_alt.network_client

    def _create_address_group(self, is_admin=False, **kwargs):
        name = data_utils.rand_name(ADDRESS_GROUP_NAME)
        return self.create_address_group(name=name, is_admin=is_admin,
                                         **kwargs)

    def _make_admin_ag_shared_to_project_id(self, project_id):
        ag = self._create_address_group(is_admin=True)
        rbac_policy = self.admin_client.create_rbac_policy(
            object_type='address_group',
            object_id=ag['id'],
            action='access_as_shared',
            target_tenant=project_id,
        )['rbac_policy']
        return {'address_group': ag, 'rbac_policy': rbac_policy}

    @decorators.idempotent_id('95f59a88-c47e-4dd9-a231-85f1782753a7')
    def test_policy_target_update(self):
        res = self._make_admin_ag_shared_to_project_id(
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

    @decorators.idempotent_id('35a214c9-5c99-468f-9242-34d0529cabfa')
    def test_secgrprule_presence_prevents_policy_rbac_policy_deletion(self):
        res = self._make_admin_ag_shared_to_project_id(
            self.client2.project_id)
        ag_id = res['address_group']['id']
        security_group = self.create_security_group(client=self.client2)
        protocol = random.choice(list(base_security_groups.V4_PROTOCOL_NAMES))
        sec_grp_rule = self.create_security_group_rule(
            security_group=security_group,
            client=self.client2, protocol=protocol,
            direction=constants.INGRESS_DIRECTION,
            remote_address_group_id=ag_id)

        # a port with shared sg should prevent the deletion of an
        # rbac-policy required for it to be shared
        with testtools.ExpectedException(exceptions.Conflict):
            self.admin_client.delete_rbac_policy(res['rbac_policy']['id'])

        # cleanup
        self.client2.delete_security_group_rule(sec_grp_rule['id'])
        self.admin_client.delete_rbac_policy(res['rbac_policy']['id'])

    @decorators.idempotent_id('c89db8d4-0b52-4072-ac7e-672860491843')
    def test_regular_client_shares_to_another_regular_client(self):
        # owned by self.admin_client
        ag = self._create_address_group(is_admin=True)
        with testtools.ExpectedException(exceptions.NotFound):
            self.client.show_address_group(ag['id'])
        rbac_policy = self.admin_client.create_rbac_policy(
            object_type='address_group', object_id=ag['id'],
            action='access_as_shared',
            target_tenant=self.client.project_id)['rbac_policy']
        self.client.show_address_group(ag['id'])

        self.assertIn(rbac_policy,
                      self.admin_client.list_rbac_policies()['rbac_policies'])
        # ensure that 'client2' can't see the rbac-policy sharing the
        # ag to it because the rbac-policy belongs to 'client'
        self.assertNotIn(rbac_policy['id'], [p['id'] for p in
                         self.client2.list_rbac_policies()['rbac_policies']])

    @decorators.idempotent_id('55a9fbb6-3333-48e8-90e4-11ab2a49567b')
    def test_filter_fields(self):
        ag = self._create_address_group()
        self.admin_client.create_rbac_policy(
            object_type='address_group', object_id=ag['id'],
            action='access_as_shared', target_tenant=self.client2.project_id)
        field_args = (('id',), ('id', 'action'), ('object_type', 'object_id'),
                      ('project_id', 'target_tenant'))
        for fields in field_args:
            res = self.admin_client.list_rbac_policies(fields=fields)
            self.assertEqual(set(fields), set(res['rbac_policies'][0].keys()))

    @decorators.idempotent_id('20b2706b-1cea-4724-ab72-d7452ecb1fc4')
    def test_rbac_policy_show(self):
        res = self._make_admin_ag_shared_to_project_id(
            self.client.project_id)
        p1 = res['rbac_policy']
        p2 = self.admin_client.create_rbac_policy(
            object_type='address_group',
            object_id=res['address_group']['id'],
            action='access_as_shared',
            target_tenant='*')['rbac_policy']

        self.assertEqual(
            p1, self.admin_client.show_rbac_policy(p1['id'])['rbac_policy'])
        self.assertEqual(
            p2, self.admin_client.show_rbac_policy(p2['id'])['rbac_policy'])

    @decorators.idempotent_id('774fc038-486c-4507-ab04-c5aac0fca5ab')
    def test_filter_rbac_policies(self):
        ag = self._create_address_group()
        rbac_pol1 = self.admin_client.create_rbac_policy(
            object_type='address_group', object_id=ag['id'],
            action='access_as_shared',
            target_tenant=self.client2.project_id)['rbac_policy']
        rbac_pol2 = self.admin_client.create_rbac_policy(
            object_type='address_group', object_id=ag['id'],
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

    @decorators.idempotent_id('a0f3a01a-e2c7-47d6-9385-0cd7a7f0c996')
    def test_regular_client_blocked_from_sharing_anothers_policy(self):
        ag = self._make_admin_ag_shared_to_project_id(
            self.client.project_id)['address_group']
        with testtools.ExpectedException(exceptions.BadRequest):
            self.client.create_rbac_policy(
                object_type='address_group', object_id=ag['id'],
                action='access_as_shared',
                target_tenant=self.client2.project_id)

        # make sure the rbac-policy is invisible to the tenant for which it's
        # being shared
        self.assertFalse(self.client.list_rbac_policies()['rbac_policies'])

    @decorators.idempotent_id('f39e32d9-4733-48ec-b550-07f0ec4998a9')
    def test_regular_client_blocked_from_updating_shared_address_group(self):
        # owned by self.admin_client
        ag = self._create_address_group(is_admin=True)
        self.admin_client.create_rbac_policy(
            object_type='address_group', object_id=ag['id'],
            action='access_as_shared',
            target_tenant=self.client.project_id)['rbac_policy']
        self.client.show_address_group(ag['id'])
        with testtools.ExpectedException(exceptions.NotFound):
            self.client.update_address_group(ag['id'], name='new_name')
