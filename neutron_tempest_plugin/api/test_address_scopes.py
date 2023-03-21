# Copyright (c) 2015 Red Hat, Inc.
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
import testtools

from tempest.common import utils
from tempest.lib.common.utils import data_utils
from tempest.lib import decorators
from tempest.lib import exceptions as lib_exc

from neutron_tempest_plugin.api import base


ADDRESS_SCOPE_NAME = 'smoke-address-scope'


class AddressScopeTestBase(base.BaseAdminNetworkTest):

    required_extensions = ['address-scope']

    def _create_address_scope(self, is_admin=False, **kwargs):
        name = data_utils.rand_name(ADDRESS_SCOPE_NAME)
        return self.create_address_scope(name=name, is_admin=is_admin,
                                         **kwargs)

    def _test_update_address_scope_helper(self, is_admin=False, shared=None):
        address_scope = self._create_address_scope(is_admin=is_admin,
                                                   ip_version=4)

        if is_admin:
            client = self.admin_client
        else:
            client = self.client

        kwargs = {'name': 'new_name'}
        if shared is not None:
            kwargs['shared'] = shared

        client.update_address_scope(address_scope['id'], **kwargs)
        body = client.show_address_scope(address_scope['id'])
        address_scope = body['address_scope']
        self.assertEqual('new_name', address_scope['name'])
        return address_scope


class AddressScopeTest(AddressScopeTestBase):

    @decorators.idempotent_id('045f9294-8b1a-4848-b6a8-edf1b41e9d06')
    def test_tenant_create_list_address_scope(self):
        address_scope = self._create_address_scope(ip_version=4)
        body = self.client.list_address_scopes()
        returned_address_scopes = body['address_scopes']
        self.assertIn(address_scope['id'],
                      [a_s['id'] for a_s in returned_address_scopes],
                      "Created address scope id should be in the list")
        self.assertIn(address_scope['name'],
                      [a_s['name'] for a_s in returned_address_scopes],
                      "Created address scope name should be in the list")

    @decorators.idempotent_id('85e0326b-4c75-4b92-bd6e-7c7de6aaf05c')
    def test_show_address_scope(self):
        address_scope = self._create_address_scope(ip_version=4)
        body = self.client.show_address_scope(
            address_scope['id'])
        returned_address_scope = body['address_scope']
        self.assertEqual(address_scope['id'], returned_address_scope['id'])
        self.assertEqual(address_scope['name'],
                         returned_address_scope['name'])
        self.assertFalse(returned_address_scope['shared'])

    @decorators.idempotent_id('bbd57364-6d57-48e4-b0f1-8b9a998f5e06')
    @utils.requires_ext(extension="project-id", service="network")
    def test_show_address_scope_project_id(self):
        address_scope = self._create_address_scope(ip_version=4)
        body = self.client.show_address_scope(address_scope['id'])
        show_addr_scope = body['address_scope']
        self.assertIn('project_id', show_addr_scope)
        self.assertIn('tenant_id', show_addr_scope)
        self.assertEqual(self.client.project_id, show_addr_scope['project_id'])
        self.assertEqual(self.client.project_id, show_addr_scope['tenant_id'])

    @decorators.idempotent_id('85a259b2-ace6-4e32-9657-a9a392b452aa')
    def test_tenant_update_address_scope(self):
        self._test_update_address_scope_helper()

    @decorators.idempotent_id('22b3b600-72a8-4b60-bc94-0f29dd6271df')
    def test_delete_address_scope(self):
        address_scope = self._create_address_scope(ip_version=4)
        self.client.delete_address_scope(address_scope['id'])
        self.assertRaises(lib_exc.NotFound, self.client.show_address_scope,
                          address_scope['id'])

    @decorators.idempotent_id('5a06c287-8036-4d04-9d78-def8e06d43df')
    def test_admin_create_shared_address_scope(self):
        address_scope = self._create_address_scope(is_admin=True, shared=True,
                                                   ip_version=4)
        body = self.admin_client.show_address_scope(
            address_scope['id'])
        returned_address_scope = body['address_scope']
        self.assertEqual(address_scope['name'],
                         returned_address_scope['name'])
        self.assertTrue(returned_address_scope['shared'])

    @decorators.idempotent_id('e9e1ccdd-9ccd-4076-9503-71820529508b')
    def test_admin_update_shared_address_scope(self):
        address_scope = self._test_update_address_scope_helper(is_admin=True,
                                                               shared=True)
        self.assertTrue(address_scope['shared'])


class RbacAddressScopeTest(AddressScopeTestBase):

    force_tenant_isolation = True
    credentials = ['primary', 'alt', 'admin']
    required_extensions = ['address-scope', 'rbac-address-scope']

    @classmethod
    def resource_setup(cls):
        super(RbacAddressScopeTest, cls).resource_setup()
        cls.client2 = cls.os_alt.network_client

    def _make_admin_as_shared_to_project_id(self, project_id):
        a_s = self._create_address_scope(ip_version=4, is_admin=True)
        rbac_policy = self.admin_client.create_rbac_policy(
            object_type='address_scope',
            object_id=a_s['id'],
            action='access_as_shared',
            target_tenant=project_id,
        )['rbac_policy']
        return {'address_scope': a_s, 'rbac_policy': rbac_policy}

    @decorators.idempotent_id('038e999b-cd4b-4021-a9ff-ebb734f6e056')
    def test_policy_target_update(self):
        res = self._make_admin_as_shared_to_project_id(
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

    @decorators.idempotent_id('798ac6c6-96cc-49ce-ba5c-c6eced7a09d3')
    def test_subnet_pool_presence_prevents_rbac_policy_deletion(self):
        res = self._make_admin_as_shared_to_project_id(
            self.client2.project_id)
        snp = self.create_subnetpool(
            data_utils.rand_name("rbac-address-scope"),
            default_prefixlen=24, prefixes=['10.0.0.0/8'],
            address_scope_id=res['address_scope']['id'],
            client=self.client2
        )
        self.addCleanup(
            self.admin_client.delete_rbac_policy,
            res['rbac_policy']['id']
        )
        self.addCleanup(self.client2.delete_subnetpool, snp['id'])

        # a port with shared sg should prevent the deletion of an
        # rbac-policy required for it to be shared
        with testtools.ExpectedException(lib_exc.Conflict):
            self.admin_client.delete_rbac_policy(res['rbac_policy']['id'])

    @decorators.idempotent_id('57da6ba2-6329-49c8-974c-9858fe187136')
    def test_regular_client_shares_to_another_regular_client(self):
        # owned by self.admin_client
        a_s = self._create_address_scope(ip_version=4, is_admin=True)
        with testtools.ExpectedException(lib_exc.NotFound):
            self.client.show_address_scope(a_s['id'])
        rbac_policy = self.admin_client.create_rbac_policy(
            object_type='address_scope', object_id=a_s['id'],
            action='access_as_shared',
            target_tenant=self.client.project_id)['rbac_policy']
        self.client.show_address_scope(a_s['id'])

        self.assertIn(rbac_policy,
                      self.admin_client.list_rbac_policies()['rbac_policies'])
        # ensure that 'client2' can't see the rbac-policy sharing the
        # as to it because the rbac-policy belongs to 'client'
        self.assertNotIn(rbac_policy['id'], [p['id'] for p in
                         self.client2.list_rbac_policies()['rbac_policies']])

    @decorators.idempotent_id('051248e7-d66f-4c69-9022-2b73ee5b9e73')
    def test_filter_fields(self):
        a_s = self._create_address_scope(ip_version=4)
        self.admin_client.create_rbac_policy(
            object_type='address_scope', object_id=a_s['id'],
            action='access_as_shared', target_tenant=self.client2.project_id)
        field_args = (('id',), ('id', 'action'), ('object_type', 'object_id'),
                      ('project_id', 'target_tenant'))
        for fields in field_args:
            res = self.admin_client.list_rbac_policies(fields=fields)
            self.assertEqual(set(fields), set(res['rbac_policies'][0].keys()))

    @decorators.idempotent_id('19cbd62e-c6c3-4495-98b9-b9c6c6c9c127')
    def test_rbac_policy_show(self):
        res = self._make_admin_as_shared_to_project_id(
            self.client.project_id)
        p1 = res['rbac_policy']
        p2 = self.admin_client.create_rbac_policy(
            object_type='address_scope',
            object_id=res['address_scope']['id'],
            action='access_as_shared',
            target_tenant='*')['rbac_policy']

        self.assertEqual(
            p1, self.admin_client.show_rbac_policy(p1['id'])['rbac_policy'])
        self.assertEqual(
            p2, self.admin_client.show_rbac_policy(p2['id'])['rbac_policy'])

    @decorators.idempotent_id('88852ba0-8546-4ce7-8f79-4a9c840c881d')
    def test_filter_rbac_policies(self):
        a_s = self._create_address_scope(ip_version=4)
        rbac_pol1 = self.admin_client.create_rbac_policy(
            object_type='address_scope', object_id=a_s['id'],
            action='access_as_shared',
            target_tenant=self.client2.project_id)['rbac_policy']
        rbac_pol2 = self.admin_client.create_rbac_policy(
            object_type='address_scope', object_id=a_s['id'],
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

    @decorators.idempotent_id('222a638d-819e-41a7-a3fe-550265c06e79')
    def test_regular_client_blocked_from_sharing_anothers_policy(self):
        a_s = self._make_admin_as_shared_to_project_id(
            self.client.project_id)['address_scope']
        with testtools.ExpectedException(lib_exc.BadRequest):
            self.client.create_rbac_policy(
                object_type='address_scope', object_id=a_s['id'],
                action='access_as_shared',
                target_tenant=self.client2.project_id)

        # make sure the rbac-policy is invisible to the tenant for which it's
        # being shared
        self.assertFalse(self.client.list_rbac_policies()['rbac_policies'])
