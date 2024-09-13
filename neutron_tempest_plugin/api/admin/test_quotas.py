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

from tempest.common import utils
from tempest.lib import decorators
from tempest.lib import exceptions as lib_exc

from neutron_tempest_plugin.api import base
from neutron_tempest_plugin import config

CONF = config.CONF


class QuotasTestBase(base.BaseAdminNetworkTest):

    required_extensions = ['quotas']

    @classmethod
    def resource_setup(cls):
        super(QuotasTestBase, cls).resource_setup()

    def _setup_quotas(self, project_id, **new_quotas):
        # Change quotas for tenant
        quota_set = self.admin_client.update_quotas(project_id,
                                                    **new_quotas)
        self.addCleanup(self._cleanup_quotas, project_id)
        return quota_set

    def _cleanup_quotas(self, project_id):
        # Try to clean up the resources. If it fails, then
        # assume that everything was already deleted, so
        # it is OK to continue.
        try:
            self.admin_client.reset_quotas(project_id)
        except lib_exc.NotFound:
            pass

    def _create_network(self, project_id):
        network = self.create_network(client=self.admin_client,
                                      tenant_id=project_id)
        self.addCleanup(self.admin_client.delete_network,
                        network['id'])
        return network

    def _create_port(self, **kwargs):
        port = self.admin_client.create_port(**kwargs)['port']
        self.addCleanup(self.admin_client.delete_port,
                        port['id'])
        return port


class QuotasTest(QuotasTestBase):
    """Test the Neutron API of Quotas.

    Tests the following operations in the Neutron API using the REST client for
    Neutron:

        list quotas for tenants who have non-default quota values
        show quotas for a specified tenant
        show detail quotas for a specified tenant
        update quotas for a specified tenant
        reset quotas to default values for a specified tenant

    v2.0 of the API is assumed.
    It is also assumed that the per-tenant quota extension API is configured
    in /etc/neutron/neutron.conf as follows:

        quota_driver = neutron.db.driver.DbQuotaDriver
    """

    @decorators.attr(type='gate')
    @decorators.idempotent_id('2390f766-836d-40ef-9aeb-e810d78207fb')
    def test_quotas(self):
        tenant_id = self.create_project()['id']
        new_quotas = {'network': 0, 'security_group': 0}

        # Change quotas for tenant
        quota_set = self._setup_quotas(tenant_id, force=True, **new_quotas)
        for key, value in new_quotas.items():
            self.assertEqual(value, quota_set[key])

        # Confirm our tenant is listed among tenants with non default quotas
        non_default_quotas = self.admin_client.list_quotas()
        found = False
        for qs in non_default_quotas['quotas']:
            if qs['tenant_id'] == tenant_id:
                self.assertEqual(tenant_id, qs['project_id'])
                found = True
        self.assertTrue(found)

        # Confirm from API quotas were changed as requested for tenant
        quota_set = self.admin_client.show_quotas(tenant_id)
        quota_set = quota_set['quota']
        for key, value in new_quotas.items():
            self.assertEqual(value, quota_set[key])

        # Reset quotas to default and confirm
        self.admin_client.reset_quotas(tenant_id)
        non_default_quotas = self.admin_client.list_quotas()
        for q in non_default_quotas['quotas']:
            self.assertNotEqual(tenant_id, q['tenant_id'])

    @decorators.idempotent_id('43d01327-d8be-4773-a8f0-1d2e9664fda2')
    @decorators.attr(type='gate')
    @utils.requires_ext(extension='quota-check-limit-default',
                        service='network')
    def test_quotas_force_false(self):
        project_id = self.create_project()['id']
        self._create_network(project_id)

        new_quotas = {'network': 0}
        # force=false (by default)
        self.assertRaises(lib_exc.BadRequest, self.admin_client.update_quotas,
                          project_id, **new_quotas)

        new_quotas['network'] = 100
        quota_set = self._setup_quotas(project_id, **new_quotas)
        self.assertEqual(new_quotas['network'], quota_set['network'])

    @decorators.idempotent_id('e974b5ba-090a-452c-a578-f9710151d9fc')
    @decorators.attr(type='gate')
    @utils.requires_ext(extension="quota_details", service="network")
    def test_detail_quotas(self):
        tenant_id = self.create_project()['id']
        new_quotas = {'network': {'used': 1, 'limit': 2, 'reserved': 0},
                      'port': {'used': 1, 'limit': 2, 'reserved': 0}}

        # create test resources
        network = self._create_network(tenant_id)
        post_body = {"network_id": network['id'],
                     "tenant_id": tenant_id}

        # NOTE(lucasagomes): Some backends such as OVN will create a port
        # to be used by the metadata agent upon creating a network. In
        # order to make this test more generic we need to calculate the
        # number of expected used ports after the network is created and
        # prior for the port being created
        ports = self.admin_client.list_ports(tenant_id=tenant_id)
        new_quotas['port']['used'] += len(ports['ports'])

        self._create_port(**post_body)

        # update quota limit for tenant
        new_quota = {'network': new_quotas['network']['limit'], 'port':
                     new_quotas['port']['limit']}
        quota_set = self._setup_quotas(tenant_id, **new_quota)

        # confirm from extended API quotas were changed
        # as requested for tenant
        quota_set = self.admin_client.show_details_quota(tenant_id)
        quota_set = quota_set['quota']
        for key, value in new_quotas.items():
            self.assertEqual(new_quotas[key]['limit'],
                             quota_set[key]['limit'])
            self.assertEqual(new_quotas[key]['reserved'],
                             quota_set[key]['reserved'])
            self.assertEqual(new_quotas[key]['used'],
                             quota_set[key]['used'])

        # validate 'default' action for old extension
        quota_limit = self.admin_client.show_quotas(tenant_id)['quota']
        for key, value in new_quotas.items():
            self.assertEqual(new_quotas[key]['limit'], quota_limit[key])
