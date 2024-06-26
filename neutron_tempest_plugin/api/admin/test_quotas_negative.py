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
from tempest.common import utils
from tempest.lib.common.utils import data_utils
from tempest.lib import decorators
from tempest.lib import exceptions as lib_exc

from neutron_tempest_plugin.api.admin import test_quotas
from neutron_tempest_plugin import config

CONF = config.CONF


class QuotasAdminNegativeTestJSON(test_quotas.QuotasTestBase):

    @decorators.attr(type='negative')
    @decorators.idempotent_id('952f9b24-9156-4bdc-90f3-682a3d4302f0')
    def test_create_network_when_quotas_is_full(self):
        tenant_id = self.create_project()['id']
        new_quotas = {'network': 1}
        self._setup_quotas(tenant_id, **new_quotas)

        net_args = {'tenant_id': tenant_id}
        net = self.admin_client.create_network(**net_args)['network']
        self.addCleanup(self.admin_client.delete_network, net['id'])

        self.assertRaises(lib_exc.Conflict,
                          self.admin_client.create_network, **net_args)

    @decorators.attr(type='negative')
    @decorators.idempotent_id('9f676a6e-d729-428b-adcd-4de2867c50e6')
    def test_set_network_quota_lower_than_networks_amount(self):
        tenant_id = self.create_project()['id']
        high_quota = 3
        low_quota = 1
        new_quotas = {'network': high_quota}
        self._setup_quotas(tenant_id, **new_quotas)
        for _ in range(high_quota - 1):
            self._create_network(tenant_id)
        # TODO(mblue): remove check_limit=True when it is default
        new_quotas.update({'network': low_quota, 'check_limit': True})

        self.assertRaises(lib_exc.BadRequest,
                          self.admin_client.update_quotas,
                          tenant_id, **new_quotas)

    @decorators.attr(type='negative')
    @decorators.idempotent_id('0b7f99e3-9f77-45ce-9a89-b39a184de618')
    def test_create_subnet_when_quotas_is_full(self):
        tenant_id = self.create_project()['id']
        new_quotas = {'subnet': 1}
        self._setup_quotas(tenant_id, **new_quotas)

        net_args = {'tenant_id': tenant_id}
        net = self.admin_client.create_network(**net_args)['network']
        self.addCleanup(self.admin_client.delete_network, net['id'])

        subnet_args = {'tenant_id': tenant_id,
                       'network_id': net['id'],
                       'cidr': '10.0.0.0/24',
                       'ip_version': '4'}
        subnet = self.admin_client.create_subnet(**subnet_args)['subnet']
        self.addCleanup(self.admin_client.delete_subnet, subnet['id'])

        subnet_args['cidr'] = '10.1.0.0/24'
        self.assertRaises(lib_exc.Conflict,
                          self.admin_client.create_subnet, **subnet_args)

    @decorators.attr(type='negative')
    @decorators.idempotent_id('fe20d9f9-346c-4a20-bbfa-d9ca390f4dc6')
    def test_create_port_when_quotas_is_full(self):
        tenant_id = self.create_project()['id']
        net_args = {'tenant_id': tenant_id}
        net = self.admin_client.create_network(**net_args)['network']
        self.addCleanup(self.admin_client.delete_network, net['id'])

        subnet_args = {'tenant_id': tenant_id,
                       'network_id': net['id'],
                       'enable_dhcp': False,
                       'cidr': '10.0.0.0/24',
                       'ip_version': '4'}
        subnet = self.admin_client.create_subnet(**subnet_args)['subnet']
        self.addCleanup(self.admin_client.delete_subnet, subnet['id'])

        ports = self.admin_client.list_ports(tenant_id=tenant_id)
        quota_limit = len(ports['ports']) + 1
        new_quotas = {'port': quota_limit}
        self._setup_quotas(tenant_id, **new_quotas)

        port_args = {'tenant_id': tenant_id,
                     'network_id': net['id']}
        port = self.admin_client.create_port(**port_args)['port']
        self.addCleanup(self.admin_client.delete_port, port['id'])

        self.assertRaises(lib_exc.Conflict,
                          self.admin_client.create_port, **port_args)

    @decorators.attr(type='negative')
    @decorators.idempotent_id('bb1e9c3c-7e6f-41f1-b579-63dbc655ecb7')
    @utils.requires_ext(extension="router", service="network")
    def test_create_router_when_quotas_is_full(self):
        tenant_id = self.create_project()['id']
        new_quotas = {'router': 1}
        self._setup_quotas(tenant_id, **new_quotas)

        name = data_utils.rand_name('test_router')
        router_args = {'tenant_id': tenant_id}
        router = self.admin_client.create_router(
            name, True, **router_args)['router']
        self.addCleanup(self.admin_client.delete_router, router['id'])

        self.assertRaises(lib_exc.Conflict,
                          self.admin_client.create_router,
                          name, True, **router_args)

    @decorators.attr(type='negative')
    @decorators.idempotent_id('5c924ff7-b7a9-474f-92a3-dbe0f976ec13')
    @utils.requires_ext(extension="security-group", service="network")
    def test_create_security_group_when_quotas_is_full(self):
        project = self.create_project()

        # Set quotas to allow to create only one more security group
        security_groups = self.admin_client.list_security_groups(
            tenant_id=project['id'])['security_groups']
        self._setup_quotas(project['id'],
                           security_group=len(security_groups) + 1)

        self.create_security_group(project=project)
        self.assertRaises(lib_exc.Conflict, self.create_security_group,
                          project=project)

    @decorators.attr(type='negative')
    @decorators.idempotent_id('b7143480-6118-4ed4-be38-1b6f15f30d05')
    @utils.requires_ext(extension="security-group", service="network")
    def test_create_security_group_rule_when_quotas_is_full(self):
        project = self.create_project()
        security_group = self.create_security_group(project=project)

        # Set quotas to allow to create only one more security group rule
        security_group_rules = self.admin_client.list_security_group_rules(
            tenant_id=project['id'])['security_group_rules']
        self._setup_quotas(project['id'],
                           security_group_rule=len(security_group_rules) + 1)

        self.create_security_group_rule(
            project=project, security_group=security_group,
            direction=constants.INGRESS_DIRECTION)
        self.assertRaises(lib_exc.Conflict,
                          self.create_security_group_rule,
                          project=project, security_group=security_group,
                          direction=constants.EGRESS_DIRECTION)

    @decorators.attr(type='negative')
    @decorators.idempotent_id('d00fe5bb-9db8-4e1a-9c31-490f52897e6f')
    @utils.requires_ext(extension="router", service="network")
    def test_create_floatingip_when_quotas_is_full(self):
        tenant_id = self.create_project()['id']
        new_quotas = {'floatingip': 1}
        self._setup_quotas(tenant_id, **new_quotas)

        self.create_floatingip(client=self.admin_client, tenant_id=tenant_id)

        self.assertRaises(lib_exc.Conflict, self.create_floatingip,
                          client=self.admin_client, tenant_id=tenant_id)
