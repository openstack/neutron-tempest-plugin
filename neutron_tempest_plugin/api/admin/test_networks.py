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

from oslo_utils import uuidutils
from tempest.common import utils
from tempest.lib import decorators
from tempest.lib import exceptions as lib_exc

from neutron_tempest_plugin.api import base
from neutron_tempest_plugin import config


class NetworksTestAdmin(base.BaseAdminNetworkTest):

    @decorators.idempotent_id('d3c76044-d067-4cb0-ae47-8cdd875c7f67')
    @utils.requires_ext(extension="project-id", service="network")
    def test_create_network_with_project(self):
        project_id = self.client.project_id  # non-admin

        name = 'admin-created-with-project_id'
        network = self.create_network(name, project_id=project_id,
                                      client=self.admin_client)
        self.assertEqual(name, network['name'])
        self.assertEqual(project_id, network['project_id'])
        self.assertEqual(project_id, network['tenant_id'])

        observed_network = self.client.list_networks(
            id=network['id'])['networks'][0]
        self.assertEqual(name, observed_network['name'])
        self.assertEqual(project_id, observed_network['project_id'])
        self.assertEqual(project_id, observed_network['tenant_id'])

    @decorators.idempotent_id('8d21aaca-4364-4eb9-8b79-44b4fff6373b')
    @utils.requires_ext(extension="project-id", service="network")
    def test_create_network_with_project_and_tenant(self):
        project_id = self.client.project_id  # non-admin

        name = 'created-with-project-and-tenant'
        network = self.create_network(name, project_id=project_id,
                                      tenant_id=project_id,
                                      client=self.admin_client)
        self.assertEqual(name, network['name'])
        self.assertEqual(project_id, network['project_id'])
        self.assertEqual(project_id, network['tenant_id'])

        observed_network = self.client.list_networks(
            id=network['id'])['networks'][0]
        self.assertEqual(name, observed_network['name'])
        self.assertEqual(project_id, observed_network['project_id'])
        self.assertEqual(project_id, observed_network['tenant_id'])

    @decorators.idempotent_id('08b92179-669d-45ee-8233-ef6611190809')
    @utils.requires_ext(extension="project-id", service="network")
    def test_create_network_with_project_and_other_tenant(self):
        project_id = self.client.project_id  # non-admin
        other_tenant = uuidutils.generate_uuid()

        name = 'created-with-project-and-other-tenant'
        e = self.assertRaises(lib_exc.BadRequest,
                              self.create_network, name,
                              project_id=project_id, tenant_id=other_tenant,
                              client=self.admin_client)
        expected_message = "'project_id' and 'tenant_id' do not match"
        self.assertEqual(expected_message, e.resp_body['message'])

    @decorators.idempotent_id('571d0dde-0f84-11e7-b565-fa163e4fa634')
    @testtools.skipUnless("vxlan" in config.CONF.neutron_plugin_options.
                          available_type_drivers,
                          'VXLAN type_driver is not enabled')
    @utils.requires_ext(extension="provider", service="network")
    def test_create_tenant_network_vxlan(self):
        network = self.admin_client.create_network(
            **{"provider:network_type": "vxlan"})['network']
        self.addCleanup(self.admin_client.delete_network,
                        network['id'])
        network = self.admin_client.show_network(
            network['id'])['network']
        self.assertEqual('vxlan', network['provider:network_type'])

    @decorators.idempotent_id('bbb9a2be-c9a7-4693-ac8e-d51b5371b68d')
    def test_list_network_filter_provider_attributes(self):
        project_id = self.client.project_id
        physnet_name = config.CONF.neutron_plugin_options.provider_vlans[0]
        # Check project networks pre-created.
        body = self.client.list_networks(project_id=project_id)['networks']
        num_networks_precreated = len(body)

        networks = []
        num_networks = 5
        for _ in range(num_networks):
            networks.append(self.create_network(
                provider_network_type='vlan',
                provider_physical_network=physnet_name,
                project_id=project_id))

        # Check new project networks created.
        body = self.client.list_networks(project_id=project_id)['networks']
        self.assertEqual(num_networks + num_networks_precreated, len(body))

        vlan_ids = [net['provider:segmentation_id'] for net in networks]

        # List networks with limit (from 1 to num_networks).
        # Each filter (except from the 'provider:segmentation_id'), uses the
        # value directly and in a list.
        for idx in range(1, num_networks + 1):
            # Filter by 'provider:network_type'
            kwargs = {'provider:network_type': 'vlan',
                      'project_id': project_id, 'limit': idx}
            body = self.client.list_networks(**kwargs)['networks']
            self.assertEqual(idx, len(body))
            kwargs['provider:network_type'] = ['vlan']
            body = self.client.list_networks(**kwargs)['networks']
            self.assertEqual(idx, len(body))

            # Filter by 'provider:physical_network'.
            kwargs = {'provider:physical_network': physnet_name,
                      'project_id': project_id, 'limit': idx}
            body = self.client.list_networks(**kwargs)['networks']
            self.assertEqual(idx, len(body))
            kwargs['provider:physical_network'] = [physnet_name]
            body = self.client.list_networks(**kwargs)['networks']
            self.assertEqual(idx, len(body))

            # Filter by 'provider:segmentation_id'
            kwargs = {'provider:segmentation_id': vlan_ids,
                      'project_id': project_id, 'limit': idx}
            body = self.client.list_networks(**kwargs)['networks']
            self.assertEqual(idx, len(body))
