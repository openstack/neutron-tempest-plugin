# Copyright 2018 Red Hat, Inc.
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

import netaddr
import six

from neutron_lib import constants as const
from tempest.common import utils
from tempest.lib.common.utils import data_utils
from tempest.lib import decorators
from tempest.lib import exceptions as tlib_exceptions

from neutron_tempest_plugin.api import base
from neutron_tempest_plugin import config

CONF = config.CONF


class PortTestCasesAdmin(base.BaseAdminNetworkTest):

    @classmethod
    def resource_setup(cls):
        super(PortTestCasesAdmin, cls).resource_setup()
        cls.network = cls.create_network()
        cls.create_subnet(cls.network)

    @decorators.idempotent_id('dfe8cc79-18d9-4ae8-acef-3ec6bb719bb1')
    def test_update_mac_address(self):
        body = self.create_port(self.network)
        current_mac = body['mac_address']

        # Verify mac_address can be successfully updated.
        body = self.admin_client.update_port(body['id'],
                                             mac_address='12:34:56:78:be:6d')
        new_mac = body['port']['mac_address']
        self.assertNotEqual(current_mac, new_mac)
        self.assertEqual('12:34:56:78:be:6d', new_mac)

        # Verify that port update without specifying mac_address does not
        # change the mac address.
        body = self.admin_client.update_port(body['port']['id'],
                                             description='Port Description')
        self.assertEqual(new_mac, body['port']['mac_address'])

    @decorators.idempotent_id('dfe8cc79-18d9-4ae8-acef-3ec6bb719cc2')
    @utils.requires_ext(extension="port-mac-address-regenerate",
                        service="network")
    def test_regenerate_mac_address(self):
        body = self.create_port(self.network)
        current_mac = body['mac_address']
        body = self.admin_client.update_port(body['id'],
                                             mac_address=None)
        new_mac = body['port']['mac_address']
        self.assertNotEqual(current_mac, new_mac)
        self.assertTrue(netaddr.valid_mac(new_mac))


class PortTestCasesResourceRequest(base.BaseAdminNetworkTest):

    required_extensions = ['port-resource-request',
                           'qos',
                           'qos-bw-minimum-ingress']

    EGRESS_KBPS = 1000
    INGRESS_KBPS = 2000

    @classmethod
    def skip_checks(cls):
        super(PortTestCasesResourceRequest, cls).skip_checks()
        if not config.CONF.neutron_plugin_options.provider_vlans:
            msg = "Skipped as provider VLANs are not available in config"
            raise cls.skipException(msg)

    @classmethod
    def resource_setup(cls):
        super(PortTestCasesResourceRequest, cls).resource_setup()

        cls.vnic_type = 'normal'

        # Note(lajoskatona): to avoid creating provider network use vxlan
        # as provider network type:
        cls.network = cls.create_network(provider_network_type='vxlan')
        cls.physnet_name = CONF.neutron_plugin_options.provider_vlans[0]
        base_segm = CONF.neutron_plugin_options.provider_net_base_segm_id
        cls.prov_network = cls.create_provider_network(
            physnet_name=cls.physnet_name, start_segmentation_id=base_segm)

    def _create_qos_policy_and_port(self, network, vnic_type,
                                    network_policy=False):
        qos_policy = self.create_qos_policy(
            name=data_utils.rand_name('test_policy'), shared=True)
        self.create_qos_minimum_bandwidth_rule(qos_policy['id'],
                                               self.EGRESS_KBPS,
                                               const.EGRESS_DIRECTION)
        self.create_qos_minimum_bandwidth_rule(qos_policy['id'],
                                               self.INGRESS_KBPS,
                                               const.INGRESS_DIRECTION)

        port_policy_id = qos_policy['id'] if not network_policy else None
        port_kwargs = {
            'qos_policy_id': port_policy_id,
            'binding:vnic_type': vnic_type
        }

        if network_policy:
            self.admin_client.update_network(network['id'],
                                             qos_policy_id=qos_policy['id'])

        port_id = self.create_port(network, **port_kwargs)['id']
        return self.admin_client.show_port(port_id)['port']

    def _assert_resource_request(self, port, vnic_type):
        self.assertIn('resource_request', port)
        vnic_trait = 'CUSTOM_VNIC_TYPE_%s' % vnic_type.upper()
        physnet_trait = 'CUSTOM_PHYSNET_%s' % self.physnet_name.upper()
        six.assertCountEqual(self, [physnet_trait, vnic_trait],
                             port['resource_request']['required'])

        self.assertEqual(
            {'NET_BW_EGR_KILOBIT_PER_SEC': self.EGRESS_KBPS,
             'NET_BW_IGR_KILOBIT_PER_SEC': self.INGRESS_KBPS},
            port['resource_request']['resources']
        )

    @decorators.idempotent_id('ebb86dc4-716c-4558-8516-6dfc4a67601f')
    def test_port_resource_request(self):
        port = self._create_qos_policy_and_port(
            network=self.prov_network, vnic_type=self.vnic_type)
        port_id = port['id']

        self._assert_resource_request(port, self.vnic_type)

        # Note(lajoskatona): port-resource-request is an admin only feature,
        # so test if non-admin user can't see the new field.
        port = self.client.show_port(port_id)['port']
        self.assertNotIn('resource_request', port)

        self.update_port(port, **{'qos_policy_id': None})
        port = self.admin_client.show_port(port_id)['port']
        self.assertIsNone(port['resource_request'])

    @decorators.idempotent_id('7261391f-64cc-45a6-a1e3-435694c54bf5')
    def test_port_resource_request_no_provider_net_conflict(self):
        conflict = self.assertRaises(
            tlib_exceptions.Conflict,
            self._create_qos_policy_and_port,
            network=self.network, vnic_type=self.vnic_type)
        self.assertEqual('QosRuleNotSupported', conflict.resp_body['type'])

    @decorators.idempotent_id('0eeb6ffa-9a7a-40b5-83dd-dbdcd67e2e64')
    def test_port_resource_request_empty(self):
        qos_policy = self.create_qos_policy(
            name=data_utils.rand_name('test_policy'), shared=True)

        # Note(lajoskatona): Add a non-minimum-bandwidth-rule to the policy
        # to make sure that the resource request is not filled with it.
        self.create_qos_bandwidth_limit_rule(qos_policy['id'],
                                             self.EGRESS_KBPS, 800,
                                             const.EGRESS_DIRECTION)

        port_kwargs = {
            'qos_policy_id': qos_policy['id'],
            'binding:vnic_type': self.vnic_type
        }

        port_id = self.create_port(self.prov_network, **port_kwargs)['id']
        port = self.admin_client.show_port(port_id)['port']

        self.assertIn('resource_request', port)
        self.assertIsNone(port['resource_request'])

    @decorators.idempotent_id('b6c34ae4-44c8-47f0-86de-7ef9866fa000')
    def test_port_resource_request_inherited_policy(self):
        port = self._create_qos_policy_and_port(
            network=self.prov_network, vnic_type=self.vnic_type,
            network_policy=True)

        self._assert_resource_request(port, self.vnic_type)
