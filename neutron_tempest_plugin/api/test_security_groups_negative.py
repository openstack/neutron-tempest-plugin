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
from neutron_lib.db import constants as db_const
from tempest.lib.common.utils import data_utils
from tempest.lib import decorators
from tempest.lib import exceptions as lib_exc

from neutron_tempest_plugin.api import base
from neutron_tempest_plugin.api import base_security_groups
from neutron_tempest_plugin.api import test_security_groups


LONG_NAME_NG = 'x' * (db_const.NAME_FIELD_SIZE + 1)


class NegativeSecGroupTest(base.BaseNetworkTest):

    required_extensions = ['security-group']

    @classmethod
    def resource_setup(cls):
        super(NegativeSecGroupTest, cls).resource_setup()
        cls.network = cls.create_network()

    @decorators.attr(type='negative')
    @decorators.idempotent_id('594edfa8-9a5b-438e-9344-49aece337d49')
    def test_create_security_group_with_too_long_name(self):
        self.assertRaises(lib_exc.BadRequest,
                          self.create_security_group,
                          name=LONG_NAME_NG)

    @decorators.attr(type='negative')
    @decorators.idempotent_id('b6b79838-7430-4d3f-8e07-51dfb61802c2')
    def test_create_security_group_with_boolean_type_name(self):
        self.assertRaises(lib_exc.BadRequest,
                          self.create_security_group,
                          name=True)

    @decorators.attr(type='negative')
    @decorators.idempotent_id('55100aa8-b24f-333c-0bef-64eefd85f15c')
    def test_update_default_security_group_name(self):
        security_group = self.client.list_security_groups(name='default')[
            'security_groups'][0]
        self.assertRaises(lib_exc.Conflict, self.client.update_security_group,
                          security_group['id'], name='test')

    @decorators.attr(type='negative')
    @decorators.idempotent_id('c8510dd8-c3a8-4df9-ae44-24354db50960')
    def test_update_security_group_with_too_long_name(self):
        security_group = self.client.list_security_groups(name='default')[
            'security_groups'][0]
        self.assertRaises(lib_exc.BadRequest,
                          self.client.update_security_group,
                          security_group['id'], name=LONG_NAME_NG)

    @decorators.attr(type='negative')
    @decorators.idempotent_id('d9a14917-f66f-4eca-ab72-018563917f1b')
    def test_update_security_group_with_boolean_type_name(self):
        security_group = self.client.list_security_groups(name='default')[
            'security_groups'][0]
        self.assertRaises(lib_exc.BadRequest,
                          self.client.update_security_group,
                          security_group['id'], name=True)

    @decorators.attr(type='negative')
    @decorators.idempotent_id('3200b1a8-d73b-48e9-b03f-e891a4abe2d3')
    def test_delete_in_use_sec_group(self):
        security_group = self.create_security_group()
        self.create_port(network=self.network,
                         security_groups=[security_group['id']])
        self.assertRaises(lib_exc.Conflict,
                          self.os_primary.network_client.delete_security_group,
                          security_group_id=security_group['id'])

    @decorators.attr(type='negative')
    @decorators.idempotent_id('867d67c3-7e26-4288-a27b-e3d0649ee54b')
    def test_assign_sec_group_twice(self):
        net = self.create_network()
        port = self.create_port(net)
        sg = self.create_security_group()
        self.assertRaises(lib_exc.BadRequest,
                          self.update_port,
                          port,
                          **{'security_groups': [sg['id'], sg['id']]})

    @decorators.attr(type='negative')
    @decorators.idempotent_id('d5ecb408-eb7e-47c1-a56f-353967dbd1c2')
    def test_assign_nonexistent_sec_group(self):
        net = self.create_network()
        port = self.create_port(net)
        self.assertRaises(lib_exc.NotFound,
                          self.update_port,
                          port,
                          **{'security_groups': [data_utils.rand_uuid()]})

    @decorators.attr(type='negative')
    @decorators.idempotent_id('98ef378d-81a2-43f6-bb6f-735c04cdef91')
    def test_no_sec_group_changes_after_assignment_failure(self):
        net = self.create_network()
        port = self.create_port(net)
        sg_list_before_failure = port['security_groups']
        self.assertRaises(lib_exc.NotFound,
                          self.update_port,
                          port,
                          **{'security_groups': [data_utils.rand_uuid()]})
        port_details_new = self.client.show_port(port['id'])['port']
        sg_list_after_failure = port_details_new['security_groups']
        self.assertEqual(sg_list_before_failure, sg_list_after_failure)


class NegativeSecGroupIPv6Test(NegativeSecGroupTest):
    _ip_version = constants.IP_VERSION_6


class NegativeSecGroupProtocolTest(base.BaseNetworkTest):

    def _test_create_security_group_rule_with_bad_protocols(self, protocols):
        security_group = self.create_security_group()

        # bad protocols can include v6 protocols because self.ethertype is v4
        for protocol in protocols:
            self.assertRaises(
                lib_exc.BadRequest,
                self.client.create_security_group_rule,
                security_group_id=security_group['id'],
                protocol=protocol, direction=constants.INGRESS_DIRECTION,
                ethertype=self.ethertype)

    @decorators.attr(type=['negative'])
    @decorators.idempotent_id('cccbb0f3-c273-43ed-b3fc-1efc48833810')
    def test_create_security_group_rule_with_ipv6_protocol_names(self):
        self._test_create_security_group_rule_with_bad_protocols(
            base_security_groups.V6_PROTOCOL_NAMES)

    @decorators.attr(type=['negative'])
    @decorators.idempotent_id('8aa636bd-7060-4fdf-b722-cdae28e2f1ef')
    def test_create_security_group_rule_with_ipv6_protocol_integers(self):
        self._test_create_security_group_rule_with_bad_protocols(
            base_security_groups.V6_PROTOCOL_INTS)


class NegativeSecGroupQuotaTest(test_security_groups.BaseSecGroupQuota):

    credentials = ['primary', 'admin']
    required_extensions = ['security-group', 'quotas']

    @decorators.attr(type=['negative'])
    @decorators.idempotent_id('63f00cba-fcf5-4000-a3ee-eca58a1795c1')
    def test_create_excess_sg(self):
        self._set_sg_quota(0)
        self.assertRaises(lib_exc.Conflict, self.create_security_group)

    @decorators.attr(type=['negative'])
    @decorators.idempotent_id('90a83445-bbc2-49d8-8c85-a111c08cd7fb')
    def test_sg_quota_incorrect_values(self):
        values = [-2, 2147483648, "value"]
        for value in values:
            self.assertRaises(lib_exc.BadRequest, self._set_sg_quota, value)
