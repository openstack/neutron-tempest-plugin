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

from neutron_lib.db import constants as db_const
from oslo_utils import uuidutils
from tempest.lib import decorators
from tempest.lib import exceptions as lib_exc

from neutron_tempest_plugin.api import base

LONG_NAME_NG = 'z' * (db_const.NAME_FIELD_SIZE + 1)
LONG_DESCRIPTION_NG = 'z' * (db_const.LONG_DESCRIPTION_FIELD_SIZE + 1)


class PortsNegativeTestJSON(base.BaseNetworkTest):

    @classmethod
    def resource_setup(cls):
        super(PortsNegativeTestJSON, cls).resource_setup()
        cls.network = cls.create_network()

    @decorators.attr(type='negative')
    @decorators.idempotent_id('0cbd256a-a6d4-4afa-a039-44cc13704bab')
    def test_add_port_with_too_long_name(self):
        self.assertRaises(lib_exc.BadRequest,
                          self.create_port,
                          self.network, name=LONG_NAME_NG)

    @decorators.attr(type='negative')
    @decorators.idempotent_id('e10da38c-1071-49c9-95c2-0c451e18ae31')
    def test_add_port_with_too_long_description(self):
        self.assertRaises(lib_exc.BadRequest,
                          self.create_port,
                          self.network, description=LONG_DESCRIPTION_NG)

    @decorators.attr(type='negative')
    @decorators.idempotent_id('5b69a905-3a84-43a4-807a-1a67ab85caeb')
    def test_add_port_with_nonexist_tenant_id(self):
        self.assertRaises(lib_exc.BadRequest,
                          self.create_port,
                          self.network,
                          project_id=uuidutils.generate_uuid())

    @decorators.attr(type='negative')
    @decorators.idempotent_id('7cf473ae-7ec8-4834-ae17-9ef6ec6b8a32')
    def test_add_port_with_nonexist_network_id(self):
        network = self.network
        # Copy and restore net ID so the cleanup will delete correct net
        original_network_id = network['id']
        network['id'] = uuidutils.generate_uuid()
        self.assertRaises(lib_exc.NotFound,
                          self.create_port,
                          network)
        network['id'] = original_network_id

    @decorators.attr(type='negative')
    @decorators.idempotent_id('cad2d349-25fa-490e-9675-cd2ea24164bc')
    def test_add_port_with_nonexist_security_groups_id(self):
        self.assertRaises(lib_exc.NotFound,
                          self.create_port,
                          self.network,
                          security_groups=[uuidutils.generate_uuid()])

    @decorators.attr(type='negative')
    @decorators.idempotent_id('9b0a4152-9aa4-4169-9b2c-579609e2fb4a')
    def test_add_port_with_illegal_ip(self):
        self.assertRaises(lib_exc.BadRequest,
                          self.create_port,
                          self.network,
                          allowed_address_pairs=[{"ip_address: 12.12.12.a"}])
