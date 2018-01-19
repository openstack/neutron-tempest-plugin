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

from oslo_utils import uuidutils
from tempest.lib.common.utils import data_utils
from tempest.lib import decorators
from tempest.lib import exceptions as lib_exc

from neutron_tempest_plugin.api import base


class LoggingNegativeTestJSON(base.BaseAdminNetworkTest):

    required_extensions = ['logging', 'standard-attr-description']

    @decorators.attr(type='negative')
    @decorators.idempotent_id('5fc61e24-cad5-4d86-a2d4-f40c0fa0a54c')
    def test_create_log_with_invalid_resource_type(self):
        log_args = {'name': data_utils.rand_name('test-log'),
                    'description': data_utils.rand_name('test-log-desc'),
                    'resource_type': 'fake_resource'}
        self.assertRaises(lib_exc.BadRequest,
                          self.admin_client.create_log, **log_args)

    @decorators.attr(type='negative')
    @decorators.idempotent_id('7ed63170-0748-44b7-b0a0-64bfd9390dac')
    def test_create_log_with_nonexistent_port(self):
        log_args = {'name': data_utils.rand_name('test-log'),
                    'description': data_utils.rand_name('test-log-desc'),
                    'resource_type': 'security_group',
                    'target_id': uuidutils.generate_uuid()}
        self.assertRaises(lib_exc.NotFound,
                          self.admin_client.create_log, **log_args)

    @decorators.attr(type='negative')
    @decorators.idempotent_id('89194c6b-8f47-400b-979b-072b1c1f767b')
    def test_create_log_with_nonexistent_sg(self):
        log_args = {'name': data_utils.rand_name('test-log'),
                    'description': data_utils.rand_name('test-log-desc'),
                    'resource_type': 'security_group',
                    'resource_id': uuidutils.generate_uuid()}
        self.assertRaises(lib_exc.NotFound,
                          self.admin_client.create_log, **log_args)
