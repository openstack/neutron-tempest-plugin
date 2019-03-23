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

from tempest.lib import decorators
from tempest.lib import exceptions as lib_exc
import testtools

from neutron_tempest_plugin.api import base
from tempest import config

CONF = config.CONF


class NetworksNegativeTest(base.BaseNetworkTest):

    @classmethod
    def resource_setup(cls):
        super(NetworksNegativeTest, cls).resource_setup()
        cls.network = cls.create_network()
        cls.subnet = cls.create_subnet(cls.network)

    @decorators.attr(type='negative')
    @decorators.idempotent_id('9f80f25b-5d1b-4f26-9f6b-774b9b270819')
    def test_delete_network_in_use(self):
        self.create_port(self.network)
        with testtools.ExpectedException(lib_exc.Conflict):
            self.client.delete_subnet(self.subnet['id'])
        with testtools.ExpectedException(lib_exc.Conflict):
            self.client.delete_network(self.network['id'])

    @decorators.attr(type='negative')
    @decorators.idempotent_id('9f80f25b-5d1b-4f26-9f6b-774b9b270820')
    def test_update_network_mtu(self):
        with testtools.ExpectedException(lib_exc.BadRequest):
            self.client.create_network(
                mtu=CONF.neutron_plugin_options.max_mtu + 1)
