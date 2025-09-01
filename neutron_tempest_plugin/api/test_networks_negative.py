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

    @decorators.attr(type='negative')
    @decorators.idempotent_id('53537bba-d6c3-4a2e-bda4-ab5b009fb7d9')
    def test_create_subnet_mtu_below_minimum_ipv4(self):
        network = self.create_network(mtu=67)
        with testtools.ExpectedException(lib_exc.Conflict):
            self.create_subnet(network, ip_version=4, cidr='10.0.0.0/24')

    @decorators.attr(type='negative')
    @decorators.idempotent_id('1de68cb6-e6d4-47df-b820-c5048796f33a')
    @testtools.skipUnless(config.CONF.network_feature_enabled.ipv6,
                          'IPv6 is not enabled')
    def test_create_subnet_mtu_below_minimum_ipv6(self):
        network = self.create_network(mtu=1279)
        with testtools.ExpectedException(lib_exc.Conflict):
            self.create_subnet(network, ip_version=6, cidr='2001:db8:0:1::/64')

    @decorators.attr(type='negative')
    @decorators.idempotent_id('5213df6d-7141-40b2-90ea-a958d9bc97e5')
    def test_update_network_mtu_below_minimum_ipv4(self):
        network = self.create_network(mtu=1280)
        self.create_subnet(network, ip_version=4, cidr='10.0.0.0/24')
        with testtools.ExpectedException(lib_exc.Conflict):
            self.client.update_network(network['id'], mtu=67)

    @decorators.attr(type='negative')
    @decorators.idempotent_id('1a714fc4-24b1-4c07-a005-d5c218672eab')
    @testtools.skipUnless(config.CONF.network_feature_enabled.ipv6,
                          'IPv6 is not enabled')
    def test_update_network_mtu_below_minimum_ipv6(self):
        network = self.create_network(mtu=1280)
        self.create_subnet(network, ip_version=6, cidr='2001:db8:0:1::/64')
        with testtools.ExpectedException(lib_exc.Conflict):
            self.client.update_network(network['id'], mtu=1279)
