# Copyright 2019 SUSE LLC
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
from tempest.common import utils
from tempest.lib import decorators

from neutron_tempest_plugin.api import test_subnetpools

SUBNETPOOL_NAME = 'smoke-subnetpool'
SUBNET_NAME = 'smoke-subnet'


class SubnetPoolPrefixOpsTestMixin(object):

    def _compare_prefix_lists(self, list_expected, list_observed):
        expected_set = netaddr.IPSet(iterable=list_expected)
        observed_set = netaddr.IPSet(iterable=list_observed)

        # compact the IPSet's
        expected_set.compact()
        observed_set.compact()

        self.assertEqual(expected_set, observed_set)

    @decorators.idempotent_id('b1d56d1f-2818-44ee-b6a3-3c1327c25318')
    @utils.requires_ext(extension='subnetpool-prefix-ops', service='network')
    def test_add_remove_prefix(self):
        created_subnetpool = self._create_subnetpool()
        req_body = {'prefixes': self.prefixes_to_add}

        # Add a prefix to the subnet pool
        resp = self.client.add_subnetpool_prefix(created_subnetpool['id'],
                                                 **req_body)
        self._compare_prefix_lists(self.prefixes + self.prefixes_to_add,
                                   resp['prefixes'])

        # Remove the prefix from the subnet pool
        resp = self.client.remove_subnetpool_prefix(created_subnetpool['id'],
                                                    **req_body)
        self._compare_prefix_lists(self.prefixes, resp['prefixes'])

    @decorators.idempotent_id('a36c18fc-10b5-4ebc-ab79-914f826c5bf5')
    @utils.requires_ext(extension='subnetpool-prefix-ops', service='network')
    def test_add_overlapping_prefix(self):
        created_subnetpool = self._create_subnetpool()
        req_body = {'prefixes': self.overlapping_prefixes}

        # Add an overlapping prefix to the subnet pool
        resp = self.client.add_subnetpool_prefix(created_subnetpool['id'],
                                                 **req_body)
        self._compare_prefix_lists(self.prefixes + self.overlapping_prefixes,
                                   resp['prefixes'])


class SubnetPoolPrefixOpsIpv4Test(test_subnetpools.SubnetPoolsTestBase,
                                  SubnetPoolPrefixOpsTestMixin):

    prefixes = ['192.168.1.0/24', '10.10.10.0/24']
    prefixes_to_add = ['192.168.2.0/24']
    overlapping_prefixes = ['10.10.0.0/16']
    min_prefixlen = 16
    ip_version = 4

    @classmethod
    def resource_setup(cls):
        super(SubnetPoolPrefixOpsIpv4Test, cls).resource_setup()
        cls._subnetpool_data = {'prefixes': cls.prefixes,
                                'min_prefixlen': cls.min_prefixlen}


class SubnetPoolPrefixOpsIpv6Test(test_subnetpools.SubnetPoolsTestBase,
                                  SubnetPoolPrefixOpsTestMixin):

    prefixes = ['2001:db8:1234::/48', '2001:db8:1235::/48']
    prefixes_to_add = ['2001:db8:4321::/48']
    overlapping_prefixes = ['2001:db8:1234:1111::/64']
    min_prefixlen = 48
    ip_version = 6

    @classmethod
    def resource_setup(cls):
        super(SubnetPoolPrefixOpsIpv6Test, cls).resource_setup()
        cls._subnetpool_data = {'prefixes': cls.prefixes,
                                'min_prefixlen': cls.min_prefixlen}
