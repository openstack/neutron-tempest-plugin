# Copyright (c) 2026 Red Hat Inc.
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
from tempest.lib.common.utils import data_utils

from neutron_tempest_plugin.api import base


class PVLANExtensionTestBase(base.BaseNetworkTest):
    """Base class for PVLAN API tests.

    Provides extension checks and helpers only. Test classes must create
    their own network resources per test method so positive and negative
    suites can run independently and in parallel.
    """

    required_extensions = ['pvlan']

    @classmethod
    def resource_setup(cls):
        super().resource_setup()
        if not utils.is_extension_enabled('pvlan', 'network'):
            msg = "PVLAN extension not enabled."
            raise cls.skipException(msg)

    @classmethod
    def create_pvlan_network(cls, name_prefix='net-pvlan-'):
        network = cls.create_network(
            name=data_utils.rand_name(name_prefix),
            pvlan=True)
        subnet = cls.create_subnet(network)
        return network, subnet

    def _assert_pvlan_disabled(self, network):
        pvlan = network.get('pvlan')
        self.assertIn(pvlan, (False, None))

    def _show_network(self, network_id):
        return self.client.show_network(network_id)['network']

    def _show_port(self, port_id):
        return self.client.show_port(port_id)['port']
