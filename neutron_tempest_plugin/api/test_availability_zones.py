# Copyright 2018 AT&T Corporation.
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
from tempest.lib import decorators

from neutron_tempest_plugin.api import base


class ListAvailableZonesTest(base.BaseNetworkTest):

    @decorators.idempotent_id('5a8a8a1a-c265-11e8-a611-080027758b73')
    @utils.requires_ext(extension="availability_zone",
                        service="network")
    def test_list_available_zones(self):
        body = self.client.list_availability_zones()
        self.assertIsNotNone(body)
        self.assertIsInstance(body['availability_zones'], list)
