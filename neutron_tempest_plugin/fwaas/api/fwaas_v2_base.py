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

from tempest.api.network import base
from tempest import config

from neutron_tempest_plugin.fwaas.common import fwaas_v2_client

CONF = config.CONF


class BaseFWaaSTest(fwaas_v2_client.FWaaSClientMixin, base.BaseNetworkTest):

    @classmethod
    def skip_checks(cls):
        super(BaseFWaaSTest, cls).skip_checks()
        msg = None
        if not CONF.fwaas.run_fwaas_tests:
            msg = ("Running of fwaas related tests is disabled in "
                   "plugin configuration.")
        if msg:
            raise cls.skipException(msg)
