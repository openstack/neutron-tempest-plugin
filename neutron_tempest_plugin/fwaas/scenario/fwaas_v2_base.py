# Copyright (c) 2015 Midokura SARL
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

from tempest import config
from tempest.lib import exceptions as lib_exc

from neutron_tempest_plugin.common import ssh
from neutron_tempest_plugin.fwaas.common import fwaas_v2_client
from neutron_tempest_plugin.scenario import base as scenario_base

CONF = config.CONF


class FWaaSScenarioTestBase:
    def check_ssh_connectivity(self, ip_address, username=None,
                               private_key=None, should_connect=True):
        """Check SSH reachability, including expected negative checks."""
        connect_timeout = CONF.validation.connect_timeout
        kwargs = {}
        if not should_connect:
            # Use a shorter timeout for negative cases.
            kwargs['timeout'] = 1
        try:
            client = ssh.Client(ip_address, username, pkey=private_key,
                                channel_timeout=connect_timeout,
                                **kwargs)
            client.test_connection_auth()
        except lib_exc.SSHTimeout:
            if should_connect:
                raise
        else:
            self.assertTrue(should_connect, "Unexpectedly reachable")


class FWaaSScenarioTest_V2(fwaas_v2_client.FWaaSClientMixin,
                           FWaaSScenarioTestBase,
                           scenario_base.BaseTempestTestCase):
    credentials = ['primary', 'admin']
    required_extensions = ['fwaas_v2', 'security-group', 'router']
