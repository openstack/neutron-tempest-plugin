# Copyright 2016 Red Hat, Inc.
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
import testtools

from tempest.lib import decorators

from neutron_tempest_plugin.common import ssh
from neutron_tempest_plugin import config
from neutron_tempest_plugin.scenario import base

CONF = config.CONF


class NetworkBasicTest(base.BaseTempestTestCase):
    credentials = ['primary', 'admin']
    force_tenant_isolation = False

    # Default to ipv4.
    _ip_version = 4

    @decorators.idempotent_id('de07fe0a-e955-449e-b48b-8641c14cd52e')
    def test_basic_instance(self):
        self.setup_network_and_server()
        self.check_connectivity(self.fip['floating_ip_address'],
                                CONF.validation.image_ssh_user,
                                self.keypair['private_key'])

    @testtools.skipUnless(
        CONF.neutron_plugin_options.global_ip_address,
        'Global IP address is not defined.')
    @decorators.idempotent_id('49609189-3a0e-43c7-832e-a7e114aad1c9')
    def test_ping_global_ip_from_vm_with_fip(self):
        self.setup_network_and_server()
        server_ssh_client = ssh.Client(self.fip['floating_ip_address'],
                                       CONF.validation.image_ssh_user,
                                       pkey=self.keypair['private_key'])
        self.check_remote_connectivity(
            server_ssh_client,
            CONF.neutron_plugin_options.global_ip_address,
            ping_count=1)
