# Copyright 2020 Ericsson Software Technology
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import collections

from neutron_lib import constants as nlib_const
from oslo_log import log as logging
from tempest.common import utils
from tempest.lib.common.utils import data_utils
from tempest.lib import decorators
from tempest.lib import exceptions
import testtools

from neutron_tempest_plugin.common import ssh
from neutron_tempest_plugin import config
from neutron_tempest_plugin.scenario import base

LOG = logging.getLogger(__name__)
CONF = config.CONF

Server = collections.namedtuple(
    'Server', ['floating_ip', 'server', 'ssh_client'])


class MetadataTest(base.BaseTempestTestCase):

    """Test metadata access over IPv6 tenant subnet.

    Please note that there is metadata over IPv4 test coverage in tempest:

    tempest.scenario.test_server_basic_ops\
        .TestServerBasicOps.test_server_basic_ops
    """

    credentials = ['primary', 'admin']
    force_tenant_isolation = False

    @classmethod
    def skip_checks(cls):
        super(MetadataTest, cls).skip_checks()
        if not utils.is_network_feature_enabled('ipv6_metadata'):
            raise cls.skipException("Metadata over IPv6 is not enabled")

    @classmethod
    def resource_setup(cls):
        super(MetadataTest, cls).resource_setup()
        cls.rand_name = data_utils.rand_name(
            cls.__name__.rsplit('.', 1)[-1])
        cls.reserve_external_subnet_cidrs()
        cls.network = cls.create_network(name=cls.rand_name)
        cls.subnet_v4 = cls.create_subnet(
            network=cls.network, name=cls.rand_name)
        cls.subnet_v6 = cls.create_subnet(
            network=cls.network, name=cls.rand_name, ip_version=6)
        cls.router = cls.create_router_by_client()
        cls.create_router_interface(cls.router['id'], cls.subnet_v4['id'])
        cls.create_router_interface(cls.router['id'], cls.subnet_v6['id'])
        cls.keypair = cls.create_keypair(name=cls.rand_name)
        cls.security_group = cls.create_security_group(name=cls.rand_name)
        cls.create_loginable_secgroup_rule(cls.security_group['id'])

    def _create_server_with_network(self, network, use_advanced_image=False):
        port = self._create_server_port(network=network)
        floating_ip = self.create_floatingip(port=port)
        ssh_client = self._create_ssh_client(
            floating_ip=floating_ip, use_advanced_image=use_advanced_image)
        server = self._create_server(port=port,
                                     use_advanced_image=use_advanced_image)
        return Server(
            floating_ip=floating_ip, server=server, ssh_client=ssh_client)

    def _create_server_port(self, network=None, **params):
        network = network or self.network
        return self.create_port(network=network, name=self.rand_name,
                                security_groups=[self.security_group['id']],
                                **params)

    def _create_server(self, port, use_advanced_image=False, **params):
        if use_advanced_image:
            flavor_ref = CONF.neutron_plugin_options.advanced_image_flavor_ref
            image_ref = CONF.neutron_plugin_options.advanced_image_ref
        else:
            flavor_ref = CONF.compute.flavor_ref
            image_ref = CONF.compute.image_ref
        return self.create_server(flavor_ref=flavor_ref,
                                  image_ref=image_ref,
                                  key_name=self.keypair['name'],
                                  networks=[{'port': port['id']}],
                                  **params)['server']

    def _create_ssh_client(self, floating_ip, use_advanced_image=False):
        if use_advanced_image:
            username = CONF.neutron_plugin_options.advanced_image_ssh_user
        else:
            username = CONF.validation.image_ssh_user
        return ssh.Client(host=floating_ip['floating_ip_address'],
                          username=username,
                          pkey=self.keypair['private_key'])

    def _assert_has_ssh_connectivity(self, ssh_client):
        ssh_client.exec_command('true')

    def _get_primary_interface(self, ssh_client):
        out = ssh_client.exec_command(
            "ip -6 -br address show scope link up | head -1 | cut -d ' ' -f1")
        interface = out.strip()
        if not interface:
            self.fail(
                'Could not find a single interface '
                'with an IPv6 link-local address.')
        return interface

    @testtools.skipUnless(
        CONF.neutron_plugin_options.advanced_image_ref or
        CONF.neutron_plugin_options.default_image_is_advanced,
        'Advanced image is required to run this test.')
    @decorators.idempotent_id('e680949a-f1cc-11ea-b49a-cba39bbbe5ad')
    def test_metadata_routed(self):
        use_advanced_image = (
            not CONF.neutron_plugin_options.default_image_is_advanced)

        vm = self._create_server_with_network(
            self.network, use_advanced_image=use_advanced_image)
        self.wait_for_server_active(server=vm.server)
        self.wait_for_guest_os_ready(vm.server)
        self.check_connectivity(host=vm.floating_ip['floating_ip_address'],
                                ssh_client=vm.ssh_client)
        interface = self._get_primary_interface(vm.ssh_client)

        try:
            out = vm.ssh_client.exec_command(
                'curl http://[%(address)s%%25%(interface)s]/' % {
                    'address': nlib_const.METADATA_V6_IP,
                    'interface': interface})
            self.assertIn('latest', out)

            out = vm.ssh_client.exec_command(
                'curl http://[%(address)s%%25%(interface)s]/openstack/' % {
                    'address': nlib_const.METADATA_V6_IP,
                    'interface': interface})
            self.assertIn('latest', out)
        except exceptions.SSHExecCommandFailed:
            self._log_console_output()
            self._log_local_network_status()
