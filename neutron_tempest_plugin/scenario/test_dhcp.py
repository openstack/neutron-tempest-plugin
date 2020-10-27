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
from oslo_log import log
from paramiko import ssh_exception as ssh_exc
from tempest.common import utils
from tempest.lib.common.utils import data_utils
from tempest.lib import decorators
from tempest.lib import exceptions as lib_exc

from neutron_tempest_plugin.common import ssh
from neutron_tempest_plugin import config
from neutron_tempest_plugin.scenario import base

CONF = config.CONF
LOG = log.getLogger(__name__)


class DHCPTest(base.BaseTempestTestCase):

    credentials = ['primary', 'admin']
    force_tenant_isolation = False

    @classmethod
    def resource_setup(cls):
        super(DHCPTest, cls).resource_setup()
        cls.rand_name = data_utils.rand_name(
            cls.__name__.rsplit('.', 1)[-1])
        cls.network = cls.create_network(name=cls.rand_name)
        cls.subnet = cls.create_subnet(
            network=cls.network, name=cls.rand_name)
        cls.router = cls.create_router_by_client()
        cls.create_router_interface(cls.router['id'], cls.subnet['id'])
        cls.keypair = cls.create_keypair(name=cls.rand_name)
        cls.security_group = cls.create_security_group(name=cls.rand_name)
        cls.create_loginable_secgroup_rule(cls.security_group['id'])

    @utils.requires_ext(extension='extra_dhcp_opt', service='network')
    @decorators.idempotent_id('58f7c094-1980-4e03-b0d3-6c4dd27217b1')
    def test_extra_dhcp_opts(self):
        """This test case tests DHCP extra options configured for Neutron port.

        Test is checking just extra option "15" which is domain-name
        according to the RFC 2132:
        https://tools.ietf.org/html/rfc2132#section-5.3

        To test that option, there is spawned VM connected to the port with
        configured extra_dhcp_opts and test asserts that search domain name is
        configured inside VM in /etc/resolv.conf file
        """

        test_domain = "test.domain"
        extra_dhcp_opts = [
            {'opt_name': 'domain-name',
             'opt_value': '"%s"' % test_domain}]
        port = self.create_port(
            network=self.network, name=self.rand_name,
            security_groups=[self.security_group['id']],
            extra_dhcp_opts=extra_dhcp_opts)
        floating_ip = self.create_floatingip(port=port)

        server = self.create_server(
            flavor_ref=CONF.compute.flavor_ref,
            image_ref=CONF.compute.image_ref,
            key_name=self.keypair['name'],
            networks=[{'port': port['id']}])
        self.wait_for_server_active(server['server'])
        self.wait_for_guest_os_ready(server['server'])

        try:
            ssh_client = ssh.Client(
                floating_ip['floating_ip_address'],
                CONF.validation.image_ssh_user,
                pkey=self.keypair['private_key'])
            vm_resolv_conf = ssh_client.exec_command(
                "cat /etc/resolv.conf")
            self.assertIn(test_domain, vm_resolv_conf)
        except (lib_exc.SSHTimeout,
                ssh_exc.AuthenticationException,
                AssertionError) as error:
            LOG.debug(error)
            self._log_console_output([server])
            self._log_local_network_status()
            raise
