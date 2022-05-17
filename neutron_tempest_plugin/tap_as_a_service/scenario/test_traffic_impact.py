# Copyright (c) 2019 AT&T
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

from contextlib import contextmanager
from oslo_log import log
import testtools

from tempest.common import utils
from tempest import config
from tempest.lib.common.utils import data_utils
from tempest.lib.common.utils.linux import remote_client
from tempest.lib.common.utils import test_utils

from tempest.lib import decorators

from neutron_tempest_plugin.tap_as_a_service.scenario import manager


CONF = config.CONF
LOG = log.getLogger(__name__)


class TestTaaSTrafficScenarios(manager.BaseTaasScenarioTests):

    @classmethod
    @utils.requires_ext(extension='taas', service='network')
    @utils.requires_ext(extension='security-group', service='network')
    @utils.requires_ext(extension='router', service='network')
    def skip_checks(cls):
        super(TestTaaSTrafficScenarios, cls).skip_checks()

    @classmethod
    def resource_setup(cls):
        super(TestTaaSTrafficScenarios, cls).resource_setup()
        cls.provider_network = None
        cls.keypair = cls.create_keypair()
        cls.secgroup = cls.create_security_group(
            name=data_utils.rand_name('secgroup'))
        cls.create_loginable_secgroup_rule(secgroup_id=cls.secgroup['id'])
        cls.create_pingable_secgroup_rule(secgroup_id=cls.secgroup['id'])

    @contextmanager
    def _setup_topology(self, taas=True, use_taas_cloud_image=False,
                        provider_net=False):
        """Setup topology for the test

           +------------+
           | monitor vm |
           +-----+------+
                 |
           +-----v---+
        +--+ network <--+
        |  +----^----+  |
        |       |       |
        |  +----+-+ +---+--+
        |  | vm 1 | | vm 2 |
        |  +------+ +------+
        |
        |  +--------+
        +--> router |
           +-----+--+
                 |
           +-----v------+
           | public net |
           +------------+
       """
        self.network, self.subnet, self.router = self.create_networks()
        LOG.debug('Setup topology sbunet details: %s ', self.subnet)
        if provider_net:
            if CONF.taas.provider_physical_network:
                self.provider_network = self._setup_provider_network()
            else:
                msg = "provider_physical_network not provided"
                raise self.skipException(msg)

        self.mon_port, mon_fip = self._create_server_with_floatingip(
            use_taas_cloud_image=use_taas_cloud_image,
            provider_net=provider_net)
        LOG.debug('Setup topology monitor port: %s  ###  monitor FIP: %s ',
                  self.mon_port, mon_fip)
        self.left_port, self.left_fip = self._create_server_with_floatingip(
            provider_net=provider_net)
        LOG.debug('Setup topology left port: %s  ###  left FIP: %s ',
                  self.left_port, self.left_fip)
        self.right_port, self.right_fip = self._create_server_with_floatingip(
            provider_net=provider_net)
        LOG.debug('Setup topology right port: %s  ###  right FIP: %s ',
                  self.right_port, self.right_fip)

        if taas:
            LOG.debug("Create TAAS service")
            tap_service = self.tap_services_client.create_tap_service(
                port_id=self.mon_port['id'])['tap_service']
            self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                            self.client.delete_tap_service, tap_service['id'])
            tap_flow = self.tap_flows_client.create_tap_flow(
                tap_service_id=tap_service['id'], direction='BOTH',
                source_port=self.left_port['id'])['tap_flow']
            self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                            self.client.delete_tap_flow, tap_flow['id'])
            tap_flow = self.tap_flows_client.create_tap_flow(
                tap_service_id=tap_service['id'], direction='BOTH',
                source_port=self.right_port['id'])['tap_flow']
            self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                            self.client.delete_tap_flow, tap_flow['id'])

        user = CONF.validation.image_ssh_user
        if use_taas_cloud_image:
            user = CONF.neutron_plugin_options.advanced_image_ssh_user

        self.monitor_client = remote_client.RemoteClient(
            mon_fip['floating_ip_address'], user,
            pkey=self.keypair['private_key'],
            ssh_key_type=CONF.validation.ssh_key_type)
        self.monitor_client.validate_authentication()
        self.left_client = remote_client.RemoteClient(
            self.left_fip['floating_ip_address'],
            CONF.validation.image_ssh_user,
            pkey=self.keypair['private_key'],
            ssh_key_type=CONF.validation.ssh_key_type)
        self.left_client.validate_authentication()
        self.right_client = remote_client.RemoteClient(
            self.right_fip['floating_ip_address'],
            CONF.validation.image_ssh_user,
            pkey=self.keypair['private_key'],
            ssh_key_type=CONF.validation.ssh_key_type)
        self.right_client.validate_authentication()
        yield

    def _check_icmp_traffic(self):
        log_location = "/tmp/tcpdumplog"

        right_ip = self.right_port['fixed_ips'][0]['ip_address']
        left_ip = self.left_port['fixed_ips'][0]['ip_address']

        # Run tcpdump in background
        self._run_in_background(self.monitor_client,
                                "sudo tcpdump -n -nn > %s" % log_location)

        # Ensure tcpdump is up and running
        psax = self.monitor_client.exec_command("ps -ax")
        self.assertTrue("tcpdump" in psax)

        # Run traffic from left_vm to right_vm
        LOG.debug('Check ICMP traffic: ping %s ', right_ip)
        # self.left_client.exec_command(
        #     "ping -c 50 %s" % self.right_fip['floating_ip_address'])
        self.check_remote_connectivity(self.left_client, right_ip,
                                       ping_count=50)

        # Collect tcpdump results
        output = self.monitor_client.exec_command("cat %s" % log_location)
        self.assertLess(0, len(output))

        looking_for = ["IP %s > %s: ICMP echo request" % (left_ip, right_ip),
                       "IP %s > %s: ICMP echo reply" % (right_ip, left_ip)]

        results = []
        for tcpdump_line in looking_for:
            results.append(tcpdump_line in output)

        return all(results)

    def _test_taas_connectivity(self, use_provider_net=False):
        """Ensure TAAS doesn't break connectivity

        This test creates TAAS service between two servers and checks that
        it doesn't break basic connectivity between them.
        """
        # Check uninterrupted traffic between VMs
        with self._setup_topology(provider_net=use_provider_net):
            # Left to right
            self.check_remote_connectivity(
                self.left_client,
                self.right_port['fixed_ips'][0]['ip_address'])

            # Right to left
            self.check_remote_connectivity(
                self.right_client,
                self.left_port['fixed_ips'][0]['ip_address'])

            # TAAS vm to right
            self.check_remote_connectivity(
                self.monitor_client,
                self.right_port['fixed_ips'][0]['ip_address'])

            # TAAS vm to left
            self.check_remote_connectivity(
                self.monitor_client,
                self.left_port['fixed_ips'][0]['ip_address'])

    @decorators.idempotent_id('ff414b7d-e81c-47f2-b6c8-53bc2f1e9b00')
    @decorators.attr(type='slow')
    @utils.services('compute', 'network')
    def test_taas_provider_network_connectivity(self):
        self._test_taas_connectivity(use_provider_net=True)

    @decorators.idempotent_id('e3c52e91-7abf-4dfd-8687-f7c071cdd333')
    @decorators.attr(type='slow')
    @utils.services('compute', 'network')
    def test_taas_network_connectivity(self):
        self._test_taas_connectivity(use_provider_net=False)

    @decorators.idempotent_id('fcb15ca3-ef61-11e9-9792-f45c89c47e11')
    @testtools.skipUnless(CONF.neutron_plugin_options.advanced_image_ref,
                          'Cloud image not found.')
    @decorators.attr(type='slow')
    @utils.services('compute', 'network')
    def test_taas_forwarded_traffic_positive(self):
        """Check that TAAS forwards traffic as expected"""

        with self._setup_topology(use_taas_cloud_image=True):
            # Check that traffic was forwarded to TAAS service
            self.assertTrue(self._check_icmp_traffic())

    @decorators.idempotent_id('6c54d9c5-075a-4a1f-bbe6-12c3c9abf1e2')
    @testtools.skipUnless(CONF.neutron_plugin_options.advanced_image_ref,
                          'Cloud image not found.')
    @decorators.attr(type='slow')
    @utils.services('compute', 'network')
    def test_taas_forwarded_traffic_negative(self):
        """Check that TAAS doesn't forward traffic"""

        with self._setup_topology(taas=False, use_taas_cloud_image=True):
            # Check that traffic was NOT forwarded to TAAS service
            self.assertFalse(self._check_icmp_traffic())

    @decorators.idempotent_id('fcb15ca3-ef61-11e9-9792-f45c89c47e12')
    @testtools.skipUnless(CONF.neutron_plugin_options.advanced_image_ref,
                          'Cloud image not found.')
    @decorators.attr(type='slow')
    @utils.services('compute', 'network')
    def test_taas_forwarded_traffic_provider_net_positive(self):
        """Check that TAAS forwards traffic as expected in provider network"""

        with self._setup_topology(use_taas_cloud_image=True,
                                  provider_net=True):
            # Check that traffic was forwarded to TAAS service
            self.assertTrue(self._check_icmp_traffic())

    @decorators.idempotent_id('6c54d9c5-075a-4a1f-bbe6-12c3c9abf1e3')
    @testtools.skipUnless(CONF.neutron_plugin_options.advanced_image_ref,
                          'Cloud image not found.')
    @decorators.attr(type='slow')
    @utils.services('compute', 'network')
    def test_taas_forwarded_traffic_provider_net_negative(self):
        """Check that TAAS doesn't forward traffic in provider network"""

        with self._setup_topology(taas=False, use_taas_cloud_image=True,
                                  provider_net=True):
            # Check that traffic was NOT forwarded to TAAS service
            self.assertFalse(self._check_icmp_traffic())
