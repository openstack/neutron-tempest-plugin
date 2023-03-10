# Copyright 2021 Red Hat, Inc
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
from tempest.lib.common.utils import data_utils
from tempest.lib import decorators

from neutron_tempest_plugin.common import ssh
from neutron_tempest_plugin.common import utils
from neutron_tempest_plugin import config
from neutron_tempest_plugin import exceptions
from neutron_tempest_plugin.scenario import base


CONF = config.CONF
LOG = log.getLogger(__name__)


# -s0 -l -c5 &> /tmp/tcpdump_out &
def get_receiver_script(result_file, packets_expected):
    """Script that listen icmp echos and write the output on result_file."""
    return """#!/bin/bash
export LC_ALL=en_US.UTF-8
tcpdump -i any -n -v 'icmp[icmptype] = icmp-echoreply or icmp[icmptype] = \
icmp-echo' -s0 -l -c%(packets_expected)d &> %(result_file)s &
    """ % {'result_file': result_file,
           'packets_expected': packets_expected}


def get_sender_script(result_file, receiver_address, completed_message):
    """Script that sends packets to the receiver server."""
    return """#!/bin/bash
export LC_ALL=en_US.UTF-8
ping -c 5 %(address)s
echo '%(completed_message)s' > %(result_file)s &
    """ % {'result_file': result_file,
           'address': receiver_address,
           'completed_message': completed_message}


class MacLearningTest(base.BaseTempestTestCase):

    credentials = ['primary', 'admin']
    force_tenant_isolation = False

    # Import configuration options
    available_type_drivers = (
        CONF.neutron_plugin_options.available_type_drivers)

    completed_message = "Done!"
    output_file = "/tmp/tcpdump_out"
    sender_output_file = "/tmp/sender_out"
    sender_script_file = "/tmp/ping.sh"
    receiver_script_file = "/tmp/traffic.sh"

    @classmethod
    def skip_checks(cls):
        super(MacLearningTest, cls).skip_checks()
        advanced_image_available = (
            CONF.neutron_plugin_options.advanced_image_ref or
            CONF.neutron_plugin_options.default_image_is_advanced)
        if not advanced_image_available:
            skip_reason = "This test requires advanced tools to be executed"
            raise cls.skipException(skip_reason)

    @classmethod
    def resource_setup(cls):
        super(MacLearningTest, cls).resource_setup()

        if CONF.neutron_plugin_options.default_image_is_advanced:
            cls.flavor_ref = CONF.compute.flavor_ref
            cls.image_ref = CONF.compute.image_ref
            cls.username = CONF.validation.image_ssh_user
        else:
            cls.flavor_ref = (
                CONF.neutron_plugin_options.advanced_image_flavor_ref)
            cls.image_ref = CONF.neutron_plugin_options.advanced_image_ref
            cls.username = CONF.neutron_plugin_options.advanced_image_ssh_user

        # Setup basic topology for servers so that we can log into them
        # It's important to keep port security and DHCP disabled for this test
        cls.network = cls.create_network(port_security_enabled=False)
        cls.subnet = cls.create_subnet(cls.network, enable_dhcp=False)
        cls.router = cls.create_router_by_client()
        cls.create_router_interface(cls.router['id'], cls.subnet['id'])

        cls.keypair = cls.create_keypair()

    def _create_server(self):
        name = data_utils.rand_name("maclearning-server")
        server = self.create_server(
            flavor_ref=self.flavor_ref,
            image_ref=self.image_ref,
            key_name=self.keypair['name'], name=name,
            networks=[{'uuid': self.network['id']}],
            config_drive='True')['server']
        self.wait_for_server_active(server)
        self.wait_for_guest_os_ready(server)
        server['port'] = self.client.list_ports(
            network_id=self.network['id'], device_id=server['id'])['ports'][0]
        server['fip'] = self.create_floatingip(port=server['port'])
        server['ssh_client'] = ssh.Client(server['fip']['floating_ip_address'],
                                          self.username,
                                          pkey=self.keypair['private_key'])
        return server

    def _prepare_sender(self, server, address):
        check_script = get_sender_script(self.sender_output_file, address,
                                         self.completed_message)
        self._check_cmd_installed_on_server(server['ssh_client'], server,
                                            'tcpdump')
        server['ssh_client'].execute_script(
            'echo "%s" > %s' % (check_script, self.sender_script_file))

    def _prepare_listener(self, server, n_packets):
        check_script = get_receiver_script(
            result_file=self.output_file,
            packets_expected=n_packets)
        self._check_cmd_installed_on_server(server['ssh_client'], server,
                                            'tcpdump')
        server['ssh_client'].execute_script(
            'echo "%s" > %s' % (check_script, self.receiver_script_file))

    @decorators.idempotent_id('013686ac-23b1-23e4-8361-10b1c98a2861')
    def test_mac_learning_vms_on_same_network(self):
        """Test mac learning works in a network.

        The receiver server will receive all the sent packets.
        The non receiver should not receive any.

        """
        sender = self._create_server()
        receiver = self._create_server()
        non_receiver = self._create_server()

        def check_server_result(server, expected_result, output_file):
            result = server['ssh_client'].execute_script(
                "cat {path} || echo '{path} not exists yet'".format(
                    path=output_file))
            LOG.debug("VM result: %s", result)
            return expected_result in result

        # Prepare the server that is intended to receive the packets
        self._prepare_listener(receiver, 5)

        # Prepare the server that is not intended receive of the packets.
        self._prepare_listener(non_receiver, 2)

        # Run the scripts
        for server in [receiver, non_receiver]:
            server['ssh_client'].execute_script(
                "bash %s" % self.receiver_script_file, become_root=True)

        # Prepare the server that will make the ping.
        target_ip = receiver['port']['fixed_ips'][0]['ip_address']
        self._prepare_sender(sender, address=target_ip)

        LOG.debug("The receiver IP is: %s", target_ip)
        # Run the sender node script
        sender['ssh_client'].execute_script(
                "bash %s" % self.sender_script_file, become_root=True)

        # Check if the message was sent.
        utils.wait_until_true(
            lambda: check_server_result(
                sender, self.completed_message,
                self.sender_output_file),
            exception=RuntimeError(
                "Sender script wasn't executed properly"))

        # Check receiver server
        receiver_expected_result = '5 packets captured'
        utils.wait_until_true(
            lambda: check_server_result(receiver,
                receiver_expected_result, self.output_file),
            exception=RuntimeError(
                'Receiver server did not receive expected packet'))

        # Check the non_receiver server
        non_receiver_expected_result = '0 packets captured'
        try:
            LOG.debug("Try killing non-receiver tcpdump")
            non_receiver['ssh_client'].execute_script(
                "killall tcpdump && sleep 2", become_root=True)
        except exceptions.SSHScriptFailed:
            LOG.debug("Killing tcpdump failed")
            self.assertTrue(check_server_result(non_receiver,
                            non_receiver_expected_result,
                            self.output_file),
                            'Non targeted server received unexpected packets')
            return
