# Copyright 2018 Red Hat, Inc.
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
from neutron_lib import constants
from neutron_lib.utils import test
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
PYTHON3_BIN = "python3"


def get_receiver_script(group, port, hello_message, ack_message, result_file):

    return """
import socket
import struct
import sys

multicast_group = '%(group)s'
server_address = ('', %(port)s)

# Create the socket
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)

# Bind to the server address
sock.bind(server_address)

# Tell the operating system to add the socket to the multicast group
# on all interfaces.
group = socket.inet_aton(multicast_group)
mreq = struct.pack('4sL', group, socket.INADDR_ANY)
sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)

# Receive/respond loop
with open('%(result_file)s', 'w') as f:
    f.write('%(hello_message)s')
    f.flush()
    data, address = sock.recvfrom(1024)
    f.write('received ' + str(len(data)) + ' bytes from ' + str(address))
    f.write(str(data))
sock.sendto(b'%(ack_message)s', address)
    """ % {'group': group,
           'port': port,
           'hello_message': hello_message,
           'ack_message': ack_message,
           'result_file': result_file}


def get_sender_script(group, port, message, result_file):

    return """
import socket
import sys

message = b'%(message)s'
multicast_group = ('%(group)s', %(port)s)

# Create the datagram socket
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
# Set the time-to-live for messages to 1 so they do not go past the
# local network segment.
sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 1)

# Set a timeout so the socket does not block indefinitely when trying
# to receive data.
sock.settimeout(1)

with open('%(result_file)s', 'w') as f:
    try:
        # Send data to the multicast group
        sent = sock.sendto(message, multicast_group)

        # Look for responses from all recipients
        while True:
            try:
                data, server = sock.recvfrom(1024)
            except socket.timeout:
                f.write('timed out, no more responses')
                break
            else:
                f.write('received reply ' + str(data) + ' from ' + str(server))
    finally:
        sys.stdout.write('closing socket')
        sock.close()
    """ % {'group': group,
           'port': port,
           'message': message,
           'result_file': result_file}


def get_unregistered_script(group, result_file):
    return """#!/bin/bash
export LC_ALL=en_US.UTF-8
tcpdump -i any -s0 -vv host %(group)s -vvneA -s0 -l &> %(result_file)s &
    """ % {'group': group,
           'result_file': result_file}


class BaseMulticastTest(object):

    credentials = ['primary']
    force_tenant_isolation = False

    # Import configuration options
    available_type_drivers = (
        CONF.neutron_plugin_options.available_type_drivers)

    hello_message = "I am waiting..."
    multicast_port = 5007
    multicast_message = "Big Bang"
    receiver_output_file = "/tmp/receiver_mcast_out"
    sender_output_file = "/tmp/sender_mcast_out"
    unregistered_output_file = "/tmp/unregistered_mcast_out"

    @classmethod
    def skip_checks(cls):
        super(BaseMulticastTest, cls).skip_checks()
        advanced_image_available = (
            CONF.neutron_plugin_options.advanced_image_ref or
            CONF.neutron_plugin_options.default_image_is_advanced)
        if not advanced_image_available:
            skip_reason = "This test require advanced tools for this test"
            raise cls.skipException(skip_reason)

    @classmethod
    def resource_setup(cls):
        super(BaseMulticastTest, cls).resource_setup()

        if CONF.neutron_plugin_options.default_image_is_advanced:
            cls.flavor_ref = CONF.compute.flavor_ref
            cls.image_ref = CONF.compute.image_ref
            cls.username = CONF.validation.image_ssh_user
        else:
            cls.flavor_ref = (
                CONF.neutron_plugin_options.advanced_image_flavor_ref)
            cls.image_ref = CONF.neutron_plugin_options.advanced_image_ref
            cls.username = CONF.neutron_plugin_options.advanced_image_ssh_user

        # setup basic topology for servers we can log into it
        cls.network = cls.create_network()
        cls.subnet = cls.create_subnet(cls.network)
        cls.router = cls.create_router_by_client()
        cls.create_router_interface(cls.router['id'], cls.subnet['id'])

        cls.keypair = cls.create_keypair()

        cls.secgroup = cls.os_primary.network_client.create_security_group(
            name='secgroup_mtu')
        cls.security_groups.append(cls.secgroup['security_group'])
        cls.create_loginable_secgroup_rule(
            secgroup_id=cls.secgroup['security_group']['id'])
        cls.create_pingable_secgroup_rule(
            secgroup_id=cls.secgroup['security_group']['id'])
        # Create security group rule for UDP (multicast traffic)
        cls.create_secgroup_rules(
            rule_list=[dict(protocol=constants.PROTO_NAME_UDP,
                            direction=constants.INGRESS_DIRECTION,
                            remote_ip_prefix=cls.any_addresses,
                            ethertype=cls.ethertype)],
            secgroup_id=cls.secgroup['security_group']['id'])

        # Multicast IP range to be used for multicast group IP asignement
        if '-' in cls.multicast_group_range:
            multicast_group_range = netaddr.IPRange(
                *cls.multicast_group_range.split('-'))
        else:
            multicast_group_range = netaddr.IPNetwork(
                cls.multicast_group_range)
        cls.multicast_group_iter = iter(multicast_group_range)

    def _create_server(self):
        name = data_utils.rand_name("multicast-server")
        server = self.create_server(
            flavor_ref=self.flavor_ref,
            image_ref=self.image_ref,
            key_name=self.keypair['name'], name=name,
            networks=[{'uuid': self.network['id']}],
            security_groups=[{'name': self.secgroup['security_group']['name']}]
        )['server']
        self.wait_for_server_active(server)
        port = self.client.list_ports(
            network_id=self.network['id'], device_id=server['id'])['ports'][0]
        server['fip'] = self.create_floatingip(port=port)
        server['ssh_client'] = ssh.Client(server['fip']['floating_ip_address'],
                                          self.username,
                                          pkey=self.keypair['private_key'])
        self._check_cmd_installed_on_server(server['ssh_client'],
                                            server['id'], PYTHON3_BIN)
        return server

    def _check_cmd_installed_on_server(self, ssh_client, server_id, cmd):
        try:
            ssh_client.execute_script('which %s' % cmd)
        except exceptions.SSHScriptFailed:
            raise self.skipException(
                "%s is not available on server %s" % (cmd, server_id))

    def _prepare_sender(self, server, mcast_address):
        check_script = get_sender_script(
            group=mcast_address, port=self.multicast_port,
            message=self.multicast_message,
            result_file=self.sender_output_file)
        server['ssh_client'].execute_script(
            'echo "%s" > ~/multicast_traffic_sender.py' % check_script)

    def _prepare_receiver(self, server, mcast_address):
        check_script = get_receiver_script(
            group=mcast_address, port=self.multicast_port,
            hello_message=self.hello_message, ack_message=server['id'],
            result_file=self.receiver_output_file)
        ssh_client = ssh.Client(
            server['fip']['floating_ip_address'],
            self.username,
            pkey=self.keypair['private_key'])
        self._check_cmd_installed_on_server(ssh_client, server['id'],
                                            PYTHON3_BIN)
        server['ssh_client'].execute_script(
            'echo "%s" > ~/multicast_traffic_receiver.py' % check_script)

    def _prepare_unregistered(self, server, mcast_address):
        check_script = get_unregistered_script(
            group=mcast_address, result_file=self.unregistered_output_file)
        ssh_client = ssh.Client(
            server['fip']['floating_ip_address'],
            self.username,
            pkey=self.keypair['private_key'])
        self._check_cmd_installed_on_server(ssh_client, server['id'],
                                            'tcpdump')
        server['ssh_client'].execute_script(
            'echo "%s" > ~/unregistered_traffic_receiver.sh' % check_script)

    @test.unstable_test("bug 1850288")
    @decorators.idempotent_id('113486fc-24c9-4be4-8361-03b1c9892867')
    def test_multicast_between_vms_on_same_network(self):
        """Test multicast messaging between two servers on the same network

        [Sender server] -> (Multicast network) -> [Receiver server]
        """
        sender = self._create_server()
        receivers = [self._create_server() for _ in range(1)]
        # Sender can be also receiver of multicast traffic
        receivers.append(sender)
        unregistered = self._create_server()
        self._check_multicast_conectivity(sender=sender, receivers=receivers,
                                          unregistered=unregistered)

    def _is_multicast_traffic_expected(self, mcast_address):
        """Checks if multicast traffic is expected to arrive.

        Checks if multicast traffic is expected to arrive to the
        unregistered VM.

        If IGMP snooping is enabled, multicast traffic should not be
        flooded unless the destination IP is in the range of 224.0.0.X
        [0].

        [0] https://tools.ietf.org/html/rfc4541 (See section 2.1.2)
        """
        return (mcast_address.startswith('224.0.0') or not
                CONF.neutron_plugin_options.is_igmp_snooping_enabled)

    def _check_multicast_conectivity(self, sender, receivers, unregistered):
        """Test multi-cast messaging between two servers

        [Sender server] -> ... some network topology ... -> [Receiver server]
        """
        mcast_address = next(self.multicast_group_iter)
        LOG.debug("Multicast group address: %s", mcast_address)

        def _message_received(client, msg, file_path):
            result = client.execute_script(
                "cat {path} || echo '{path} not exists yet'".format(
                    path=file_path))
            return msg in result

        self._prepare_unregistered(unregistered, mcast_address)

        # Run the unregistered node script
        unregistered['ssh_client'].execute_script(
            "bash ~/unregistered_traffic_receiver.sh", become_root=True)

        self._prepare_sender(sender, mcast_address)
        receiver_ids = []
        for receiver in receivers:
            self._prepare_receiver(receiver, mcast_address)
            receiver['ssh_client'].execute_script(
                "%s ~/multicast_traffic_receiver.py &" % PYTHON3_BIN,
                shell="bash")
            utils.wait_until_true(
                lambda: _message_received(
                    receiver['ssh_client'], self.hello_message,
                    self.receiver_output_file),
                exception=RuntimeError(
                    "Receiver script didn't start properly on server "
                    "{!r}.".format(receiver['id'])))

            receiver_ids.append(receiver['id'])

        # Now lets run scripts on sender
        sender['ssh_client'].execute_script(
            "%s ~/multicast_traffic_sender.py" % PYTHON3_BIN)

        # And check if message was received
        for receiver in receivers:
            utils.wait_until_true(
                lambda: _message_received(
                    receiver['ssh_client'], self.multicast_message,
                    self.receiver_output_file),
                exception=RuntimeError(
                    "Receiver {!r} didn't get multicast message".format(
                        receiver['id'])))

        # TODO(slaweq): add validation of answears on sended server
        replies_result = sender['ssh_client'].execute_script(
            "cat {path} || echo '{path} not exists yet'".format(
                path=self.sender_output_file))
        for receiver_id in receiver_ids:
            self.assertIn(receiver_id, replies_result)

        # Kill the tcpdump command running on the unregistered node so
        # tcpdump flushes its output to the output file
        unregistered['ssh_client'].execute_script(
            "killall tcpdump && sleep 2", become_root=True)

        unregistered_result = unregistered['ssh_client'].execute_script(
            "cat {path} || echo '{path} not exists yet'".format(
                path=self.unregistered_output_file))
        num_of_pckt = (1 if self._is_multicast_traffic_expected(mcast_address)
                       else 0)
        self.assertIn('%d packets captured' % num_of_pckt, unregistered_result)


class MulticastTestIPv4(BaseMulticastTest, base.BaseTempestTestCase):

    # Import configuration options
    multicast_group_range = CONF.neutron_plugin_options.multicast_group_range

    # IP version specific parameters
    _ip_version = constants.IP_VERSION_4
    any_addresses = constants.IPv4_ANY
