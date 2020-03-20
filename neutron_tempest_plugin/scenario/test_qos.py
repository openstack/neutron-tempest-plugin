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
import errno
import socket
import time

from neutron_lib.services.qos import constants as qos_consts
from oslo_log import log as logging
from tempest.common import utils as tutils
from tempest.common import waiters
from tempest.lib import decorators

from neutron_tempest_plugin.api import base as base_api
from neutron_tempest_plugin.common import ssh
from neutron_tempest_plugin.common import utils
from neutron_tempest_plugin import config
from neutron_tempest_plugin.scenario import base
from neutron_tempest_plugin.scenario import constants
from neutron_tempest_plugin.scenario import exceptions as sc_exceptions

CONF = config.CONF
LOG = logging.getLogger(__name__)


def _try_connect(host_ip, port, socket_timeout):
    try:
        client_socket = socket.socket(socket.AF_INET,
                                      socket.SOCK_STREAM)
        client_socket.connect((host_ip, port))
        client_socket.settimeout(socket_timeout)
        return client_socket
    except socket.error as serr:
        if serr.errno == errno.ECONNREFUSED:
            raise sc_exceptions.SocketConnectionRefused(host=host_ip,
                                                        port=port)
        else:
            raise


def _connect_socket(host, port, socket_timeout):
    """Try to initiate a connection to a host using an ip address and a port.

    Trying couple of times until a timeout is reached in case the listening
    host is not ready yet.
    """

    start = time.time()
    while True:
        try:
            return _try_connect(host, port, socket_timeout)
        except sc_exceptions.SocketConnectionRefused:
            if time.time() - start > constants.SOCKET_CONNECT_TIMEOUT:
                raise sc_exceptions.ConnectionTimeoutException(host=host,
                                                               port=port)


class QoSTestMixin(object):
    credentials = ['primary', 'admin']
    force_tenant_isolation = False

    TOLERANCE_FACTOR = 1.5
    BUFFER_SIZE = 512
    LIMIT_BYTES_SEC = (constants.LIMIT_KILO_BITS_PER_SECOND * 1024 *
                       TOLERANCE_FACTOR / 8.0)
    NC_PORT = 1234
    DOWNLOAD_DURATION = 5
    # NOTE(mjozefcz): This makes around 10 retries.
    CHECK_TIMEOUT = DOWNLOAD_DURATION * 10

    def _check_bw(self, ssh_client, host, port, expected_bw=LIMIT_BYTES_SEC):
        utils.kill_nc_process(ssh_client)
        self.ensure_nc_listen(ssh_client, port, "tcp")

        # Open TCP socket to remote VM and download big file
        start_time = time.time()
        client_socket = _connect_socket(
            host, port, constants.SOCKET_CONNECT_TIMEOUT)
        total_bytes_read = 0
        try:
            while time.time() - start_time < self.DOWNLOAD_DURATION:
                data = client_socket.recv(self.BUFFER_SIZE)
                total_bytes_read += len(data)

            # Calculate and return actual BW + logging result
            time_elapsed = time.time() - start_time
            bytes_per_second = total_bytes_read / time_elapsed

            LOG.debug("time_elapsed = %(time_elapsed).16f, "
                      "total_bytes_read = %(total_bytes_read)d, "
                      "bytes_per_second = %(bytes_per_second)d, "
                      "expected_bw = %(expected_bw)d.",
                      {'time_elapsed': time_elapsed,
                       'total_bytes_read': total_bytes_read,
                       'bytes_per_second': bytes_per_second,
                       'expected_bw': expected_bw})
            return bytes_per_second <= expected_bw
        except socket.timeout:
            LOG.warning('Socket timeout while reading the remote file, bytes '
                        'read: %s', total_bytes_read)
            utils.kill_nc_process(ssh_client)
            return False
        finally:
            client_socket.close()

    def _create_ssh_client(self):
        return ssh.Client(self.fip['floating_ip_address'],
                          CONF.validation.image_ssh_user,
                          pkey=self.keypair['private_key'])

    def _test_basic_resources(self):
        self.setup_network_and_server()
        self.check_connectivity(self.fip['floating_ip_address'],
                                CONF.validation.image_ssh_user,
                                self.keypair['private_key'])
        rulesets = [{'protocol': 'tcp',
                     'direction': 'ingress',
                     'port_range_min': self.NC_PORT,
                     'port_range_max': self.NC_PORT,
                     'remote_ip_prefix': '0.0.0.0/0'}]
        self.create_secgroup_rules(rulesets,
                                   self.security_groups[-1]['id'])

    def _create_qos_policy(self):
        policy = self.os_admin.network_client.create_qos_policy(
                                        name='test-policy',
                                        description='test-qos-policy',
                                        shared=True)
        return policy['policy']['id']

    def _create_server_by_port(self, port=None):
        """Launch an instance using a port interface;

        In case that the given port is None, a new port is created,
        activated and configured with inbound SSH and TCP connection.
        """
        # Create and activate the port that will be assign to the instance.
        if port is None:
            secgroup = self.create_security_group()
            self.create_loginable_secgroup_rule(
                secgroup_id=secgroup['id'])

            secgroup_rules = [{'protocol': 'tcp',
                               'direction': 'ingress',
                               'port_range_min': self.NC_PORT,
                               'port_range_max': self.NC_PORT,
                               'remote_ip_prefix': '0.0.0.0/0'}]

            self.create_secgroup_rules(secgroup_rules,
                                       secgroup['id'])

            port = self.create_port(self.network,
                                    security_groups=[secgroup['id']])
            self.fip = self.create_floatingip(port=port)

        keypair = self.create_keypair()

        server_kwargs = {
            'flavor_ref': CONF.compute.flavor_ref,
            'image_ref': CONF.compute.image_ref,
            'key_name': keypair['name'],
            'networks': [{'port': port['id']}],
        }

        server = self.create_server(**server_kwargs)
        self.wait_for_server_active(server['server'])
        self.check_connectivity(self.fip['floating_ip_address'],
                                CONF.validation.image_ssh_user,
                                keypair['private_key'])
        return server, port


class QoSTest(QoSTestMixin, base.BaseTempestTestCase):
    @classmethod
    @tutils.requires_ext(extension="qos", service="network")
    @base_api.require_qos_rule_type(qos_consts.RULE_TYPE_BANDWIDTH_LIMIT)
    def resource_setup(cls):
        super(QoSTest, cls).resource_setup()

    @decorators.idempotent_id('00682a0c-b72e-11e8-b81e-8c16450ea513')
    def test_qos_basic_and_update(self):
        """This test covers both:

            1) Basic QoS functionality
            This is a basic test that check that a QoS policy with
            a bandwidth limit rule is applied correctly by sending
            a file from the instance to the test node.
            Then calculating the bandwidth every ~1 sec by the number of bits
            received / elapsed time.

            2) Update QoS policy
            Administrator has the ability to update existing QoS policy,
            this test is planned to verify that:
            - actual BW is affected as expected after updating QoS policy.
            Test scenario:
            1) Associating QoS Policy with "Original_bandwidth"
               to the test node
            2) BW validation - by downloading file on test node.
               ("Original_bandwidth" is expected)
            3) Updating existing QoS Policy to a new BW value
               "Updated_bandwidth"
            4) BW validation - by downloading file on test node.
               ("Updated_bandwidth" is expected)
            Note:
            There are two options to associate QoS policy to VM:
            "Neutron Port" or "Network", in this test
            both options are covered.
        """

        # Setup resources
        self._test_basic_resources()
        ssh_client = self._create_ssh_client()

        # Create QoS policy
        bw_limit_policy_id = self._create_qos_policy()

        # As admin user create QoS rule
        rule_id = self.os_admin.network_client.create_bandwidth_limit_rule(
            policy_id=bw_limit_policy_id,
            max_kbps=constants.LIMIT_KILO_BITS_PER_SECOND,
            max_burst_kbps=constants.LIMIT_KILO_BITS_PER_SECOND)[
                'bandwidth_limit_rule']['id']

        # Associate QoS to the network
        self.os_admin.network_client.update_network(
            self.network['id'], qos_policy_id=bw_limit_policy_id)

        # Basic test, Check that actual BW while downloading file
        # is as expected (Original BW)
        utils.wait_until_true(lambda: self._check_bw(
            ssh_client,
            self.fip['floating_ip_address'],
            port=self.NC_PORT),
            timeout=self.CHECK_TIMEOUT,
            sleep=1)

        # As admin user update QoS rule
        self.os_admin.network_client.update_bandwidth_limit_rule(
            bw_limit_policy_id,
            rule_id,
            max_kbps=constants.LIMIT_KILO_BITS_PER_SECOND * 2,
            max_burst_kbps=constants.LIMIT_KILO_BITS_PER_SECOND * 2)

        # Check that actual BW while downloading file
        # is as expected (Update BW)
        utils.wait_until_true(lambda: self._check_bw(
            ssh_client,
            self.fip['floating_ip_address'],
            port=self.NC_PORT,
            expected_bw=QoSTest.LIMIT_BYTES_SEC * 2),
            timeout=self.CHECK_TIMEOUT,
            sleep=1)

        # Create a new QoS policy
        bw_limit_policy_id_new = self._create_qos_policy()

        # As admin user create a new QoS rule
        rule_id_new = self.os_admin.network_client.create_bandwidth_limit_rule(
            policy_id=bw_limit_policy_id_new,
            max_kbps=constants.LIMIT_KILO_BITS_PER_SECOND,
            max_burst_kbps=constants.LIMIT_KILO_BITS_PER_SECOND)[
                'bandwidth_limit_rule']['id']

        # Associate a new QoS policy to Neutron port
        self.os_admin.network_client.update_port(
            self.port['id'], qos_policy_id=bw_limit_policy_id_new)

        # Check that actual BW while downloading file
        # is as expected (Original BW)
        utils.wait_until_true(lambda: self._check_bw(
            ssh_client,
            self.fip['floating_ip_address'],
            port=self.NC_PORT),
            timeout=self.CHECK_TIMEOUT,
            sleep=1)

        # As admin user update QoS rule
        self.os_admin.network_client.update_bandwidth_limit_rule(
            bw_limit_policy_id_new,
            rule_id_new,
            max_kbps=constants.LIMIT_KILO_BITS_PER_SECOND * 3,
            max_burst_kbps=constants.LIMIT_KILO_BITS_PER_SECOND * 3)

        # Check that actual BW while downloading file
        # is as expected (Update BW)
        utils.wait_until_true(lambda: self._check_bw(
            ssh_client,
            self.fip['floating_ip_address'],
            port=self.NC_PORT,
            expected_bw=QoSTest.LIMIT_BYTES_SEC * 3),
            timeout=self.CHECK_TIMEOUT,
            sleep=1)

    @decorators.idempotent_id('66e5673e-0522-11ea-8d71-362b9e155667')
    def test_attach_previously_used_port_to_new_instance(self):
        """The test spawns new instance using port with QoS policy.

        Ports with attached QoS policy could be used multiple times.
        The policy rules have to be enforced on the new machines.
        """
        self.network = self.create_network()
        self.subnet = self.create_subnet(self.network)
        self.router = self.create_router_by_client()
        self.create_router_interface(self.router['id'], self.subnet['id'])

        vm, vm_port = self._create_server_by_port()

        port_policy = self.os_admin.network_client.create_qos_policy(
            name='port-policy',
            description='policy for attach',
            shared=False)['policy']

        rule = self.os_admin.network_client.create_bandwidth_limit_rule(
            policy_id=port_policy['id'],
            max_kbps=constants.LIMIT_KILO_BITS_PER_SECOND,
            max_burst_kbps=constants.LIMIT_KILO_BITS_PER_SECOND)[
                    'bandwidth_limit_rule']

        self.os_admin.network_client.update_port(
            vm_port['id'], qos_policy_id=port_policy['id'])

        self.os_primary.servers_client.delete_server(vm['server']['id'])
        waiters.wait_for_server_termination(
            self.os_primary.servers_client,
            vm['server']['id'])

        # Launch a new server using the same port with attached policy
        self._create_server_by_port(port=vm_port)

        retrieved_port = self.os_admin.network_client.show_port(
            vm_port['id'])
        self.assertEqual(port_policy['id'],
                         retrieved_port['port']['qos_policy_id'],
                         """The expected policy ID is {0},
                         the actual value is {1}""".
                         format(port_policy['id'],
                                retrieved_port['port']['qos_policy_id']))

        retrieved_policy = self.os_admin.network_client.show_qos_policy(
                           retrieved_port['port']['qos_policy_id'])

        retrieved_rule_id = retrieved_policy['policy']['rules'][0]['id']
        self.assertEqual(rule['id'],
                         retrieved_rule_id,
                         """The expected rule ID is {0},
                         the actual value is {1}""".
                         format(rule['id'], retrieved_rule_id))

    @decorators.idempotent_id('4eee64da-5646-11ea-82b4-0242ac130003')
    def test_create_instance_using_network_with_existing_policy(self):
        network = self.create_network()

        qos_policy = self.os_admin.network_client.create_qos_policy(
            name='network-policy',
            shared=False)['policy']

        rule = self.os_admin.network_client.create_bandwidth_limit_rule(
            policy_id=qos_policy['id'],
            max_kbps=constants.LIMIT_KILO_BITS_PER_SECOND,
            max_burst_kbps=constants.LIMIT_KILO_BITS_PER_SECOND)

        network = self.os_admin.network_client.update_network(
                  network['id'],
                  qos_policy_id=qos_policy['id'])['network']
        self.setup_network_and_server(network=network)
        retrieved_net = self.client.show_network(network['id'])
        self.assertEqual(qos_policy['id'],
                         retrieved_net['network']['qos_policy_id'],
                         """The expected policy ID is {0},
                         the actual value is {1}""".
                         format(qos_policy['id'],
                                retrieved_net['network']['qos_policy_id']))

        retrieved_policy = self.os_admin.network_client.show_qos_policy(
                           retrieved_net['network']['qos_policy_id'])
        retrieved_rule_id = retrieved_policy['policy']['rules'][0]['id']

        self.assertEqual(rule['bandwidth_limit_rule']['id'],
                         retrieved_rule_id,
                         """The expected rule ID is {0},
                         the actual value is {1}""".
                         format(rule['bandwidth_limit_rule']['id'],
                                retrieved_rule_id))
