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

    FILE_SIZE = 1024 * 1024
    TOLERANCE_FACTOR = 1.5
    BUFFER_SIZE = 512
    COUNT = FILE_SIZE / BUFFER_SIZE
    LIMIT_BYTES_SEC = (constants.LIMIT_KILO_BITS_PER_SECOND * 1024 *
                       TOLERANCE_FACTOR / 8.0)
    FILE_PATH = "/tmp/img"

    NC_PORT = 1234
    FILE_DOWNLOAD_TIMEOUT = 120

    def _create_file_for_bw_tests(self, ssh_client):
        cmd = ("(dd if=/dev/zero bs=%(bs)d count=%(count)d of=%(file_path)s) "
               % {'bs': self.BUFFER_SIZE, 'count': self.COUNT,
               'file_path': self.FILE_PATH})
        ssh_client.exec_command(cmd, timeout=5)
        cmd = "stat -c %%s %s" % self.FILE_PATH
        filesize = ssh_client.exec_command(cmd, timeout=5)
        if int(filesize.strip()) != self.FILE_SIZE:
            raise sc_exceptions.FileCreationFailedException(
                file=self.FILE_PATH)

    def _check_bw(self, ssh_client, host, port, expected_bw=LIMIT_BYTES_SEC):
        utils.kill_nc_process(ssh_client)
        cmd = ("(nc -ll -p %(port)d < %(file_path)s > /dev/null &)" % {
                'port': port, 'file_path': self.FILE_PATH})
        ssh_client.exec_command(cmd, timeout=5)

        # Open TCP socket to remote VM and download big file
        start_time = time.time()
        socket_timeout = self.FILE_SIZE * self.TOLERANCE_FACTOR / expected_bw
        client_socket = _connect_socket(host, port, socket_timeout)
        total_bytes_read = 0
        try:
            while total_bytes_read < self.FILE_SIZE:
                data = client_socket.recv(self.BUFFER_SIZE)
                total_bytes_read += len(data)

            # Calculate and return actual BW + logging result
            time_elapsed = time.time() - start_time
            bytes_per_second = total_bytes_read / time_elapsed

            LOG.debug("time_elapsed = %(time_elapsed).16f, "
                      "total_bytes_read = %(total_bytes_read)d, "
                      "bytes_per_second = %(bytes_per_second)d",
                      {'time_elapsed': time_elapsed,
                       'total_bytes_read': total_bytes_read,
                       'bytes_per_second': bytes_per_second})
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

        # Create file on VM
        self._create_file_for_bw_tests(ssh_client)

        # Basic test, Check that actual BW while downloading file
        # is as expected (Original BW)
        utils.wait_until_true(lambda: self._check_bw(
            ssh_client,
            self.fip['floating_ip_address'],
            port=self.NC_PORT),
            timeout=self.FILE_DOWNLOAD_TIMEOUT,
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
            timeout=self.FILE_DOWNLOAD_TIMEOUT,
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
            timeout=self.FILE_DOWNLOAD_TIMEOUT,
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
            port=self.NC_PORT, expected_bw=QoSTest.LIMIT_BYTES_SEC * 3),
            timeout=self.FILE_DOWNLOAD_TIMEOUT,
            sleep=1)
