# Copyright 2019 Red Hat, Inc.
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

from neutron_lib import constants
from oslo_log import log
from tempest.lib.common.utils import data_utils
from tempest.lib import decorators
from tempest.lib import exceptions as lib_exc

from neutron_tempest_plugin.common import ssh
from neutron_tempest_plugin.common import utils
from neutron_tempest_plugin import config
from neutron_tempest_plugin.scenario import base

CONF = config.CONF

LOG = log.getLogger(__name__)


class PortForwardingTestJSON(base.BaseTempestTestCase):

    credentials = ['primary', 'admin']
    required_extensions = ['router', 'floating-ip-port-forwarding']

    @classmethod
    def resource_setup(cls):
        super(PortForwardingTestJSON, cls).resource_setup()
        cls.skip_if_no_extension_enabled_in_l3_agents("port_forwarding")
        cls.network = cls.create_network()
        cls.subnet = cls.create_subnet(cls.network)
        cls.router = cls.create_router_by_client()
        cls.create_router_interface(cls.router['id'], cls.subnet['id'])
        cls.fip = cls.create_floatingip()
        cls.secgroup = cls.create_security_group(
            name=data_utils.rand_name("test_port_secgroup"))
        cls.create_loginable_secgroup_rule(secgroup_id=cls.secgroup['id'])
        udp_sg_rule = {'protocol': constants.PROTO_NAME_UDP,
                       'direction': constants.INGRESS_DIRECTION,
                       'remote_ip_prefix': '0.0.0.0/0'}
        cls.create_secgroup_rules(
            [udp_sg_rule], secgroup_id=cls.secgroup['id'])
        cls.keypair = cls.create_keypair()

    def _prepare_resources(self, num_servers, internal_tcp_port=22,
                           external_port_base=1025):
        servers = []
        for i in range(1, num_servers + 1):
            internal_udp_port = internal_tcp_port + 10
            external_tcp_port = external_port_base + i
            external_udp_port = external_tcp_port + 10
            name = data_utils.rand_name("server-%s" % i)
            port = self.create_port(
                self.network,
                security_groups=[self.secgroup['id']])
            server = self.create_server(
                flavor_ref=CONF.compute.flavor_ref,
                image_ref=CONF.compute.image_ref,
                key_name=self.keypair['name'], name=name,
                networks=[{'port': port['id']}])['server']
            server['name'] = name
            self.wait_for_server_active(server)
            self.wait_for_guest_os_ready(server)
            server['port_forwarding_tcp'] = self.create_port_forwarding(
                self.fip['id'],
                internal_port_id=port['id'],
                internal_ip_address=port['fixed_ips'][0]['ip_address'],
                internal_port=internal_tcp_port,
                external_port=external_tcp_port,
                protocol=constants.PROTO_NAME_TCP)
            server['port_forwarding_udp'] = self.create_port_forwarding(
                self.fip['id'],
                internal_port_id=port['id'],
                internal_ip_address=port['fixed_ips'][0]['ip_address'],
                internal_port=internal_udp_port,
                external_port=external_udp_port,
                protocol=constants.PROTO_NAME_UDP)
            servers.append(server)
        return servers

    def _test_udp_port_forwarding(self, servers, timeout=None):

        def _message_received(server, ssh_client, expected_msg):
            self.nc_listen(ssh_client,
                           server['port_forwarding_udp']['internal_port'],
                           constants.PROTO_NAME_UDP,
                           expected_msg,
                           [server])
            received_msg = self.nc_client(
                self.fip['floating_ip_address'],
                server['port_forwarding_udp']['external_port'],
                constants.PROTO_NAME_UDP)
            return expected_msg in received_msg

        for server in servers:
            expected_msg = "%s-UDP-test" % server['name']
            ssh_client = ssh.Client(
                self.fip['floating_ip_address'],
                CONF.validation.image_ssh_user,
                pkey=self.keypair['private_key'],
                port=server['port_forwarding_tcp']['external_port'])
            wait_params = {
                'exception': RuntimeError(
                    "Timed out waiting for message from server {!r} ".format(
                        server['id']))
            }
            if timeout:
                wait_params['timeout'] = timeout
            utils.wait_until_true(
                lambda: _message_received(server, ssh_client, expected_msg),
                **wait_params)

    @decorators.idempotent_id('ab40fc48-ca8d-41a0-b2a3-f6679c847bfe')
    def test_port_forwarding_to_2_servers(self):
        servers = self._prepare_resources(num_servers=2,
                                          external_port_base=1035)
        # Test TCP port forwarding by SSH to each server
        self.check_servers_hostnames(servers)
        # And now test UDP port forwarding using nc
        self._test_udp_port_forwarding(servers)

    @decorators.idempotent_id('aa19d46c-a4a6-11ea-bb37-0242ac130002')
    def test_port_forwarding_editing_and_deleting_tcp_rule(self):
        test_ext_port = 3333
        server = self._prepare_resources(num_servers=1,
                                         external_port_base=1045)
        fip_id = server[0]['port_forwarding_tcp']['floatingip_id']
        pf_id = server[0]['port_forwarding_tcp']['id']

        # Check connectivity with the original parameters
        self.check_servers_hostnames(server)

        def fip_pf_connectivity(test_ssh_connect_timeout=60):
            try:
                self.check_servers_hostnames(
                    server, timeout=test_ssh_connect_timeout)
                return True
            except (AssertionError, lib_exc.SSHTimeout):
                return False

        def no_fip_pf_connectivity():
            return not fip_pf_connectivity(6)

        # Update external port and check connectivity with original parameters
        # Port under server[0]['port_forwarding_tcp']['external_port'] should
        # not answer at this point.
        self.client.update_port_forwarding(fip_id, pf_id,
                                           external_port=test_ext_port)
        utils.wait_until_true(
            no_fip_pf_connectivity,
            exception=RuntimeError(
                "Connection to the server {!r} through "
                "port {!r} is still possible.".format(
                    server[0]['id'],
                    server[0]['port_forwarding_tcp']['external_port'])))

        # Check connectivity with the new parameters
        server[0]['port_forwarding_tcp']['external_port'] = test_ext_port
        utils.wait_until_true(
            fip_pf_connectivity,
            exception=RuntimeError(
                "Connection to the server {!r} through "
                "port {!r} is not possible.".format(
                    server[0]['id'],
                    server[0]['port_forwarding_tcp']['external_port'])))

        # Remove port forwarding and ensure connection stops working.
        self.client.delete_port_forwarding(fip_id, pf_id)
        self.assertRaises(lib_exc.NotFound, self.client.get_port_forwarding,
                          fip_id, pf_id)
        utils.wait_until_true(
            no_fip_pf_connectivity,
            exception=RuntimeError(
                "Connection to the server {!r} through "
                "port {!r} is still possible.".format(
                    server[0]['id'],
                    server[0]['port_forwarding_tcp']['external_port'])))

    @decorators.idempotent_id('6d05b1b2-6109-4c30-b402-1503f4634acb')
    def test_port_forwarding_editing_and_deleting_udp_rule(self):
        test_ext_port = 3344
        server = self._prepare_resources(num_servers=1,
                                         external_port_base=1055)
        fip_id = server[0]['port_forwarding_udp']['floatingip_id']
        pf_id = server[0]['port_forwarding_udp']['id']

        # Check connectivity with the original parameters
        self.check_servers_hostnames(server)

        def fip_pf_udp_connectivity(test_udp_timeout=60):
            try:
                self._test_udp_port_forwarding(server, test_udp_timeout)
                return True
            except (AssertionError, RuntimeError):
                return False

        def no_fip_pf_udp_connectivity():
            return not fip_pf_udp_connectivity(6)

        # Update external port and check connectivity with original parameters
        # Port under server[0]['port_forwarding_udp']['external_port'] should
        # not answer at this point.
        self.client.update_port_forwarding(fip_id, pf_id,
                                           external_port=test_ext_port)
        utils.wait_until_true(
            no_fip_pf_udp_connectivity,
            exception=RuntimeError(
                "Connection to the server {!r} through "
                "port {!r} is still possible.".format(
                    server[0]['id'],
                    server[0]['port_forwarding_udp']['external_port'])))

        # Check connectivity with the new parameters
        server[0]['port_forwarding_udp']['external_port'] = test_ext_port
        utils.wait_until_true(
            fip_pf_udp_connectivity,
            exception=RuntimeError(
                "Connection to the server {!r} through "
                "port {!r} is not possible.".format(
                    server[0]['id'],
                    server[0]['port_forwarding_udp']['external_port'])))

        # Remove port forwarding and ensure connection stops working.
        self.client.delete_port_forwarding(fip_id, pf_id)
        self.assertRaises(lib_exc.NotFound, self.client.get_port_forwarding,
                          fip_id, pf_id)
        utils.wait_until_true(
            no_fip_pf_udp_connectivity,
            exception=RuntimeError(
                "Connection to the server {!r} through "
                "port {!r} is still possible.".format(
                    server[0]['id'],
                    server[0]['port_forwarding_udp']['external_port'])))

    @decorators.idempotent_id('5971881d-06a0-459e-b636-ce5d1929e2d4')
    def test_port_forwarding_to_2_fixed_ips(self):
        port = self.create_port(self.network,
            security_groups=[self.secgroup['id']])
        name = data_utils.rand_name("server-0")
        server = self.create_server(flavor_ref=CONF.compute.flavor_ref,
            image_ref=CONF.compute.image_ref, key_name=self.keypair['name'],
            name=name, networks=[{'port': port['id']}])['server']
        server['name'] = name
        self.wait_for_server_active(server)
        self.wait_for_guest_os_ready(server)

        # Add a second fixed_ip address to port (same subnet)
        internal_subnet_id = port['fixed_ips'][0]['subnet_id']
        port['fixed_ips'].append({'subnet_id': internal_subnet_id})
        port = self.update_port(port, fixed_ips=port['fixed_ips'])
        internal_ip_address1 = port['fixed_ips'][0]['ip_address']
        internal_ip_address2 = port['fixed_ips'][1]['ip_address']
        pfs = []
        for ip_address, external_port in [(internal_ip_address1, 1066),
                                          (internal_ip_address2, 1067)]:
            pf = self.create_port_forwarding(
                self.fip['id'], internal_port_id=port['id'],
                internal_ip_address=ip_address,
                internal_port=22, external_port=external_port,
                protocol=constants.PROTO_NAME_TCP)
            pfs.append(pf)

        test_ssh_connect_timeout = 32
        number_of_connects = 0
        for pf in pfs:
            try:
                self.check_servers_hostnames(
                    [server], timeout=test_ssh_connect_timeout,
                    external_port=pf['external_port'])
                number_of_connects += 1
            except (AssertionError, lib_exc.SSHTimeout):
                pass

        # TODO(flaviof): Quite possibly, the server is using only one of the
        # fixed ips associated with the neutron port. Being so, we should not
        # fail the test, as long as at least one connection was successful.
        self.assertGreaterEqual(
            number_of_connects, 1, "Did not connect via FIP port forwarding")
