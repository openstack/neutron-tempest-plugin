# Copyright (c) 2017 Midokura SARL
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

import time

from neutron_lib import constants as lib_constants
from neutron_lib.services.qos import constants as qos_consts
from neutron_lib.utils import test
from tempest.common import utils
from tempest.common import waiters
from tempest.lib.common.utils import data_utils
from tempest.lib import decorators
from tempest.lib import exceptions
import testscenarios
from testscenarios.scenarios import multiply_scenarios

from neutron_tempest_plugin.api import base as base_api
from neutron_tempest_plugin.common import ssh
from neutron_tempest_plugin.common import utils as common_utils
from neutron_tempest_plugin import config
from neutron_tempest_plugin.scenario import base
from neutron_tempest_plugin.scenario import constants
from neutron_tempest_plugin.scenario import test_qos


CONF = config.CONF


load_tests = testscenarios.load_tests_apply_scenarios


class FloatingIpTestCasesMixin(object):
    credentials = ['primary', 'admin']

    @classmethod
    @utils.requires_ext(extension="router", service="network")
    def resource_setup(cls):
        super(FloatingIpTestCasesMixin, cls).resource_setup()
        cls.network = cls.create_network()
        cls.subnet = cls.create_subnet(cls.network)
        cls.router = cls.create_router_by_client()
        cls.create_router_interface(cls.router['id'], cls.subnet['id'])
        cls.keypair = cls.create_keypair()

        cls.secgroup = cls.os_primary.network_client.create_security_group(
            name=data_utils.rand_name('secgroup'))['security_group']
        cls.security_groups.append(cls.secgroup)
        cls.create_loginable_secgroup_rule(secgroup_id=cls.secgroup['id'])
        cls.create_pingable_secgroup_rule(secgroup_id=cls.secgroup['id'])

        if cls.same_network:
            cls._dest_network = cls.network
        else:
            cls._dest_network = cls._create_dest_network()

    @classmethod
    def _get_external_gateway(cls):
        if CONF.network.public_network_id:
            subnets = cls.os_admin.network_client.list_subnets(
                network_id=CONF.network.public_network_id)

            for subnet in subnets['subnets']:
                if (subnet['gateway_ip'] and
                    subnet['ip_version'] == lib_constants.IP_VERSION_4):
                    return subnet['gateway_ip']

    @classmethod
    def _create_dest_network(cls):
        network = cls.create_network()
        subnet = cls.create_subnet(network)
        cls.create_router_interface(cls.router['id'], subnet['id'])
        return network

    def _create_server(self, create_floating_ip=True, network=None):
        if network is None:
            network = self.network
        port = self.create_port(network, security_groups=[self.secgroup['id']])
        if create_floating_ip:
            fip = self.create_floatingip(port=port)
        else:
            fip = None
        server = self.create_server(
            flavor_ref=CONF.compute.flavor_ref,
            image_ref=CONF.compute.image_ref,
            key_name=self.keypair['name'],
            networks=[{'port': port['id']}])['server']
        waiters.wait_for_server_status(self.os_primary.servers_client,
                                       server['id'],
                                       constants.SERVER_STATUS_ACTIVE)
        return {'port': port, 'fip': fip, 'server': server}

    def _test_east_west(self):
        # The proxy VM is used to control the source VM when it doesn't
        # have a floating-ip.
        if self.src_has_fip:
            proxy = None
            proxy_client = None
        else:
            proxy = self._create_server()
            proxy_client = ssh.Client(proxy['fip']['floating_ip_address'],
                                      CONF.validation.image_ssh_user,
                                      pkey=self.keypair['private_key'])

        # Source VM
        if self.src_has_fip:
            src_server = self._create_server()
            src_server_ip = src_server['fip']['floating_ip_address']
        else:
            src_server = self._create_server(create_floating_ip=False)
            src_server_ip = src_server['port']['fixed_ips'][0]['ip_address']
        ssh_client = ssh.Client(src_server_ip,
                                CONF.validation.image_ssh_user,
                                pkey=self.keypair['private_key'],
                                proxy_client=proxy_client)

        # Destination VM
        if self.dest_has_fip:
            dest_server = self._create_server(network=self._dest_network)
        else:
            dest_server = self._create_server(create_floating_ip=False,
                                              network=self._dest_network)

        # Check connectivity
        self.check_remote_connectivity(ssh_client,
            dest_server['port']['fixed_ips'][0]['ip_address'],
            servers=[src_server, dest_server])
        if self.dest_has_fip:
            self.check_remote_connectivity(ssh_client,
                dest_server['fip']['floating_ip_address'],
                servers=[src_server, dest_server])


class FloatingIpSameNetwork(FloatingIpTestCasesMixin,
                            base.BaseTempestTestCase):
    scenarios = multiply_scenarios([
        ('SRC with FIP', dict(src_has_fip=True)),
        ('SRC without FIP', dict(src_has_fip=False)),
    ], [
        ('DEST with FIP', dict(dest_has_fip=True)),
        ('DEST without FIP', dict(dest_has_fip=False)),
    ])

    same_network = True

    @test.unstable_test("bug 1717302")
    @decorators.idempotent_id('05c4e3b3-7319-4052-90ad-e8916436c23b')
    def test_east_west(self):
        self._test_east_west()


class FloatingIpSeparateNetwork(FloatingIpTestCasesMixin,
                                base.BaseTempestTestCase):
    scenarios = multiply_scenarios([
        ('SRC with FIP', dict(src_has_fip=True)),
        ('SRC without FIP', dict(src_has_fip=False)),
    ], [
        ('DEST with FIP', dict(dest_has_fip=True)),
        ('DEST without FIP', dict(dest_has_fip=False)),
    ])

    same_network = False

    @test.unstable_test("bug 1717302")
    @decorators.idempotent_id('f18f0090-3289-4783-b956-a0f8ac511e8b')
    def test_east_west(self):
        self._test_east_west()


class DefaultSnatToExternal(FloatingIpTestCasesMixin,
                            base.BaseTempestTestCase):
    same_network = True

    @decorators.idempotent_id('3d73ea1a-27c6-45a9-b0f8-04a283d9d764')
    def test_snat_external_ip(self):
        """Check connectivity to an external IP"""
        gateway_external_ip = self._get_external_gateway()

        if not gateway_external_ip:
            raise self.skipTest("IPv4 gateway is not configured for public "
                                "network or public_network_id is not "
                                "configured")
        proxy = self._create_server()
        proxy_client = ssh.Client(proxy['fip']['floating_ip_address'],
                                  CONF.validation.image_ssh_user,
                                  pkey=self.keypair['private_key'])
        src_server = self._create_server(create_floating_ip=False)
        src_server_ip = src_server['port']['fixed_ips'][0]['ip_address']
        ssh_client = ssh.Client(src_server_ip,
                                CONF.validation.image_ssh_user,
                                pkey=self.keypair['private_key'],
                                proxy_client=proxy_client)
        self.check_remote_connectivity(ssh_client,
                                       gateway_external_ip,
                                       servers=[proxy, src_server])


class FloatingIPPortDetailsTest(FloatingIpTestCasesMixin,
                                base.BaseTempestTestCase):
    same_network = True

    @classmethod
    @utils.requires_ext(extension="router", service="network")
    @utils.requires_ext(extension="fip-port-details", service="network")
    def resource_setup(cls):
        super(FloatingIPPortDetailsTest, cls).resource_setup()

    @test.unstable_test("bug 1815585")
    @decorators.idempotent_id('a663aeee-dd81-492b-a207-354fd6284dbe')
    def test_floatingip_port_details(self):
        """Tests the following:

        1. Create a port with floating ip in Neutron.
        2. Create two servers in Nova.
        3. Attach the port to the server.
        4. Detach the port from the server.
        5. Attach the port to the second server.
        6. Detach the port from the second server.
        """
        port = self.create_port(self.network)
        fip = self.create_and_associate_floatingip(port['id'])
        server1 = self._create_server(create_floating_ip=False)
        server2 = self._create_server(create_floating_ip=False)

        for server in [server1, server2]:
            # attach the port to the server
            self.create_interface(
                server['server']['id'], port_id=port['id'])
            waiters.wait_for_interface_status(
                self.os_primary.interfaces_client, server['server']['id'],
                port['id'], lib_constants.PORT_STATUS_ACTIVE)
            fip = self.client.show_floatingip(fip['id'])['floatingip']
            self._check_port_details(
                fip, port, status=lib_constants.PORT_STATUS_ACTIVE,
                device_id=server['server']['id'], device_owner='compute:nova')

            # detach the port from the server; this is a cast in the compute
            # API so we have to poll the port until the device_id is unset.
            self.delete_interface(server['server']['id'], port['id'])
            port = self._wait_for_port_detach(port['id'])
            fip = self._wait_for_fip_port_down(fip['id'])
            self._check_port_details(
                fip, port, status=lib_constants.PORT_STATUS_DOWN,
                device_id='', device_owner='')

    def _check_port_details(self, fip, port, status, device_id, device_owner):
        self.assertIn('port_details', fip)
        port_details = fip['port_details']
        self.assertEqual(port['name'], port_details['name'])
        self.assertEqual(port['network_id'], port_details['network_id'])
        self.assertEqual(port['mac_address'], port_details['mac_address'])
        self.assertEqual(port['admin_state_up'],
                         port_details['admin_state_up'])
        self.assertEqual(status, port_details['status'])
        self.assertEqual(device_id, port_details['device_id'])
        self.assertEqual(device_owner, port_details['device_owner'])

    def _wait_for_port_detach(self, port_id, timeout=120, interval=10):
        """Waits for the port's device_id to be unset.

        :param port_id: The id of the port being detached.
        :returns: The final port dict from the show_port response.
        """
        port = self.client.show_port(port_id)['port']
        device_id = port['device_id']
        start = int(time.time())

        # NOTE(mriedem): Nova updates the port's device_id to '' rather than
        # None, but it's not contractual so handle Falsey either way.
        while device_id:
            time.sleep(interval)
            port = self.client.show_port(port_id)['port']
            device_id = port['device_id']

            timed_out = int(time.time()) - start >= timeout

            if device_id and timed_out:
                message = ('Port %s failed to detach (device_id %s) within '
                           'the required time (%s s).' %
                           (port_id, device_id, timeout))
                raise exceptions.TimeoutException(message)

        return port

    def _wait_for_fip_port_down(self, fip_id, timeout=120, interval=10):
        """Waits for the fip's attached port status to be 'DOWN'.

        :param fip_id: The id of the floating IP.
        :returns: The final fip dict from the show_floatingip response.
        """
        fip = self.client.show_floatingip(fip_id)['floatingip']
        self.assertIn('port_details', fip)
        port_details = fip['port_details']
        status = port_details['status']
        start = int(time.time())

        while status != lib_constants.PORT_STATUS_DOWN:
            time.sleep(interval)
            fip = self.client.show_floatingip(fip_id)['floatingip']
            self.assertIn('port_details', fip)
            port_details = fip['port_details']
            status = port_details['status']

            timed_out = int(time.time()) - start >= timeout

            if status != lib_constants.PORT_STATUS_DOWN and timed_out:
                port_id = fip.get("port_id")
                port = self.os_admin.network_client.show_port(port_id)['port']
                message = ('Floating IP %s attached port status failed to '
                           'transition to DOWN (current status %s) within '
                           'the required time (%s s). Port details: %s' %
                           (fip_id, status, timeout, port))
                raise exceptions.TimeoutException(message)

        return fip


class FloatingIPQosTest(FloatingIpTestCasesMixin,
                        test_qos.QoSTestMixin,
                        base.BaseTempestTestCase):

    same_network = True

    @classmethod
    @utils.requires_ext(extension="router", service="network")
    @utils.requires_ext(extension="qos", service="network")
    @utils.requires_ext(extension="qos-fip", service="network")
    @base_api.require_qos_rule_type(qos_consts.RULE_TYPE_BANDWIDTH_LIMIT)
    def resource_setup(cls):
        super(FloatingIPQosTest, cls).resource_setup()

    @decorators.idempotent_id('5eb48aea-eaba-4c20-8a6f-7740070a0aa3')
    def test_qos(self):
        """Test floating IP is binding to a QoS policy with

           ingress and egress bandwidth limit rules. And it applied correctly
           by sending a file from the instance to the test node.
           Then calculating the bandwidth every ~1 sec by the number of bits
           received / elapsed time.
        """

        self._test_basic_resources()
        policy_id = self._create_qos_policy()
        ssh_client = self._create_ssh_client()
        self.os_admin.network_client.create_bandwidth_limit_rule(
            policy_id, max_kbps=constants.LIMIT_KILO_BITS_PER_SECOND,
            max_burst_kbps=constants.LIMIT_KILO_BYTES,
            direction=lib_constants.INGRESS_DIRECTION)
        self.os_admin.network_client.create_bandwidth_limit_rule(
            policy_id, max_kbps=constants.LIMIT_KILO_BITS_PER_SECOND,
            max_burst_kbps=constants.LIMIT_KILO_BYTES,
            direction=lib_constants.EGRESS_DIRECTION)

        rules = self.os_admin.network_client.list_bandwidth_limit_rules(
            policy_id)
        self.assertEqual(2, len(rules['bandwidth_limit_rules']))

        fip = self.os_admin.network_client.get_floatingip(
            self.fip['id'])['floatingip']
        self.assertEqual(self.port['id'], fip['port_id'])

        self.os_admin.network_client.update_floatingip(
            self.fip['id'],
            qos_policy_id=policy_id)

        fip = self.os_admin.network_client.get_floatingip(
            self.fip['id'])['floatingip']
        self.assertEqual(policy_id, fip['qos_policy_id'])

        common_utils.wait_until_true(lambda: self._check_bw(
            ssh_client,
            self.fip['floating_ip_address'],
            port=self.NC_PORT),
            timeout=120,
            sleep=1)


class TestFloatingIPUpdate(FloatingIpTestCasesMixin,
                           base.BaseTempestTestCase):

    same_network = None

    @decorators.idempotent_id('1bdd849b-03dd-4b8f-994f-457cf8a36f93')
    def test_floating_ip_update(self):
        """Test updating FIP with another port.

        The test creates two servers and attaches floating ip to first server.
        Then it checks server is accesible using the FIP. FIP is then
        associated with the second server and connectivity is checked again.
        """
        ports = [self.create_port(
            self.network, security_groups=[self.secgroup['id']])
            for i in range(2)]

        servers = []
        for port in ports:
            name = data_utils.rand_name("server-%s" % port['id'][:8])
            server = self.create_server(
                name=name,
                flavor_ref=CONF.compute.flavor_ref,
                key_name=self.keypair['name'],
                image_ref=CONF.compute.image_ref,
                networks=[{'port': port['id']}])['server']
            server['name'] = name
            servers.append(server)
        for server in servers:
            self.wait_for_server_active(server)

        self.fip = self.create_floatingip(port=ports[0])
        self.check_connectivity(self.fip['floating_ip_address'],
                                CONF.validation.image_ssh_user,
                                self.keypair['private_key'],
                                servers=servers)
        self.client.update_floatingip(self.fip['id'], port_id=ports[1]['id'])

        def _wait_for_fip_associated():
            try:
                self.check_servers_hostnames(servers[-1:], log_errors=False)
            except (AssertionError, exceptions.SSHTimeout):
                return False
            return True

        # The FIP is now associated with the port of the second server.
        try:
            common_utils.wait_until_true(_wait_for_fip_associated,
                                         timeout=15, sleep=3)
        except common_utils.WaitTimeout:
            self._log_console_output(servers[-1:])
            self.fail(
                "Server %s is not accessible via its floating ip %s" % (
                    servers[-1]['id'], self.fip['id']))
