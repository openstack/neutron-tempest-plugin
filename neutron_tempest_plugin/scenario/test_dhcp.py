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
from oslo_log import log
from paramiko import ssh_exception as ssh_exc
from tempest.common import utils
from tempest.lib.common.utils import data_utils
from tempest.lib import decorators
from tempest.lib import exceptions as lib_exc
import testtools

from neutron_tempest_plugin.common import ssh
from neutron_tempest_plugin.common import utils as neutron_utils
from neutron_tempest_plugin import config
from neutron_tempest_plugin.scenario import base

CONF = config.CONF
LOG = log.getLogger(__name__)


class DHCPTest(base.BaseTempestTestCase):

    credentials = ['primary', 'admin']
    force_tenant_isolation = False

    @classmethod
    def resource_setup(cls):
        super().resource_setup()
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


class DHCPPortUpdateTest(base.BaseTempestTestCase):

    credentials = ['primary', 'admin']

    @classmethod
    def resource_setup(cls):
        super().resource_setup()
        cls.rand_name = data_utils.rand_name(
            cls.__name__.rsplit('.', 1)[-1])
        cls.network = cls.create_network(name=cls.rand_name)
        cls.router = cls.create_router_by_client()
        cls.keypair = cls.create_keypair(name=cls.rand_name)
        cls.security_group = cls.create_security_group(name=cls.rand_name)
        cls.create_loginable_secgroup_rule(cls.security_group['id'])
        cls.create_pingable_secgroup_rule(cls.security_group['id'])

    @testtools.skipUnless(
        CONF.neutron_plugin_options.firewall_driver == 'ovn',
        "OVN driver is required to run this test - "
        "LP#1942794 solution only applied to OVN")
    @decorators.idempotent_id('8171cc68-9dbb-46ca-b065-17b5b2e26094')
    def test_modify_dhcp_port_ip_address(self):
        """Test Scenario

        1) Create a network and a subnet with DHCP enabled
        2) Modify the default IP address from the subnet DHCP port
        3) Create a server in this network and check ssh connectivity

        For the step 3), the server needs to obtain ssh keys from the metadata

        Related bug: LP#1942794
        """
        # create subnet (dhcp is enabled by default)
        subnet = self.create_subnet(network=self.network, name=self.rand_name)

        def _get_dhcp_ports():
            # in some cases, like ML2/OVS, the subnet port associated to DHCP
            # is created with device_owner='network:dhcp'
            dhcp_ports = self.client.list_ports(
                network_id=self.network['id'],
                device_owner=constants.DEVICE_OWNER_DHCP)['ports']
            # in other cases, like ML2/OVN, the subnet port used for metadata
            # is created with device_owner='network:distributed'
            distributed_ports = self.client.list_ports(
                network_id=self.network['id'],
                device_owner=constants.DEVICE_OWNER_DISTRIBUTED)['ports']
            self.dhcp_ports = dhcp_ports + distributed_ports
            self.assertLessEqual(
                len(self.dhcp_ports), 1, msg='Only one port was expected')
            return len(self.dhcp_ports) == 1

        # obtain the dhcp port
        # in some cases this port is not created together with the subnet, but
        # immediately after it, so some delay may be needed and that is the
        # reason why a waiter function is used here
        self.dhcp_ports = []
        neutron_utils.wait_until_true(
            lambda: _get_dhcp_ports(),
            timeout=10)
        dhcp_port = self.dhcp_ports[0]

        # modify DHCP port IP address
        old_dhcp_port_ip = netaddr.IPAddress(
            dhcp_port['fixed_ips'][0]['ip_address'])
        if str(old_dhcp_port_ip) != subnet['allocation_pools'][0]['end']:
            new_dhcp_port_ip = str(old_dhcp_port_ip + 1)
        else:
            new_dhcp_port_ip = str(old_dhcp_port_ip - 1)
        self.update_port(port=dhcp_port,
                         fixed_ips=[{'subnet_id': subnet['id'],
                                     'ip_address': new_dhcp_port_ip}])

        # create server
        server = self.create_server(
            flavor_ref=CONF.compute.flavor_ref,
            image_ref=CONF.compute.image_ref,
            key_name=self.keypair['name'],
            security_groups=[{'name': self.security_group['name']}],
            networks=[{'uuid': self.network['id']}])

        # attach fip to the server
        self.create_router_interface(self.router['id'], subnet['id'])
        server_port = self.client.list_ports(
            network_id=self.network['id'],
            device_id=server['server']['id'])['ports'][0]
        fip = self.create_floatingip(port_id=server_port['id'])

        # check connectivity
        self.check_connectivity(fip['floating_ip_address'],
                                CONF.validation.image_ssh_user,
                                self.keypair['private_key'])


class DHCPLeaseOptionsTest(base.BaseTempestTestCase):
    """Check what the guest learns from DHCP, whoever answers it.

    The same assertions hold for the DHCP agent and for the OVS agent
    DHCP extension, so that a job running either proves they configure
    a guest alike.
    """

    credentials = ['primary', 'admin']

    DNS_SERVERS = ['192.0.2.53', '192.0.2.54']

    @classmethod
    def resource_setup(cls):
        super().resource_setup()
        cls.rand_name = data_utils.rand_name(
            cls.__name__.rsplit('.', 1)[-1])
        cls.network = cls.create_network(name=cls.rand_name)
        cls.subnet = cls.create_subnet(
            network=cls.network, name=cls.rand_name,
            dns_nameservers=cls.DNS_SERVERS[:1])
        cidr = netaddr.IPNetwork(cls.subnet['cidr'])
        cls.host_route = {'destination': '198.51.100.0/24',
                          'nexthop': str(cidr[-2])}
        cls.subnet = cls.client.update_subnet(
            cls.subnet['id'], host_routes=[cls.host_route])['subnet']
        # A sibling subnet is on-link for the guest, even without DHCP.
        cls.sibling_subnet = cls.create_subnet(
            network=cls.network, name=cls.rand_name + '-sibling',
            gateway=None, enable_dhcp=False)
        cls.router = cls.create_router_by_client()
        cls.create_router_interface(cls.router['id'], cls.subnet['id'])
        cls.keypair = cls.create_keypair(name=cls.rand_name)
        cls.security_group = cls.create_security_group(name=cls.rand_name)
        cls.create_loginable_secgroup_rule(cls.security_group['id'])
        cls.setup_advanced_image()

    def _create_server(self):
        port = self.create_port(
            network=self.network, name=self.rand_name,
            security_groups=[self.security_group['id']],
            fixed_ips=[{'subnet_id': self.subnet['id']}])
        fip = self.create_floatingip(port=port)
        server = self.create_server(
            flavor_ref=self.flavor_ref,
            image_ref=self.image_ref,
            key_name=self.keypair['name'],
            networks=[{'port': port['id']}])
        self.wait_for_server_active(server['server'])
        self.wait_for_guest_os_ready(server['server'])
        self.addOnException(
            lambda exc_info: (self._log_console_output([server['server']]),
                              self._log_local_network_status()))
        ssh_client = ssh.Client(fip['floating_ip_address'], self.username,
                                pkey=self.keypair['private_key'])
        return port, ssh_client

    @staticmethod
    def _guest_interface(ssh_client, port):
        ip_address = port['fixed_ips'][0]['ip_address']
        out = ssh_client.exec_command(
            "ip -o -4 addr show | awk '/inet %s\\// {print $2}'" %
            ip_address)
        return out.strip()

    @staticmethod
    def _guest_dns_servers(ssh_client):
        # systemd-resolved keeps the servers it learnt out of
        # /etc/resolv.conf.
        out = ssh_client.exec_command(
            "cat /run/systemd/resolve/resolv.conf 2>/dev/null || "
            "cat /etc/resolv.conf")
        return [line.split()[1] for line in out.splitlines()
                if line.startswith('nameserver')]

    @staticmethod
    def _guest_routes(ssh_client, iface):
        return ssh_client.exec_command(
            'ip -4 route show dev %s' % iface).splitlines()

    def _assert_lease(self, port, ssh_client, dns_servers):
        iface = self._guest_interface(ssh_client, port)
        self.assertTrue(iface)

        mtu = ssh_client.exec_command('cat /sys/class/net/%s/mtu' % iface)
        self.assertEqual(self.network['mtu'], int(mtu))

        self.assertIn('%(destination)s via %(nexthop)s' % self.host_route,
                      '\n'.join(self._guest_routes(ssh_client, iface)))

        self.assertEqual(dns_servers, self._guest_dns_servers(ssh_client))

    @testtools.skipUnless(
        (CONF.neutron_plugin_options.advanced_image_ref or
         CONF.neutron_plugin_options.default_image_is_advanced),
        "Advanced image is required to run this test.")
    @decorators.idempotent_id('7a8f2de8-9384-47d8-89e7-9dad53cc6355')
    def test_dhcp_lease_options(self):
        """The network MTU, host routes and DNS servers reach the guest."""
        port, ssh_client = self._create_server()
        self._assert_lease(port, ssh_client, self.DNS_SERVERS[:1])

    @testtools.skipUnless(
        (CONF.neutron_plugin_options.advanced_image_ref or
         CONF.neutron_plugin_options.default_image_is_advanced),
        "Advanced image is required to run this test.")
    @decorators.idempotent_id('c0da67a0-7da5-40e0-99fc-2467730fb5a5')
    def test_dhcp_lease_sibling_subnet_on_link(self):
        """A sibling subnet is on-link for the guest, even without DHCP."""
        port, ssh_client = self._create_server()
        iface = self._guest_interface(ssh_client, port)
        self.assertTrue(iface)
        routes = self._guest_routes(ssh_client, iface)
        sibling = [r for r in routes
                   if r.startswith(self.sibling_subnet['cidr'] + ' ')]
        self.assertTrue(sibling, "No route to %s in %s" %
                        (self.sibling_subnet['cidr'], routes))
        self.assertNotIn(' via ', sibling[0])

    @testtools.skipUnless(
        (CONF.neutron_plugin_options.advanced_image_ref or
         CONF.neutron_plugin_options.default_image_is_advanced),
        "Advanced image is required to run this test.")
    @decorators.idempotent_id('4c5f8032-7df4-47d2-8bfc-a07a7eeb1cde')
    def test_dhcp_lease_follows_subnet_update(self):
        """A lease renewed after a subnet update carries the new options."""
        port, ssh_client = self._create_server()
        self.client.update_subnet(self.subnet['id'],
                                  dns_nameservers=self.DNS_SERVERS)
        self.addCleanup(self.client.update_subnet, self.subnet['id'],
                        dns_nameservers=self.DNS_SERVERS[:1])
        iface = self._guest_interface(ssh_client, port)

        def _renewed():
            ssh_client.exec_command('sudo networkctl renew %s' % iface)
            return self._guest_dns_servers(ssh_client) == self.DNS_SERVERS

        neutron_utils.wait_until_true(
            _renewed, timeout=60, sleep=5,
            exception=AssertionError(
                "The guest did not get the DNS servers %s" %
                self.DNS_SERVERS))
        self._assert_lease(port, ssh_client, self.DNS_SERVERS)
