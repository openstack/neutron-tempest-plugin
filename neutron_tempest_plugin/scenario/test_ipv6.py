# Copyright 2020 Red Hat, Inc.
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

from neutron_lib import constants as lib_constants
from oslo_log import log
from paramiko import ssh_exception as ssh_exc
from tempest.common import utils as tempest_utils
from tempest.lib.common.utils import data_utils
from tempest.lib import decorators
from tempest.lib import exceptions as lib_exc
import testtools

from neutron_tempest_plugin.common import ip
from neutron_tempest_plugin.common import ssh
from neutron_tempest_plugin.common import utils
from neutron_tempest_plugin import config
from neutron_tempest_plugin.scenario import base

CONF = config.CONF

LOG = log.getLogger(__name__)


def turn_nic6_on(ssh, ipv6_port, config_nic=True):
    """Turns the IPv6 vNIC on

    Required because guest images usually set only the first vNIC on boot.
    Searches for the IPv6 vNIC's MAC and brings it up.
    # NOTE(slaweq): on RHEL based OS ifcfg file for new interface is
    # needed to make IPv6 working on it, so if
    # /etc/sysconfig/network-scripts directory exists ifcfg-%(nic)s file
    # should be added in it

    @param ssh: RemoteClient ssh instance to server
    @param ipv6_port: port from IPv6 network attached to the server
    """
    ip_command = ip.IPCommand(ssh)
    nic = ip_command.get_nic_name_by_mac(ipv6_port['mac_address'])

    if config_nic:
        try:
            if sysconfig_network_scripts_dir_exists(ssh):
                ssh.execute_script(
                    'echo -e "DEVICE=%(nic)s\\nNAME=%(nic)s\\nIPV6INIT=yes" | '
                    'tee /etc/sysconfig/network-scripts/ifcfg-%(nic)s; '
                    % {'nic': nic}, become_root=True)
            if nmcli_command_exists(ssh):
                ssh.execute_script('nmcli connection reload %s' % nic,
                                   become_root=True)
                ssh.execute_script('nmcli con mod %s ipv6.addr-gen-mode eui64'
                                   % nic, become_root=True)
                ssh.execute_script('nmcli connection up %s' % nic,
                                   become_root=True)

        except lib_exc.SSHExecCommandFailed as e:
            # NOTE(slaweq): Sometimes it can happen that this SSH command
            # will fail because of some error from network manager in
            # guest os.
            # But even then doing ip link set up below is fine and
            # IP address should be configured properly.
            LOG.debug("Error creating NetworkManager profile. "
                      "Error message: %(error)s",
                      {'error': e})

    ip_command.set_link(nic, "up")


def configure_eth_connection_profile_NM(ssh):
    """Prepare a Network manager profile for ipv6 port

    By default the NetworkManager uses IPv6 privacy
    format it isn't supported by neutron then we create
    a ether profile with eui64 supported format

    @param ssh: RemoteClient ssh instance to server
    """
    # NOTE(ccamposr): on RHEL based OS we need a ether profile with
    # eui64 format
    if nmcli_command_exists(ssh):
        try:
            ssh.execute_script('nmcli connection add type ethernet con-name '
                               'ether ifname "*"', become_root=True)
            ssh.execute_script('nmcli con mod ether ipv6.addr-gen-mode eui64',
                               become_root=True)

        except lib_exc.SSHExecCommandFailed as e:
            # NOTE(slaweq): Sometimes it can happen that this SSH command
            # will fail because of some error from network manager in
            # guest os.
            # But even then doing ip link set up below is fine and
            # IP address should be configured properly.
            LOG.debug("Error creating NetworkManager profile. "
                      "Error message: %(error)s",
                      {'error': e})


def sysconfig_network_scripts_dir_exists(ssh):
    return "False" not in ssh.execute_script(
        'test -d /etc/sysconfig/network-scripts/ || echo "False"')


def nmcli_command_exists(ssh):
    return "False" not in ssh.execute_script(
        'if ! type nmcli > /dev/null ; then echo "False"; fi')


class IPv6Test(base.BaseTempestTestCase):
    credentials = ['primary', 'admin']

    ipv6_ra_mode = 'slaac'
    ipv6_address_mode = 'slaac'

    @classmethod
    def skip_checks(cls):
        super(IPv6Test, cls).skip_checks()
        if not CONF.network_feature_enabled.ipv6:
            raise cls.skipException("IPv6 is not enabled")

    @classmethod
    @tempest_utils.requires_ext(extension="router", service="network")
    def resource_setup(cls):
        super(IPv6Test, cls).resource_setup()
        cls.reserve_external_subnet_cidrs()
        cls._setup_basic_resources()

    @classmethod
    def _setup_basic_resources(cls):
        cls.network = cls.create_network()
        cls.subnet = cls.create_subnet(cls.network)
        cls.router = cls.create_router_by_client()
        cls.create_router_interface(cls.router['id'], cls.subnet['id'])
        cls.keypair = cls.create_keypair()
        cls.secgroup = cls.create_security_group(
            name=data_utils.rand_name('secgroup'))
        cls.create_loginable_secgroup_rule(secgroup_id=cls.secgroup['id'])
        cls.create_pingable_secgroup_rule(secgroup_id=cls.secgroup['id'])

    def _test_ipv6_address_configured(self, ssh_client, vm, ipv6_port):
        ipv6_address = ipv6_port['fixed_ips'][0]['ip_address']
        ip_command = ip.IPCommand(ssh_client)

        def guest_has_address(expected_address):
            ip_addresses = [a.address for a in ip_command.list_addresses()]
            for ip_address in ip_addresses:
                if expected_address in ip_address:
                    return True
            return False
        # Set NIC with IPv6 to be UP and wait until IPv6 address
        # will be configured on this NIC
        turn_nic6_on(ssh_client, ipv6_port, False)
        # And check if IPv6 address will be properly configured
        # on this NIC
        try:
            utils.wait_until_true(
                lambda: guest_has_address(ipv6_address),
                timeout=60)
        except utils.WaitTimeout:
            LOG.debug('Timeout without NM configuration')
        except (lib_exc.SSHTimeout,
                ssh_exc.AuthenticationException) as ssh_e:
            LOG.debug(ssh_e)
            self._log_console_output([vm])
            self._log_local_network_status()
            raise

        if not guest_has_address(ipv6_address):
            try:
                # Set NIC with IPv6 to be UP and wait until IPv6 address
                # will be configured on this NIC
                turn_nic6_on(ssh_client, ipv6_port)
                # And check if IPv6 address will be properly configured
                # on this NIC
                utils.wait_until_true(
                    lambda: guest_has_address(ipv6_address),
                    timeout=90,
                    exception=RuntimeError(
                        "Timed out waiting for IP address {!r} to be "
                        "configured in the VM {!r}.".format(ipv6_address,
                        vm['id'])))
            except (lib_exc.SSHTimeout,
                    ssh_exc.AuthenticationException) as ssh_e:
                LOG.debug(ssh_e)
                self._log_console_output([vm])
                self._log_local_network_status()
                raise

    def _test_ipv6_hotplug(self, ra_mode, address_mode):
        ipv6_networks = [self.create_network() for _ in range(2)]
        for net in ipv6_networks:
            subnet = self.create_subnet(
                network=net, ip_version=6,
                ipv6_ra_mode=ra_mode, ipv6_address_mode=address_mode)
            self.create_router_interface(self.router['id'], subnet['id'])

        server_kwargs = {
            'flavor_ref': CONF.compute.flavor_ref,
            'image_ref': CONF.compute.image_ref,
            'key_name': self.keypair['name'],
            'networks': [
                {'uuid': self.network['id']},
                {'uuid': ipv6_networks[0]['id']}],
            'security_groups': [{'name': self.secgroup['name']}],
        }
        vm = self.create_server(**server_kwargs)['server']
        self.wait_for_server_active(vm)
        self.wait_for_guest_os_ready(vm)
        ipv4_port = self.client.list_ports(
            network_id=self.network['id'],
            device_id=vm['id'])['ports'][0]
        fip = self.create_floatingip(port=ipv4_port)
        ssh_client = ssh.Client(
            fip['floating_ip_address'], CONF.validation.image_ssh_user,
            pkey=self.keypair['private_key'])

        ipv6_port = self.client.list_ports(
            network_id=ipv6_networks[0]['id'],
            device_id=vm['id'])['ports'][0]
        self._test_ipv6_address_configured(ssh_client, vm, ipv6_port)

        # Now remove this port IPv6 port from the VM and attach new one
        self.delete_interface(vm['id'], ipv6_port['id'])

        # And plug VM to the second IPv6 network
        ipv6_port = self.create_port(ipv6_networks[1])
        # Add NetworkManager profile with ipv6 eui64 format to guest OS
        configure_eth_connection_profile_NM(ssh_client)
        self.create_interface(vm['id'], ipv6_port['id'])
        ip.wait_for_interface_status(
            self.os_primary.interfaces_client, vm['id'],
            ipv6_port['id'], lib_constants.PORT_STATUS_ACTIVE,
            ssh_client=ssh_client, mac_address=ipv6_port['mac_address'])
        self._test_ipv6_address_configured(ssh_client, vm, ipv6_port)

    @testtools.skipUnless(CONF.network_feature_enabled.ipv6_subnet_attributes,
                          "DHCPv6 attributes are not enabled.")
    @decorators.idempotent_id('b13e5408-5250-4a42-8e46-6996ce613e91')
    def test_ipv6_hotplug_slaac(self):
        self._test_ipv6_hotplug("slaac", "slaac")

    @testtools.skipUnless(CONF.network_feature_enabled.ipv6_subnet_attributes,
                          "DHCPv6 attributes are not enabled.")
    @decorators.idempotent_id('9aaedbc4-986d-42d5-9177-3e721728e7e0')
    def test_ipv6_hotplug_dhcpv6stateless(self):
        self._test_ipv6_hotplug("dhcpv6-stateless", "dhcpv6-stateless")
