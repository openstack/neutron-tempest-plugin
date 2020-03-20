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
import distutils
import re
import subprocess

from debtcollector import removals
import netaddr
from neutron_lib.api import validators
from neutron_lib import constants as neutron_lib_constants
from oslo_log import log
from tempest.common.utils import net_utils
from tempest.common import waiters
from tempest.lib.common.utils import data_utils
from tempest.lib.common.utils import test_utils
from tempest.lib import exceptions as lib_exc

from neutron_tempest_plugin.api import base as base_api
from neutron_tempest_plugin.common import ip as ip_utils
from neutron_tempest_plugin.common import shell
from neutron_tempest_plugin.common import ssh
from neutron_tempest_plugin.common import utils
from neutron_tempest_plugin import config
from neutron_tempest_plugin import exceptions
from neutron_tempest_plugin.scenario import constants

CONF = config.CONF

LOG = log.getLogger(__name__)


def get_ncat_version(ssh_client=None):
    cmd = "ncat --version 2>&1"
    try:
        version_result = shell.execute(cmd, ssh_client=ssh_client).stdout
    except exceptions.ShellCommandFailed:
        m = None
    else:
        m = re.match(r"Ncat: Version ([\d.]+) *.", version_result)
    # NOTE(slaweq): by default lets assume we have ncat 7.60 which is in Ubuntu
    # 18.04 which is used on u/s gates
    return distutils.version.StrictVersion(m.group(1) if m else '7.60')


def get_ncat_server_cmd(port, protocol, msg=None):
    udp = ''
    if protocol.lower() == neutron_lib_constants.PROTO_NAME_UDP:
        udp = '-u'
    cmd = "nc %(udp)s -p %(port)s -lk " % {
        'udp': udp, 'port': port}
    if msg:
        if CONF.neutron_plugin_options.default_image_is_advanced:
            cmd += "-c 'echo %s' &" % msg
        else:
            cmd += "-e echo %s &" % msg
    else:
        cmd += "< /dev/zero &"
    return cmd


def get_ncat_client_cmd(ip_address, port, protocol):
    udp = ''
    if protocol.lower() == neutron_lib_constants.PROTO_NAME_UDP:
        udp = '-u'
    cmd = 'echo "knock knock" | nc '
    ncat_version = get_ncat_version()
    if ncat_version > distutils.version.StrictVersion('7.60'):
        cmd += '-z '
    cmd += '-w 1 %(udp)s %(host)s %(port)s' % {
        'udp': udp, 'host': ip_address, 'port': port}
    return cmd


class BaseTempestTestCase(base_api.BaseNetworkTest):

    def create_server(self, flavor_ref, image_ref, key_name, networks,
                      **kwargs):
        """Create a server using tempest lib

        All the parameters are the ones used in Compute API
        * - Kwargs that require admin privileges

        Args:
           flavor_ref(str): The flavor of the server to be provisioned.
           image_ref(str):  The image of the server to be provisioned.
           key_name(str): SSH key to to be used to connect to the
                            provisioned server.
           networks(list): List of dictionaries where each represent
               an interface to be attached to the server. For network
               it should be {'uuid': network_uuid} and for port it should
               be {'port': port_uuid}
        kwargs:
           name(str): Name of the server to be provisioned.
           security_groups(list): List of dictionaries where
                the keys is 'name' and the value is the name of
                the security group. If it's not passed the default
                security group will be used.
           availability_zone(str)*: The availability zone that
                the instance will be in.
                You can request a specific az without actually creating one,
                Just pass 'X:Y' where X is the default availability
                zone, and Y is the compute host name.
        """

        kwargs.setdefault('name', data_utils.rand_name('server-test'))

        # We cannot use setdefault() here because caller could have passed
        # security_groups=None and we don't want to pass None to
        # client.create_server()
        if not kwargs.get('security_groups'):
            kwargs['security_groups'] = [{'name': 'default'}]

        client = self.os_primary.servers_client
        if kwargs.get('availability_zone'):
            client = self.os_admin.servers_client

        server = client.create_server(
            flavorRef=flavor_ref,
            imageRef=image_ref,
            key_name=key_name,
            networks=networks,
            **kwargs)

        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        waiters.wait_for_server_termination,
                        client,
                        server['server']['id'])
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        client.delete_server,
                        server['server']['id'])
        return server

    @classmethod
    def create_secgroup_rules(cls, rule_list, secgroup_id=None,
                              client=None):
        client = client or cls.os_primary.network_client
        if not secgroup_id:
            sgs = client.list_security_groups()['security_groups']
            for sg in sgs:
                if sg['name'] == constants.DEFAULT_SECURITY_GROUP:
                    secgroup_id = sg['id']
                    break

        for rule in rule_list:
            direction = rule.pop('direction')
            client.create_security_group_rule(
                direction=direction,
                security_group_id=secgroup_id,
                **rule)

    @classmethod
    def create_loginable_secgroup_rule(cls, secgroup_id=None,
                                       client=None):
        """This rule is intended to permit inbound ssh

        Allowing ssh traffic traffic from all sources, so no group_id is
        provided.
        Setting a group_id would only permit traffic from ports
        belonging to the same security group.
        """
        return cls.create_security_group_rule(
            security_group_id=secgroup_id,
            client=client,
            protocol=neutron_lib_constants.PROTO_NAME_TCP,
            direction=neutron_lib_constants.INGRESS_DIRECTION,
            port_range_min=22,
            port_range_max=22)

    @classmethod
    def create_pingable_secgroup_rule(cls, secgroup_id=None,
                                      client=None):
        """This rule is intended to permit inbound ping

        """
        return cls.create_security_group_rule(
            security_group_id=secgroup_id, client=client,
            protocol=neutron_lib_constants.PROTO_NAME_ICMP,
            direction=neutron_lib_constants.INGRESS_DIRECTION)

    @classmethod
    def create_router_by_client(cls, is_admin=False, **kwargs):
        kwargs.update({'router_name': data_utils.rand_name('router'),
                       'admin_state_up': True,
                       'external_network_id': CONF.network.public_network_id})
        if not is_admin:
            router = cls.create_router(**kwargs)
        else:
            router = cls.create_admin_router(**kwargs)
        LOG.debug("Created router %s", router['name'])
        cls.routers.append(router)
        return router

    @removals.remove(version='Stein',
                     message="Please use create_floatingip method instead of "
                             "create_and_associate_floatingip.")
    def create_and_associate_floatingip(self, port_id, client=None):
        client = client or self.os_primary.network_client
        return self.create_floatingip(port_id=port_id, client=client)

    def create_interface(cls, server_id, port_id, client=None):
        client = client or cls.os_primary.interfaces_client
        body = client.create_interface(server_id, port_id=port_id)
        return body['interfaceAttachment']

    def delete_interface(cls, server_id, port_id, client=None):
        client = client or cls.os_primary.interfaces_client
        client.delete_interface(server_id, port_id=port_id)

    def setup_network_and_server(self, router=None, server_name=None,
                                 network=None, **kwargs):
        """Create network resources and a server.

        Creating a network, subnet, router, keypair, security group
        and a server.
        """
        self.network = network or self.create_network()
        LOG.debug("Created network %s", self.network['name'])
        self.subnet = self.create_subnet(self.network)
        LOG.debug("Created subnet %s", self.subnet['id'])

        secgroup = self.os_primary.network_client.create_security_group(
            name=data_utils.rand_name('secgroup'))
        LOG.debug("Created security group %s",
                  secgroup['security_group']['name'])
        self.security_groups.append(secgroup['security_group'])
        if not router:
            router = self.create_router_by_client(**kwargs)
        self.create_router_interface(router['id'], self.subnet['id'])
        self.keypair = self.create_keypair()
        self.create_loginable_secgroup_rule(
            secgroup_id=secgroup['security_group']['id'])

        server_kwargs = {
            'flavor_ref': CONF.compute.flavor_ref,
            'image_ref': CONF.compute.image_ref,
            'key_name': self.keypair['name'],
            'networks': [{'uuid': self.network['id']}],
            'security_groups': [{'name': secgroup['security_group']['name']}],
        }
        if server_name is not None:
            server_kwargs['name'] = server_name

        self.server = self.create_server(**server_kwargs)
        self.wait_for_server_active(self.server['server'])
        self.port = self.client.list_ports(network_id=self.network['id'],
                                           device_id=self.server[
                                               'server']['id'])['ports'][0]
        self.fip = self.create_floatingip(port=self.port)

    def check_connectivity(self, host, ssh_user, ssh_key, servers=None):
        ssh_client = ssh.Client(host, ssh_user, pkey=ssh_key)
        try:
            ssh_client.test_connection_auth()
        except lib_exc.SSHTimeout as ssh_e:
            LOG.debug(ssh_e)
            self._log_console_output(servers)
            self._log_local_network_status()
            raise

    def _log_console_output(self, servers=None):
        if not CONF.compute_feature_enabled.console_output:
            LOG.debug('Console output not supported, cannot log')
            return
        if not servers:
            servers = self.os_primary.servers_client.list_servers()
            servers = servers['servers']
        for server in servers:
            # NOTE(slaweq): sometimes servers are passed in dictionary with
            # "server" key as first level key and in other cases it may be that
            # it is just the "inner" dict without "server" key. Lets try to
            # handle both cases
            server = server.get("server") or server
            try:
                console_output = (
                    self.os_primary.servers_client.get_console_output(
                        server['id'])['output'])
                LOG.debug('Console output for %s\nbody=\n%s',
                          server['id'], console_output)
            except lib_exc.NotFound:
                LOG.debug("Server %s disappeared(deleted) while looking "
                          "for the console log", server['id'])

    def _log_local_network_status(self):
        local_routes = ip_utils.IPCommand().list_routes()
        LOG.debug('Local routes:\n%s', '\n'.join(str(r) for r in local_routes))
        arp_table = ip_utils.arp_table()
        LOG.debug('Local ARP table:\n%s', '\n'.join(str(r) for r in arp_table))

    def _check_remote_connectivity(self, source, dest, count,
                                   should_succeed=True,
                                   nic=None, mtu=None, fragmentation=True,
                                   timeout=None, pattern=None):
        """check ping server via source ssh connection

        :param source: RemoteClient: an ssh connection from which to ping
        :param dest: and IP to ping against
        :param count: Number of ping packet(s) to send
        :param should_succeed: boolean should ping succeed or not
        :param nic: specific network interface to ping from
        :param mtu: mtu size for the packet to be sent
        :param fragmentation: Flag for packet fragmentation
        :param timeout: Timeout for all ping packet(s) to succeed
        :param pattern: hex digits included in ICMP messages
        :returns: boolean -- should_succeed == ping
        :returns: ping is false if ping failed
        """
        def ping_host(source, host, count,
                      size=CONF.validation.ping_size, nic=None, mtu=None,
                      fragmentation=True, pattern=None):
            IP_VERSION_4 = neutron_lib_constants.IP_VERSION_4
            IP_VERSION_6 = neutron_lib_constants.IP_VERSION_6

            # Use 'ping6' for IPv6 addresses, 'ping' for IPv4 and hostnames
            ip_version = (
                IP_VERSION_6 if netaddr.valid_ipv6(host) else IP_VERSION_4)
            cmd = (
                'ping6' if ip_version == IP_VERSION_6 else 'ping')
            if nic:
                cmd = 'sudo {cmd} -I {nic}'.format(cmd=cmd, nic=nic)
            if mtu:
                if not fragmentation:
                    cmd += ' -M do'
                size = str(net_utils.get_ping_payload_size(
                    mtu=mtu, ip_version=ip_version))
            if pattern:
                cmd += ' -p {pattern}'.format(pattern=pattern)
            cmd += ' -c{0} -w{0} -s{1} {2}'.format(count, size, host)
            return source.exec_command(cmd)

        def ping_remote():
            try:
                result = ping_host(source, dest, count, nic=nic, mtu=mtu,
                                   fragmentation=fragmentation,
                                   pattern=pattern)

            except lib_exc.SSHExecCommandFailed:
                LOG.warning('Failed to ping IP: %s via a ssh connection '
                            'from: %s.', dest, source.host)
                return not should_succeed
            LOG.debug('ping result: %s', result)

            if validators.validate_ip_address(dest) is None:
                # Assert that the return traffic was from the correct
                # source address.
                from_source = 'from %s' % dest
                self.assertIn(from_source, result)
            return should_succeed

        return test_utils.call_until_true(
            ping_remote, timeout or CONF.validation.ping_timeout, 1)

    def check_remote_connectivity(self, source, dest, should_succeed=True,
                                  nic=None, mtu=None, fragmentation=True,
                                  servers=None, timeout=None,
                                  ping_count=CONF.validation.ping_count,
                                  pattern=None):
        try:
            self.assertTrue(self._check_remote_connectivity(
                source, dest, ping_count, should_succeed, nic, mtu,
                fragmentation,
                timeout=timeout, pattern=pattern))
        except lib_exc.SSHTimeout as ssh_e:
            LOG.debug(ssh_e)
            self._log_console_output(servers)
            raise
        except AssertionError:
            self._log_console_output(servers)
            raise

    def ping_ip_address(self, ip_address, should_succeed=True,
                        ping_timeout=None, mtu=None):
        # the code is taken from tempest/scenario/manager.py in tempest git
        timeout = ping_timeout or CONF.validation.ping_timeout
        cmd = ['ping', '-c1', '-w1']

        if mtu:
            cmd += [
                # don't fragment
                '-M', 'do',
                # ping receives just the size of ICMP payload
                '-s', str(net_utils.get_ping_payload_size(mtu, 4))
            ]
        cmd.append(ip_address)

        def ping():
            proc = subprocess.Popen(cmd,
                                    stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE)
            proc.communicate()

            return (proc.returncode == 0) == should_succeed

        caller = test_utils.find_test_caller()
        LOG.debug('%(caller)s begins to ping %(ip)s in %(timeout)s sec and the'
                  ' expected result is %(should_succeed)s', {
                      'caller': caller, 'ip': ip_address, 'timeout': timeout,
                      'should_succeed':
                      'reachable' if should_succeed else 'unreachable'
                  })
        result = test_utils.call_until_true(ping, timeout, 1)

        # To make sure ping_ip_address called by test works
        # as expected.
        self.assertTrue(result)

        LOG.debug('%(caller)s finishes ping %(ip)s in %(timeout)s sec and the '
                  'ping result is %(result)s', {
                      'caller': caller, 'ip': ip_address, 'timeout': timeout,
                      'result': 'expected' if result else 'unexpected'
                  })
        return result

    def wait_for_server_status(self, server, status, client=None, **kwargs):
        """Waits for a server to reach a given status.

        :param server:  mapping having schema {'id': <server_id>}
        :param status: string status to wait for (es: 'ACTIVE')
        :param clien:  servers client (self.os_primary.servers_client as
                       default value)
        """

        client = client or self.os_primary.servers_client
        waiters.wait_for_server_status(client, server['id'], status, **kwargs)

    def wait_for_server_active(self, server, client=None):
        """Waits for a server to reach active status.

        :param server:  mapping having schema {'id': <server_id>}
        :param clien:  servers client (self.os_primary.servers_client as
                       default value)
        """
        self.wait_for_server_status(
            server, constants.SERVER_STATUS_ACTIVE, client)

    def check_servers_hostnames(self, servers, log_errors=True):
        """Compare hostnames of given servers with their names."""
        try:
            for server in servers:
                kwargs = {}
                try:
                    kwargs['port'] = (
                        server['port_forwarding_tcp']['external_port'])
                except KeyError:
                    pass
                ssh_client = ssh.Client(
                    self.fip['floating_ip_address'],
                    CONF.validation.image_ssh_user,
                    pkey=self.keypair['private_key'],
                    **kwargs)
                self.assertIn(server['name'],
                              ssh_client.exec_command('hostname'))
        except lib_exc.SSHTimeout as ssh_e:
            LOG.debug(ssh_e)
            if log_errors:
                self._log_console_output(servers)
            raise
        except AssertionError as assert_e:
            LOG.debug(assert_e)
            if log_errors:
                self._log_console_output(servers)
            raise

    def ensure_nc_listen(self, ssh_client, port, protocol, echo_msg=None,
                         servers=None):
        """Ensure that nc server listening on the given TCP/UDP port is up.

        Listener is created always on remote host.
        """
        def spawn_and_check_process():
            self.nc_listen(ssh_client, port, protocol, echo_msg, servers)
            return utils.process_is_running(ssh_client, "nc")

        utils.wait_until_true(spawn_and_check_process)

    def nc_listen(self, ssh_client, port, protocol, echo_msg=None,
                  servers=None):
        """Create nc server listening on the given TCP/UDP port.

        Listener is created always on remote host.
        """
        try:
            return ssh_client.execute_script(
                get_ncat_server_cmd(port, protocol, echo_msg),
                become_root=True)
        except lib_exc.SSHTimeout as ssh_e:
            LOG.debug(ssh_e)
            self._log_console_output(servers)
            raise

    def nc_client(self, ip_address, port, protocol):
        """Check connectivity to TCP/UDP port at host via nc.

        Client is always executed locally on host where tests are executed.
        """
        cmd = get_ncat_client_cmd(ip_address, port, protocol)
        result = shell.execute_local_command(cmd)
        self.assertEqual(0, result.exit_status)
        return result.stdout
