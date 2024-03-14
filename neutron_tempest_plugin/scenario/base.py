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

import re
import subprocess

from debtcollector import removals
import netaddr
from neutron_lib.api import validators
from neutron_lib import constants as neutron_lib_constants
from oslo_log import log
from packaging import version as packaging_version
from paramiko import ssh_exception as ssh_exc
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
SSH_EXC_TUPLE = (lib_exc.SSHTimeout,
                 ssh_exc.AuthenticationException,
                 ssh_exc.NoValidConnectionsError,
                 ConnectionResetError)


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
    return packaging_version.Version(m.group(1) if m else '7.60')


def get_ncat_server_cmd(port, protocol, msg=None):
    udp = ''
    if protocol.lower() == neutron_lib_constants.PROTO_NAME_UDP:
        udp = '-u'
    cmd = "nc %(udp)s -p %(port)s -lk " % {
        'udp': udp, 'port': port}
    if msg:
        if CONF.neutron_plugin_options.default_image_is_advanced:
            cmd += "-c 'echo %s' " % msg
        else:
            cmd += "-e echo %s " % msg
    cmd += "< /dev/zero &{0}sleep 0.1{0}".format('\n')
    return cmd


def get_ncat_client_cmd(ip_address, port, protocol, ssh_client=None):
    cmd = 'echo "knock knock" | nc '
    ncat_version = get_ncat_version(ssh_client=ssh_client)
    if ncat_version > packaging_version.Version('7.60'):
        cmd += '-d 1 '
    if protocol.lower() == neutron_lib_constants.PROTO_NAME_UDP:
        cmd += '-u '
        if ncat_version > packaging_version.Version('7.60'):
            cmd += '-z '
    cmd += '-w 1 %(host)s %(port)s' % {'host': ip_address, 'port': port}
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

        client = kwargs.pop('client', None)
        if client is None:
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

        self.wait_for_server_active(server['server'], client=client)
        self.wait_for_guest_os_ready(server['server'], client=client)

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
        resp = []
        for rule in rule_list:
            direction = rule.pop('direction')
            resp.append(client.create_security_group_rule(
                        direction=direction,
                        security_group_id=secgroup_id,
                        **rule)['security_group_rule'])
        return resp

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
    def create_ingress_metadata_secgroup_rule(cls, secgroup_id=None):
        """This rule is intended to permit inbound metadata traffic

        Allowing ingress traffic from metadata server, required only for
        stateless security groups.
        """
        # NOTE(slaweq): in case of stateless security groups, there is no
        # "related" or "established" traffic matching at all so even if
        # egress traffic to 169.254.169.254 is allowed by default SG, we
        # need to explicitly allow ingress traffic from the metadata server
        # to be able to receive responses in the guest vm
        cls.create_security_group_rule(
            security_group_id=secgroup_id,
            direction=neutron_lib_constants.INGRESS_DIRECTION,
            protocol=neutron_lib_constants.PROTO_NAME_TCP,
            remote_ip_prefix='169.254.169.254/32',
            description='metadata out'
        )

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
        cls._wait_for_router_ha_active(router['id'])
        return router

    @classmethod
    def _wait_for_router_ha_active(cls, router_id):
        router = cls.os_admin.network_client.show_router(router_id)['router']
        if not router.get('ha') or cls.is_driver_ovn:
            return

        def _router_active_on_l3_agent():
            agents = cls.os_admin.network_client.list_l3_agents_hosting_router(
                router_id)['agents']
            return "active" in [agent['ha_state'] for agent in agents]

        error_msg = (
            "Router %s is not active on any of the L3 agents" % router_id)
        # NOTE(slaweq): timeout here should be lower for sure, but due to
        # the bug https://launchpad.net/bugs/1923633 let's wait even 10
        # minutes until router will be active on some of the L3 agents
        utils.wait_until_true(_router_active_on_l3_agent,
                              timeout=600, sleep=5,
                              exception=lib_exc.TimeoutException(error_msg))

    @classmethod
    def skip_if_no_extension_enabled_in_l3_agents(cls, extension):
        l3_agents = cls.os_admin.network_client.list_agents(
                binary='neutron-l3-agent')['agents']
        if not l3_agents:
            # the tests should not be skipped when neutron-l3-agent does not
            # exist (this validation doesn't apply to the setups like
            # e.g. ML2/OVN)
            return
        for agent in l3_agents:
            if extension in agent['configurations'].get('extensions', []):
                return
        raise cls.skipTest("No L3 agent with '%s' extension enabled found." %
                           extension)

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
                                 network=None, use_stateless_sg=False,
                                 **kwargs):
        """Create network resources and a server.

        Creating a network, subnet, router, keypair, security group
        and a server.
        """
        self.network = network or self.create_network()
        LOG.debug("Created network %s", self.network['name'])
        self.subnet = self.create_subnet(self.network)
        LOG.debug("Created subnet %s", self.subnet['id'])

        sg_args = {
            'name': data_utils.rand_name('secgroup')
        }
        if use_stateless_sg:
            sg_args['stateful'] = False
        secgroup = self.os_primary.network_client.create_security_group(
            **sg_args)
        LOG.debug("Created security group %s",
                  secgroup['security_group']['name'])
        self.security_groups.append(secgroup['security_group'])
        if not router:
            router = self.create_router_by_client(**kwargs)
        self.create_router_interface(router['id'], self.subnet['id'])
        self.keypair = self.create_keypair()
        self.create_loginable_secgroup_rule(
            secgroup_id=secgroup['security_group']['id'])
        if use_stateless_sg:
            self.create_ingress_metadata_secgroup_rule(
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
        self.port = self.client.list_ports(network_id=self.network['id'],
                                           device_id=self.server[
                                               'server']['id'])['ports'][0]
        self.fip = self.create_floatingip(port=self.port)

    def check_connectivity(self, host, ssh_user=None, ssh_key=None,
                           servers=None, ssh_timeout=None, ssh_client=None):
        # Either ssh_client or ssh_user+ssh_key is mandatory.
        if ssh_client is None:
            ssh_client = ssh.Client(host, ssh_user,
                                    pkey=ssh_key, timeout=ssh_timeout)
        try:
            ssh_client.test_connection_auth()
        except SSH_EXC_TUPLE as ssh_e:
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
        self._log_ns_network_status()
        for ns_name in ip_utils.IPCommand().list_namespaces():
            self._log_ns_network_status(ns_name=ns_name)

    def _log_ns_network_status(self, ns_name=None):
        try:
            local_ips = ip_utils.IPCommand(namespace=ns_name).list_addresses()
            local_routes = ip_utils.IPCommand(namespace=ns_name).list_routes()
            arp_table = ip_utils.arp_table(namespace=ns_name)
            iptables = ip_utils.list_iptables(namespace=ns_name)
            lsockets = ip_utils.list_listening_sockets(namespace=ns_name)
        except exceptions.ShellCommandFailed:
            LOG.debug('Namespace %s has been deleted synchronously during the '
                      'host network collection process', ns_name)
            return

        LOG.debug('Namespace %s; IP Addresses:\n%s',
                  ns_name, '\n'.join(str(r) for r in local_ips))
        LOG.debug('Namespace %s; Local routes:\n%s',
                  ns_name, '\n'.join(str(r) for r in local_routes))
        LOG.debug('Namespace %s; Local ARP table:\n%s',
                  ns_name, '\n'.join(str(r) for r in arp_table))
        LOG.debug('Namespace %s; Local iptables:\n%s', ns_name, iptables)
        LOG.debug('Namespace %s; Listening sockets:\n%s', ns_name, lsockets)

    def _check_remote_connectivity(self, source, dest, count,
                                   should_succeed=True,
                                   nic=None, mtu=None, fragmentation=True,
                                   timeout=None, pattern=None,
                                   forbid_packet_loss=False,
                                   check_response_ip=True):
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
        :param forbid_packet_loss: forbid or allow some lost packets
        :param check_response_ip: check response ip
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
            cmd += ' -c{0} -W{0} -s{1} {2}'.format(count, size, host)
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

            if forbid_packet_loss and ' 0% packet loss' not in result:
                LOG.debug('Packet loss detected')
                return not should_succeed

            if (check_response_ip and
                    validators.validate_ip_address(dest) is None):
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
                                  pattern=None, forbid_packet_loss=False,
                                  check_response_ip=True):
        try:
            self.assertTrue(self._check_remote_connectivity(
                source, dest, ping_count, should_succeed, nic, mtu,
                fragmentation,
                timeout=timeout, pattern=pattern,
                forbid_packet_loss=forbid_packet_loss,
                check_response_ip=check_response_ip))
        except SSH_EXC_TUPLE as ssh_e:
            LOG.debug(ssh_e)
            self._log_console_output(servers)
            self._log_local_network_status()
            raise
        except AssertionError:
            self._log_console_output(servers)
            self._log_local_network_status()
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

    def wait_for_guest_os_ready(self, server, client=None):
        if not CONF.compute_feature_enabled.console_output:
            LOG.debug('Console output not supported, cannot check if server '
                      '%s is ready.', server['id'])
            return

        client = client or self.os_primary.servers_client

        def system_booted():
            console_output = client.get_console_output(server['id'])['output']
            for line in console_output.split('\n'):
                if 'login:' in line.lower():
                    return True
            return False

        try:
            utils.wait_until_true(system_booted, timeout=90, sleep=5)
        except utils.WaitTimeout:
            LOG.debug("No correct output in console of server %s found. "
                      "Guest operating system status can't be checked.",
                      server['id'])

    def check_servers_hostnames(self, servers, timeout=None, log_errors=True,
                                external_port=None):
        """Compare hostnames of given servers with their names."""
        try:
            for server in servers:
                kwargs = {}
                if timeout:
                    kwargs['timeout'] = timeout
                try:
                    kwargs['port'] = external_port or (
                        server['port_forwarding_tcp']['external_port'])
                except KeyError:
                    pass
                ssh_client = ssh.Client(
                    self.fip['floating_ip_address'],
                    CONF.validation.image_ssh_user,
                    pkey=self.keypair['private_key'],
                    **kwargs)
                self.assertIn(server['name'],
                              ssh_client.get_hostname())
        except SSH_EXC_TUPLE as ssh_e:
            LOG.debug(ssh_e)
            if log_errors:
                self._log_console_output(servers)
                self._log_local_network_status()
            raise
        except AssertionError as assert_e:
            LOG.debug(assert_e)
            if log_errors:
                self._log_console_output(servers)
                self._log_local_network_status()
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
                become_root=True, combine_stderr=True)
        except SSH_EXC_TUPLE as ssh_e:
            LOG.debug(ssh_e)
            self._log_console_output(servers)
            self._log_local_network_status()
            raise

    def nc_client(self, ip_address, port, protocol, ssh_client=None):
        """Check connectivity to TCP/UDP port at host via nc.

        If ssh_client is not given, it is executed locally on host where tests
        are executed. Otherwise ssh_client object is used to execute it.
        """
        cmd = get_ncat_client_cmd(ip_address, port, protocol,
                                  ssh_client=ssh_client)
        result = shell.execute(cmd, ssh_client=ssh_client, check=False)
        return result.stdout

    def _ensure_public_router(self, client=None, tenant_id=None):
        """Retrieve a router for the given tenant id.

        If a public router has been configured, it will be returned.

        If a public router has not been configured, but a public
        network has, a tenant router will be created and returned that
        routes traffic to the public network.
        """
        if not client:
            client = self.client
        if not tenant_id:
            tenant_id = client.project_id
        router_id = CONF.network.public_router_id
        network_id = CONF.network.public_network_id
        if router_id:
            body = client.show_router(router_id)
            return body['router']
        elif network_id:
            router = self.create_router_by_client()
            self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                            client.delete_router, router['id'])
            kwargs = {'external_gateway_info': dict(network_id=network_id)}
            router = client.update_router(router['id'], **kwargs)['router']
            return router
        else:
            raise Exception("Neither of 'public_router_id' or "
                            "'public_network_id' has been defined.")

    def _update_router_admin_state(self, router, admin_state_up):
        kwargs = dict(admin_state_up=admin_state_up)
        router = self.client.update_router(
            router['id'], **kwargs)['router']
        self.assertEqual(admin_state_up, router['admin_state_up'])

    def _check_cmd_installed_on_server(self, ssh_client, server, cmd):
        try:
            ssh_client.execute_script('which %s' % cmd)
        except SSH_EXC_TUPLE as ssh_e:
            LOG.debug(ssh_e)
            self._log_console_output([server])
            self._log_local_network_status()
            raise
        except exceptions.SSHScriptFailed:
            raise self.skipException(
                "%s is not available on server %s" % (cmd, server['id']))
