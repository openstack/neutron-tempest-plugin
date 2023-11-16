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

import netaddr
from neutron_lib import constants
import testtools

from oslo_log import log
from tempest.common import utils as tempest_utils
from tempest.common import waiters
from tempest.lib.common.utils import data_utils
from tempest.lib.common.utils import test_utils
from tempest.lib import decorators

from neutron_tempest_plugin.common import ip
from neutron_tempest_plugin.common import ssh
from neutron_tempest_plugin.common import utils
from neutron_tempest_plugin import config
from neutron_tempest_plugin import exceptions
from neutron_tempest_plugin.scenario import base
from neutron_tempest_plugin.scenario import constants as const

CONF = config.CONF
LOG = log.getLogger(__name__)
EPHEMERAL_PORT_RANGE = {'min': 32768, 'max': 65535}


def get_capture_script(interface, tcp_port, packet_types, result_file):
    return """#!/bin/bash
tcpdump -i %(interface)s -vvneA -s0 -l -c1 \
"dst port %(port)s and tcp[tcpflags] == %(packet_types)s" &> %(result)s &
    """ % {'interface': interface,
           'port': tcp_port,
           'packet_types': packet_types,
           'result': result_file}


class BaseNetworkSecGroupTest(base.BaseTempestTestCase):
    credentials = ['primary', 'admin']
    required_extensions = ['router', 'security-group']

    def _verify_http_connection(self, ssh_client, ssh_server,
                                test_ip, test_port, servers, should_pass=True):
        """Verify if HTTP connection works using remote hosts.

        :param ssh.Client ssh_client: The client host active SSH client.
        :param ssh.Client ssh_server: The HTTP server host active SSH client.
        :param string test_ip: IP address of HTTP server
        :param string test_port: Port of HTTP server
        :param list servers: List of servers for which console output will be
                             logged in case when test case
        :param bool should_pass: Wheter test should pass or not.

        :return: if passed or not
        :rtype: bool
        """
        utils.kill_nc_process(ssh_server)
        url = 'http://%s:%d' % (test_ip, test_port)
        utils.spawn_http_server(ssh_server, port=test_port, message='foo_ok')
        utils.process_is_running(ssh_server, 'nc')
        try:
            ret = utils.call_url_remote(ssh_client, url)
            if should_pass:
                self.assertIn('foo_ok', ret)
                return
            self.assertNotIn('foo_ok', ret)
        except Exception as e:
            if not should_pass:
                return
            self._log_console_output(servers)
            self._log_local_network_status()
            raise e

    @classmethod
    def setup_credentials(cls):
        super(BaseNetworkSecGroupTest, cls).setup_credentials()
        cls.network_client = cls.os_admin.network_client

    @classmethod
    def setup_clients(cls):
        super(BaseNetworkSecGroupTest, cls).setup_clients()
        cls.project_id = cls.os_primary.credentials.tenant_id

    @classmethod
    def resource_setup(cls):
        super(BaseNetworkSecGroupTest, cls).resource_setup()
        # setup basic topology for servers we can log into it
        cls.reserve_external_subnet_cidrs()
        cls.network = cls.create_network()
        cls.subnet = cls.create_subnet(cls.network)
        cls.router = cls.create_router_by_client()
        cls.create_router_interface(cls.router['id'], cls.subnet['id'])
        if cls.ipv6_mode:
            cls.subnet_v6 = cls.create_subnet(
                cls.network,
                ip_version=constants.IP_VERSION_6,
                ipv6_ra_mode=cls.ipv6_mode,
                ipv6_address_mode=cls.ipv6_mode)
            cls.create_router_interface(cls.router['id'], cls.subnet_v6['id'])
        cls.keypair = cls.create_keypair()

    def setUp(self):
        super(BaseNetworkSecGroupTest, self).setUp()
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        self.network_client.reset_quotas, self.project_id)
        self.network_client.update_quotas(self.project_id, security_group=-1)
        self.network_client.update_quotas(self.project_id,
                                          security_group_rule=-1)

    def create_vm_testing_sec_grp(self, num_servers=2, security_groups=None,
                                  ports=None, network_id=None,
                                  use_advanced_image=False):
        """Create instance for security group testing

        :param num_servers (int): number of servers to spawn
        :param security_groups (list): list of security groups
        :param ports* (list): list of ports
        :param: use_advanced_image (bool): use Cirros (False) or
                advanced guest image
        *Needs to be the same length as num_servers
        """
        if (not use_advanced_image or
                CONF.neutron_plugin_options.default_image_is_advanced):
            flavor_ref = CONF.compute.flavor_ref
            image_ref = CONF.compute.image_ref
            username = CONF.validation.image_ssh_user
        else:
            flavor_ref = CONF.neutron_plugin_options.advanced_image_flavor_ref
            image_ref = CONF.neutron_plugin_options.advanced_image_ref
            username = CONF.neutron_plugin_options.advanced_image_ssh_user
        network_id = network_id or self.network['id']
        servers, fips, server_ssh_clients = ([], [], [])
        for i in range(num_servers):
            server_args = {
                'flavor_ref': flavor_ref,
                'image_ref': image_ref,
                'key_name': self.keypair['name'],
                'networks': [{'uuid': network_id}],
                'security_groups': security_groups
            }
            if ports is not None:
                server_args['networks'][0].update({'port': ports[i]['id']})
            servers.append(self.create_server(**server_args))
        for i, server in enumerate(servers):
            waiters.wait_for_server_status(
                self.os_primary.servers_client, server['server']['id'],
                const.SERVER_STATUS_ACTIVE)
            port = self.client.list_ports(
                network_id=network_id, device_id=server['server'][
                    'id'])['ports'][0]
            fips.append(self.create_floatingip(port=port))
            server_ssh_clients.append(ssh.Client(
                fips[i]['floating_ip_address'], username,
                pkey=self.keypair['private_key']))
        return server_ssh_clients, fips, servers

    def _get_default_security_group(self):
        sgs = self.os_primary.network_client.list_security_groups(
            project_id=self.project_id)['security_groups']
        for sg in sgs:
            if sg['name'] == 'default':
                return sg

    def _create_security_group(self, name_prefix, **kwargs):
        if self.stateless_sg:
            kwargs['stateful'] = False
        return super(BaseNetworkSecGroupTest, self).create_security_group(
            name=data_utils.rand_name(name_prefix), **kwargs)

    def _create_client_and_server_vms(
            self, allowed_tcp_port=None, use_advanced_image=False):
        networks = {
            'server': self.network,
            'client': self.create_network()}
        subnet = self.create_subnet(networks['client'])
        self.create_router_interface(self.router['id'], subnet['id'])

        security_groups = {}
        for sg_name in ["server", "client"]:
            sg = self._create_security_group('vm_%s_secgrp' % sg_name)
            self.create_loginable_secgroup_rule(
                secgroup_id=sg['id'])
            if allowed_tcp_port:
                self.create_security_group_rule(
                    security_group_id=sg['id'],
                    protocol=constants.PROTO_NAME_TCP,
                    direction=constants.INGRESS_DIRECTION,
                    port_range_min=allowed_tcp_port,
                    port_range_max=allowed_tcp_port)
            else:
                self.create_pingable_secgroup_rule(sg['id'])
            if self.stateless_sg:
                self.create_ingress_metadata_secgroup_rule(
                    secgroup_id=sg['id'])
            security_groups[sg_name] = sg
        # NOTE(slaweq): we need to iterate over create_vm_testing_sec_grp as
        # this method plugs all SGs to all VMs and we need each vm to use other
        # SGs
        ssh_clients = {}
        fips = {}
        servers = {}
        for server_name, sg in security_groups.items():
            _ssh_clients, _fips, _servers = self.create_vm_testing_sec_grp(
                num_servers=1,
                security_groups=[{'name': sg['name']}],
                network_id=networks[server_name]['id'],
                use_advanced_image=use_advanced_image)
            ssh_clients[server_name] = _ssh_clients[0]
            fips[server_name] = _fips[0]
            servers[server_name] = _servers[0]
        return ssh_clients, fips, servers, security_groups

    def _test_connectivity_between_vms_using_different_sec_groups(self):
        TEST_TCP_PORT = 1022
        ssh_clients, fips, servers, security_groups = (
            self._create_client_and_server_vms(TEST_TCP_PORT))

        # make sure tcp connectivity between vms works fine
        for fip in fips.values():
            self.check_connectivity(fip['floating_ip_address'],
                                    CONF.validation.image_ssh_user,
                                    self.keypair['private_key'])
        # Check connectivity between servers
        def _message_received(server_ssh_client, client_ssh_client,
                              dest_fip, servers):
            expected_msg = "Test_msg"
            utils.kill_nc_process(server_ssh_client)
            self.nc_listen(server_ssh_client,
                           TEST_TCP_PORT,
                           constants.PROTO_NAME_TCP,
                           expected_msg,
                           list(servers.values()))
            try:
                received_msg = self.nc_client(
                    dest_fip,
                    TEST_TCP_PORT,
                    constants.PROTO_NAME_TCP,
                    ssh_client=client_ssh_client)
                return received_msg and expected_msg in received_msg
            except exceptions.ShellCommandFailed:
                return False

        if self.stateless_sg:
            # In case of stateless SG connectivity will not work without
            # explicit allow ingress response from server to client
            utils.wait_until_true(
                lambda: not _message_received(
                    ssh_clients['server'], ssh_clients['client'],
                    fips['server']['fixed_ip_address'], servers))
            self.create_security_group_rule(
                security_group_id=security_groups['client']['id'],
                protocol=constants.PROTO_NAME_TCP,
                direction=constants.INGRESS_DIRECTION,
                port_range_min=EPHEMERAL_PORT_RANGE['min'],
                port_range_max=EPHEMERAL_PORT_RANGE['max'])

        utils.wait_until_true(
            lambda: _message_received(
                ssh_clients['server'], ssh_clients['client'],
                fips['server']['fixed_ip_address'], servers))

    def _test_ip_prefix(self, rule_list, should_succeed):
        # Add specific remote prefix to VMs and check connectivity
        ssh_secgrp = self._create_security_group('ssh_secgrp')
        self.create_loginable_secgroup_rule(
            secgroup_id=ssh_secgrp['id'])
        if self.stateless_sg:
            self.create_ingress_metadata_secgroup_rule(
                secgroup_id=ssh_secgrp['id'])
        icmp_secgrp = self._create_security_group('icmp_secgrp')
        self.create_secgroup_rules(
            rule_list, secgroup_id=icmp_secgrp['id'])
        for sec_grp in (ssh_secgrp, icmp_secgrp):
            self.security_groups.append(sec_grp)
        security_groups_list = [
            {'name': ssh_secgrp['name']},
            {'name': icmp_secgrp['name']}]
        server_ssh_clients, fips, servers = self.create_vm_testing_sec_grp(
            security_groups=security_groups_list)

        # make sure ssh connectivity works
        self.check_connectivity(fips[0]['floating_ip_address'],
                                CONF.validation.image_ssh_user,
                                self.keypair['private_key'])

        # make sure ICMP connectivity works
        self.check_remote_connectivity(server_ssh_clients[0], fips[1][
            'fixed_ip_address'], should_succeed=should_succeed,
            servers=servers)

    def _test_default_sec_grp_scenarios(self):
        # Ensure that SG used in tests is stateful or stateless as required
        default_sg_id = self._get_default_security_group()['id']
        self.os_primary.network_client.update_security_group(
            default_sg_id, stateful=not self.stateless_sg)
        if self.stateless_sg:
            self.create_ingress_metadata_secgroup_rule(
                secgroup_id=default_sg_id)
        server_ssh_clients, fips, servers = self.create_vm_testing_sec_grp()

        # Check ssh connectivity when you add sec group rule, enabling ssh
        self.create_loginable_secgroup_rule(default_sg_id)
        self.check_connectivity(fips[0]['floating_ip_address'],
                                CONF.validation.image_ssh_user,
                                self.keypair['private_key'])

        # make sure ICMP connectivity still fails as only ssh rule was added
        self.ping_ip_address(fips[0]['floating_ip_address'],
                             should_succeed=False)

        # Check ICMP connectivity between VMs without specific rule for that
        # It should work though the rule is not configured
        self.check_remote_connectivity(
            server_ssh_clients[0], fips[1]['fixed_ip_address'],
            servers=servers)

        # Check ICMP connectivity from VM to external network
        if self.stateless_sg:
            # NOTE(slaweq): in case of stateless SG explicit ingress rule for
            # the ICMP replies needs to be added too
            self.create_pingable_secgroup_rule(default_sg_id)
        subnets = self.os_admin.network_client.list_subnets(
            network_id=CONF.network.public_network_id)['subnets']
        ext_net_ip = None
        for subnet in subnets:
            if subnet['ip_version'] == 4:
                ext_net_ip = subnet['gateway_ip']
                break
        self.assertTrue(ext_net_ip)
        self.check_remote_connectivity(server_ssh_clients[0], ext_net_ip,
                                       servers=servers)
        return server_ssh_clients, fips, servers

    def _test_protocol_number_rule(self):
        # protocol number is added instead of str in security rule creation
        name = data_utils.rand_name("test_protocol_number_rule")
        security_group = self._create_security_group(name)
        port = self.create_port(network=self.network, name=name,
                                security_groups=[security_group['id']])
        _, fips, _ = self.create_vm_testing_sec_grp(num_servers=1,
                                                    ports=[port])
        self.ping_ip_address(fips[0]['floating_ip_address'],
                             should_succeed=False)
        rule_list = [{'protocol': constants.PROTO_NUM_ICMP,
                      'direction': constants.INGRESS_DIRECTION,
                      'remote_ip_prefix': '0.0.0.0/0'}]
        self.create_secgroup_rules(rule_list, secgroup_id=security_group['id'])
        self.ping_ip_address(fips[0]['floating_ip_address'])

    def _test_two_sec_groups(self):
        # add 2 sec groups to VM and test rules of both are working
        ssh_secgrp = self._create_security_group('ssh_secgrp')
        self.create_loginable_secgroup_rule(
            secgroup_id=ssh_secgrp['id'])
        icmp_secgrp = self._create_security_group('icmp_secgrp')
        self.create_pingable_secgroup_rule(
            secgroup_id=icmp_secgrp['id'])
        if self.stateless_sg:
            self.create_ingress_metadata_secgroup_rule(
                secgroup_id=ssh_secgrp['id'])
        for sec_grp in (ssh_secgrp, icmp_secgrp):
            self.security_groups.append(sec_grp)
        security_groups_list = [
            {'name': ssh_secgrp['name']},
            {'name': icmp_secgrp['name']}]
        server_ssh_clients, fips, servers = self.create_vm_testing_sec_grp(
            num_servers=1, security_groups=security_groups_list)
        # make sure ssh connectivity works
        self.check_connectivity(fips[0]['floating_ip_address'],
                                CONF.validation.image_ssh_user,
                                self.keypair['private_key'])
        # make sure ICMP connectivity works
        self.ping_ip_address(fips[0]['floating_ip_address'],
                             should_succeed=True)
        ports = self.client.list_ports(device_id=servers[0]['server']['id'])
        port_id = ports['ports'][0]['id']

        # update port with ssh security group only
        self.os_primary.network_client.update_port(
            port_id, security_groups=[ssh_secgrp['id']])

        # make sure ssh connectivity works
        self.check_connectivity(fips[0]['floating_ip_address'],
                                CONF.validation.image_ssh_user,
                                self.keypair['private_key'])

        # make sure ICMP connectivity doesn't work
        self.ping_ip_address(fips[0]['floating_ip_address'],
                             should_succeed=False)

        # update port with ssh and ICMP security groups
        self.os_primary.network_client.update_port(
            port_id, security_groups=[icmp_secgrp['id'], ssh_secgrp['id']])

        # make sure ssh connectivity  works after update
        self.check_connectivity(fips[0]['floating_ip_address'],
                                CONF.validation.image_ssh_user,
                                self.keypair['private_key'])

        # make sure ICMP connectivity works after update
        self.ping_ip_address(fips[0]['floating_ip_address'])

    def _test_remote_group(self):
        # create a new sec group
        ssh_secgrp = self._create_security_group('ssh_secgrp')
        # configure sec group to support SSH connectivity
        self.create_loginable_secgroup_rule(
            secgroup_id=ssh_secgrp['id'])
        if self.stateless_sg:
            self.create_ingress_metadata_secgroup_rule(
                secgroup_id=ssh_secgrp['id'])
        # spawn two instances with the sec group created
        server_ssh_clients, fips, servers = self.create_vm_testing_sec_grp(
            security_groups=[{'name': ssh_secgrp['name']}])
        # verify SSH functionality
        for i in range(2):
            self.check_connectivity(fips[i]['floating_ip_address'],
                                    CONF.validation.image_ssh_user,
                                    self.keypair['private_key'])
        # try to ping instances without ICMP permissions
        self.check_remote_connectivity(
            server_ssh_clients[0], fips[1]['fixed_ip_address'],
            should_succeed=False)
        # add ICMP support to the remote group
        rule_list = [{'protocol': constants.PROTO_NUM_ICMP,
                      'direction': constants.INGRESS_DIRECTION,
                      'remote_group_id': ssh_secgrp['id']}]
        self.create_secgroup_rules(
            rule_list, secgroup_id=ssh_secgrp['id'])
        # verify ICMP connectivity between instances works
        self.check_remote_connectivity(
            server_ssh_clients[0], fips[1]['fixed_ip_address'],
            servers=servers)
        # make sure ICMP connectivity doesn't work from framework
        self.ping_ip_address(fips[0]['floating_ip_address'],
                             should_succeed=False)

    def _test_remote_group_and_remote_address_group(self):
        """Test SG rules with remote group and remote address group

        This test checks the ICMP connection among two servers using a security
        group rule with remote group and another rule with remote address
        group. The connection should be granted when at least one of the rules
        is applied. When both rules are applied (overlapped), removing one of
        them should not disable the connection.
        """
        # create a new sec group
        ssh_secgrp = self._create_security_group('ssh_secgrp')
        # configure sec group to support SSH connectivity
        self.create_loginable_secgroup_rule(
            secgroup_id=ssh_secgrp['id'])
        # spawn two instances with the sec group created
        server_ssh_clients, fips, servers = self.create_vm_testing_sec_grp(
            security_groups=[{'name': ssh_secgrp['name']}])
        # verify SSH functionality
        for i in range(2):
            self.check_connectivity(fips[i]['floating_ip_address'],
                                    CONF.validation.image_ssh_user,
                                    self.keypair['private_key'])
        # try to ping instances without ICMP permissions
        self.check_remote_connectivity(
            server_ssh_clients[0], fips[1]['fixed_ip_address'],
            should_succeed=False)
        # add ICMP support to the remote group
        rule_list = [{'protocol': constants.PROTO_NUM_ICMP,
                      'direction': constants.INGRESS_DIRECTION,
                      'remote_group_id': ssh_secgrp['id']}]
        remote_sg_rid = self.create_secgroup_rules(
            rule_list, secgroup_id=ssh_secgrp['id'])[0]['id']
        # verify ICMP connectivity between instances works
        self.check_remote_connectivity(
            server_ssh_clients[0], fips[1]['fixed_ip_address'],
            servers=servers)
        # make sure ICMP connectivity doesn't work from framework
        self.ping_ip_address(fips[0]['floating_ip_address'],
                             should_succeed=False)

        # add ICMP rule with remote address group
        test_ag = self.create_address_group(
            name=data_utils.rand_name('test_ag'),
            addresses=[str(netaddr.IPNetwork(fips[0]['fixed_ip_address']))])
        rule_list = [{'protocol': constants.PROTO_NUM_ICMP,
                      'direction': constants.INGRESS_DIRECTION,
                      'remote_address_group_id': test_ag['id']}]
        remote_ag_rid = self.create_secgroup_rules(
            rule_list, secgroup_id=ssh_secgrp['id'])[0]['id']
        # verify ICMP connectivity between instances still works
        self.check_remote_connectivity(
            server_ssh_clients[0], fips[1]['fixed_ip_address'],
            servers=servers)
        # make sure ICMP connectivity doesn't work from framework
        self.ping_ip_address(fips[0]['floating_ip_address'],
                             should_succeed=False)

        # Remove the ICMP rule with remote group
        self.client.delete_security_group_rule(remote_sg_rid)
        # verify ICMP connectivity between instances still works as granted
        # by the rule with remote address group
        self.check_remote_connectivity(
            server_ssh_clients[0], fips[1]['fixed_ip_address'],
            servers=servers)
        # make sure ICMP connectivity doesn't work from framework
        self.ping_ip_address(fips[0]['floating_ip_address'],
                             should_succeed=False)

        # Remove the ICMP rule with remote address group
        self.client.delete_security_group_rule(remote_ag_rid)
        # verify ICMP connectivity between instances doesn't work now
        self.check_remote_connectivity(
            server_ssh_clients[0], fips[1]['fixed_ip_address'],
            should_succeed=False)
        # make sure ICMP connectivity doesn't work from framework
        self.ping_ip_address(fips[0]['floating_ip_address'],
                             should_succeed=False)

    def _test_multiple_ports_secgroup_inheritance(self):
        """Test multiple port security group inheritance

        This test creates two ports with security groups, then
        boots two instances and verify that the security group was
        inherited properly and enforced in these instances.
        """
        # create a security group and make it loginable and pingable
        secgrp = self._create_security_group('secgrp')
        self.create_loginable_secgroup_rule(
            secgroup_id=secgrp['id'])
        self.create_pingable_secgroup_rule(
            secgroup_id=secgrp['id'])
        if self.stateless_sg:
            self.create_ingress_metadata_secgroup_rule(
                secgroup_id=secgrp['id'])
        # create two ports with fixed IPs and the security group created
        ports = []
        for i in range(2):
            ports.append(self.create_port(
                self.network, fixed_ips=[{'subnet_id': self.subnets[0]['id']}],
                security_groups=[secgrp['id']]))
        # spawn instances with the ports created
        server_ssh_clients, fips, servers = self.create_vm_testing_sec_grp(
            ports=ports)
        # verify ICMP reachability and ssh connectivity
        for fip in fips:
            self.ping_ip_address(fip['floating_ip_address'])
            self.check_connectivity(fip['floating_ip_address'],
                                    CONF.validation.image_ssh_user,
                                    self.keypair['private_key'])

    def _test_multiple_ports_portrange_remote(self):
        initial_security_groups = []
        if self.stateless_sg:
            md_secgrp = self._create_security_group('metadata_secgrp')
            self.create_ingress_metadata_secgroup_rule(
                secgroup_id=md_secgrp['id'])
            initial_security_groups.append(
                {'name': md_secgrp['name']})

        ssh_clients, fips, servers = self.create_vm_testing_sec_grp(
            num_servers=3, security_groups=initial_security_groups)
        secgroups = []
        ports = []

        # Create remote and test security groups
        for i in range(0, 2):
            secgroups.append(
                self._create_security_group('secgrp-%d' % i))
            # configure sec groups to support SSH connectivity
            self.create_loginable_secgroup_rule(
                secgroup_id=secgroups[-1]['id'])

        # Configure security groups, first two servers as remotes
        for i, server in enumerate(servers):
            port = self.client.list_ports(
                network_id=self.network['id'], device_id=server['server'][
                    'id'])['ports'][0]
            ports.append(port)
            secgroup = secgroups[0 if i in range(0, 2) else 1]
            self.client.update_port(port['id'], security_groups=[
                secgroup['id']])

        # verify SSH functionality
        for fip in fips:
            self.check_connectivity(fip['floating_ip_address'],
                                    CONF.validation.image_ssh_user,
                                    self.keypair['private_key'])

        test_ip = ports[2]['fixed_ips'][0]['ip_address']

        # verify that conections are not working
        for port in range(80, 84):
            with utils.StatefulConnection(
                    ssh_clients[0], ssh_clients[2], test_ip, port) as con:
                con.test_connection(should_pass=False)

        # add two remote-group rules with port-ranges
        rule_list = [{'protocol': constants.PROTO_NUM_TCP,
                      'direction': constants.INGRESS_DIRECTION,
                      'port_range_min': '80',
                      'port_range_max': '81',
                      'remote_group_id': secgroups[0]['id']},
                     {'protocol': constants.PROTO_NUM_TCP,
                      'direction': constants.INGRESS_DIRECTION,
                      'port_range_min': '82',
                      'port_range_max': '83',
                      'remote_group_id': secgroups[0]['id']}]
        if self.stateless_sg:
            rule_list.append({
                'protocol': constants.PROTO_NUM_TCP,
                'direction': constants.EGRESS_DIRECTION,
                'remote_group_id': secgroups[0]['id']})
            # NOTE(slaweq): in case of stateless SG, client needs to have also
            # rule which will explicitly accept ingress connections from
            # secgroup[1]

            self.create_security_group_rule(
                security_group_id=secgroups[0]['id'],
                protocol=constants.PROTO_NAME_TCP,
                direction=constants.INGRESS_DIRECTION,
                remote_group_id=secgroups[1]['id'])

        self.create_secgroup_rules(
            rule_list, secgroup_id=secgroups[1]['id'])

        # verify that conections are working
        for port in range(80, 84):
            with utils.StatefulConnection(
                    ssh_clients[0], ssh_clients[2], test_ip, port) as con:
                con.test_connection()

        # list the tcp rule id by SG id and port-range
        sg_rule_id = self.os_primary.network_client.list_security_group_rules(
            security_group_id=secgroups[1]['id'],
            port_range_min=80)['security_group_rules'][0]['id']

        # delete the tcp rule from the security group
        self.client.delete_security_group_rule(sg_rule_id)

        # verify that conections are not working
        for port in range(80, 82):
            with utils.StatefulConnection(
                    ssh_clients[0], ssh_clients[2], test_ip, port) as con:
                con.test_connection(should_pass=False)

    def _test_overlapping_sec_grp_rules(self):
        """Test security group rules with overlapping port ranges"""
        initial_security_groups = []
        if self.stateless_sg:
            md_secgrp = self._create_security_group('metadata_secgrp')
            self.create_ingress_metadata_secgroup_rule(
                secgroup_id=md_secgrp['id'])
            initial_security_groups.append(
                {'name': md_secgrp['name']})
        client_ssh, _, vms = self.create_vm_testing_sec_grp(
            num_servers=2, security_groups=initial_security_groups)
        tmp_ssh, _, tmp_vm = self.create_vm_testing_sec_grp(
            num_servers=1, security_groups=initial_security_groups)
        srv_ssh = tmp_ssh[0]
        srv_vm = tmp_vm[0]
        srv_port = self.client.list_ports(network_id=self.network['id'],
                device_id=srv_vm['server']['id'])['ports'][0]
        srv_ip = srv_port['fixed_ips'][0]['ip_address']
        secgrps = []
        for i, vm in enumerate(vms):
            sg = self._create_security_group('secgrp-%d' % i)
            self.create_loginable_secgroup_rule(secgroup_id=sg['id'])
            port = self.client.list_ports(network_id=self.network['id'],
                    device_id=vm['server']['id'])['ports'][0]
            self.client.update_port(port['id'], security_groups=[sg['id']])
            secgrps.append(sg)
        tcp_port = 3000
        rule_list = [{'protocol': constants.PROTO_NUM_TCP,
                      'direction': constants.INGRESS_DIRECTION,
                      'port_range_min': tcp_port,
                      'port_range_max': tcp_port,
                      'remote_group_id': secgrps[0]['id']},
                     {'protocol': constants.PROTO_NUM_TCP,
                      'direction': constants.INGRESS_DIRECTION,
                      'port_range_min': tcp_port,
                      'port_range_max': tcp_port + 2,
                      'remote_group_id': secgrps[1]['id']}]
        self.client.update_port(srv_port['id'],
                security_groups=[secgrps[0]['id'], secgrps[1]['id']])
        self.create_secgroup_rules(rule_list, secgroup_id=secgrps[0]['id'])

        if self.stateless_sg:
            # NOTE(slaweq): in case of stateless SG, client needs to have also
            # rule which will explicitly accept ingress TCP connections which
            # will be replies from the TCP server so it will use random
            # destination port (depends on the src port choosen by client while
            # establishing connection)
            self.create_security_group_rule(
                security_group_id=secgrps[0]['id'],
                protocol=constants.PROTO_NAME_TCP,
                direction=constants.INGRESS_DIRECTION)
            self.create_security_group_rule(
                security_group_id=secgrps[1]['id'],
                protocol=constants.PROTO_NAME_TCP,
                direction=constants.INGRESS_DIRECTION)

        # The conntrack entries are ruled by the OF definitions but conntrack
        # status can change the datapath. Let's check the rules in two
        # attempts
        for _ in range(2):
            with utils.StatefulConnection(
                    client_ssh[0], srv_ssh, srv_ip, tcp_port) as con:
                con.test_connection()
            for port in range(tcp_port, tcp_port + 3):
                with utils.StatefulConnection(
                        client_ssh[1], srv_ssh, srv_ip, port) as con:
                    con.test_connection()

    def _test_remove_sec_grp_from_active_vm(self):
        """Tests the following:

        1. Create SG associated with ICMP rule
        2. Create Port (assoiated to SG #1) and use it to create the VM
        3. Ping the VM, expected should be PASS
        4. Remove the security group from VM by Port update
        5. Ping the VM, expected should be FAIL
        """
        secgrp = self._create_security_group('test_sg')
        self.security_groups.append(secgrp)
        self.create_pingable_secgroup_rule(secgrp['id'])

        ex_port = self.create_port(
            self.network, fixed_ips=[{'subnet_id': self.subnet['id']}],
            security_groups=[secgrp['id']])
        fip = self.create_vm_testing_sec_grp(
            num_servers=1, security_groups=[{'name': secgrp['name']}],
            ports=[ex_port])[1][0]

        self.ping_ip_address(fip['floating_ip_address'])
        self.client.update_port(ex_port['id'],
                                security_groups=[])
        self.ping_ip_address(fip['floating_ip_address'],
                             should_succeed=False)


class StatefulNetworkSecGroupTest(BaseNetworkSecGroupTest):
    stateless_sg = False
    ipv6_mode = None

    @decorators.idempotent_id('3d73ec1a-2ec6-45a9-b0f8-04a283d9d764')
    def test_default_sec_grp_scenarios(self):
        self._test_default_sec_grp_scenarios()

    @decorators.idempotent_id('3d73ec1a-2ec6-45a9-b0f8-04a283d9d864')
    def test_protocol_number_rule(self):
        self._test_protocol_number_rule()

    @decorators.idempotent_id('3d73ec1a-2ec6-45a9-b0f8-04a283d9d964')
    def test_two_sec_groups(self):
        self._test_two_sec_groups()

    @decorators.idempotent_id('3d73ec1a-2ec6-45a9-b0f8-04a283d9d664')
    def test_ip_prefix(self):
        cidr = self.subnet['cidr']
        rule_list = [{'protocol': constants.PROTO_NUM_ICMP,
                      'direction': constants.INGRESS_DIRECTION,
                      'remote_ip_prefix': cidr}]
        self._test_ip_prefix(rule_list, should_succeed=True)

    @decorators.attr(type='negative')
    @decorators.idempotent_id('a01cd2ef-3cfc-4614-8aac-9d1333ea21dd')
    def test_ip_prefix_negative(self):
        # define bad CIDR
        cidr = '10.100.0.254/32'
        rule_list = [{'protocol': constants.PROTO_NUM_ICMP,
                      'direction': constants.INGRESS_DIRECTION,
                      'remote_ip_prefix': cidr}]
        self._test_ip_prefix(rule_list, should_succeed=False)

    @decorators.idempotent_id('7ed39b86-006d-40fb-887a-ae46693dabc9')
    def test_remote_group(self):
        self._test_remote_group()

    @testtools.skipUnless(
        CONF.neutron_plugin_options.firewall_driver == 'openvswitch',
        "Openvswitch agent is required to run this test")
    @decorators.idempotent_id('678dd4c0-2953-4626-b89c-8e7e4110ec4b')
    @tempest_utils.requires_ext(extension="address-group", service="network")
    @tempest_utils.requires_ext(
        extension="security-groups-remote-address-group", service="network")
    def test_remote_group_and_remote_address_group(self):
        self._test_remote_group_and_remote_address_group()

    @decorators.idempotent_id('f07d0159-8f9e-4faa-87f5-a869ab0ad488')
    def test_multiple_ports_secgroup_inheritance(self):
        self._test_multiple_ports_secgroup_inheritance()

    @decorators.idempotent_id('f07d0159-8f9e-4faa-87f5-a869ab0ad489')
    def test_multiple_ports_portrange_remote(self):
        self._test_multiple_ports_portrange_remote()

    @decorators.idempotent_id('f07d0159-8f9e-4faa-87f5-a869ab0ad490')
    def test_intra_sg_isolation(self):
        """Test intra security group isolation

        This test creates a security group that does not allow ingress
        packets from vms of the same security group. The purpose of this
        test is to verify that intra SG traffic is properly blocked, while
        traffic like metadata and DHCP remains working due to the
        allow-related behavior of the egress rules (added via default).
        """
        # create a security group and make it loginable
        secgrp = self._create_security_group('secgrp')

        # remove all rules and add ICMP, DHCP and metadata as egress,
        # and ssh as ingress.
        for sgr in secgrp['security_group_rules']:
            self.client.delete_security_group_rule(sgr['id'])

        self.create_loginable_secgroup_rule(secgroup_id=secgrp['id'])
        rule_list = [{'direction': constants.EGRESS_DIRECTION,
                      'protocol': constants.PROTO_NAME_TCP,
                      'remote_ip_prefix': '169.254.169.254/32',
                      'description': 'metadata out',
                      },
                     {'direction': constants.EGRESS_DIRECTION,
                      'protocol': constants.PROTO_NAME_UDP,
                      'port_range_min': '67',
                      'port_range_max': '67',
                      'description': 'dhcpv4 out',
                      },
                     {'direction': constants.EGRESS_DIRECTION,
                      'protocol': constants.PROTO_NAME_ICMP,
                      'description': 'ping out',
                      },
                     ]
        self.create_secgroup_rules(rule_list, secgroup_id=secgrp['id'])

        # go vms, go!
        ssh_clients, fips, servers = self.create_vm_testing_sec_grp(
            num_servers=2,
            security_groups=[{'name': secgrp['name']}])

        # verify SSH functionality. This will ensure that servers were
        # able to reach dhcp + metadata servers
        for fip in fips:
            self.check_connectivity(fip['floating_ip_address'],
                                    CONF.validation.image_ssh_user,
                                    self.keypair['private_key'])

        # try to ping instances without intra SG permission (should fail)
        self.check_remote_connectivity(
            ssh_clients[0], fips[1]['fixed_ip_address'],
            should_succeed=False)
        self.check_remote_connectivity(
            ssh_clients[1], fips[0]['fixed_ip_address'],
            should_succeed=False)

        # add intra sg rule. This will allow packets from servers that
        # are in the same sg
        rule_list = [{'direction': constants.INGRESS_DIRECTION,
                      'remote_group_id': secgrp['id']}]
        self.create_secgroup_rules(rule_list, secgroup_id=secgrp['id'])

        # try to ping instances with intra SG permission
        self.check_remote_connectivity(
            ssh_clients[0], fips[1]['fixed_ip_address'])
        self.check_remote_connectivity(
            ssh_clients[1], fips[0]['fixed_ip_address'])

    @decorators.idempotent_id('cd66b826-d86c-4fb4-ab37-17c8391753cb')
    def test_overlapping_sec_grp_rules(self):
        self._test_overlapping_sec_grp_rules()

    @decorators.idempotent_id('96dcd5ff-9d45-4e0d-bea0-0b438cbd388f')
    def test_remove_sec_grp_from_active_vm(self):
        self._test_remove_sec_grp_from_active_vm()

    @decorators.idempotent_id('01f0ddca-b049-47eb-befd-82acb502c9ec')
    def test_established_tcp_session_after_re_attachinging_sg(self):
        """Test existing connection remain open after sg has been re-attached

        Verifies that new packets can pass over the existing connection when
        the security group has been removed from the server and then added
        back
        """

        ssh_sg = self._create_security_group('ssh_sg')
        self.create_loginable_secgroup_rule(secgroup_id=ssh_sg['id'])
        vm_ssh, fips, vms = self.create_vm_testing_sec_grp(
                security_groups=[{'name': ssh_sg['name']}])
        sg = self._create_security_group('sg')
        nc_rule = [{'protocol': constants.PROTO_NUM_TCP,
                    'direction': constants.INGRESS_DIRECTION,
                    'port_range_min': 6666,
                    'port_range_max': 6666}]
        self.create_secgroup_rules(nc_rule, secgroup_id=sg['id'])
        srv_port = self.client.list_ports(network_id=self.network['id'],
                device_id=vms[1]['server']['id'])['ports'][0]
        srv_ip = srv_port['fixed_ips'][0]['ip_address']
        with utils.StatefulConnection(
                vm_ssh[0], vm_ssh[1], srv_ip, 6666) as con:
            self.client.update_port(srv_port['id'],
                    security_groups=[ssh_sg['id'], sg['id']])
            con.test_connection()
        with utils.StatefulConnection(
                vm_ssh[0], vm_ssh[1], srv_ip, 6666) as con:
            self.client.update_port(
                    srv_port['id'], security_groups=[ssh_sg['id']])
            con.test_connection(should_pass=False)
        with utils.StatefulConnection(
                vm_ssh[0], vm_ssh[1], srv_ip, 6666) as con:
            self.client.update_port(srv_port['id'],
                    security_groups=[ssh_sg['id'], sg['id']])
            con.test_connection()
            self.client.update_port(srv_port['id'],
                    security_groups=[ssh_sg['id']])
            con.test_connection(should_pass=False)
            self.client.update_port(srv_port['id'],
                    security_groups=[ssh_sg['id'], sg['id']])
            con.test_connection()

    @decorators.idempotent_id('4a724164-bbc0-4029-a844-644ece66c026')
    def test_connectivity_between_vms_using_different_sec_groups(self):
        self._test_connectivity_between_vms_using_different_sec_groups()


@testtools.skipIf(
    CONF.neutron_plugin_options.firewall_driver in ['openvswitch', 'None'],
    "Firewall driver other than 'openvswitch' is required to use "
    "stateless security groups.")
class StatelessNetworkSecGroupIPv4Test(BaseNetworkSecGroupTest):
    required_extensions = ['security-group', 'stateful-security-group']
    stateless_sg = True
    ipv6_mode = None

    @decorators.idempotent_id('9e193e3f-56f2-4f4e-886c-988a147958ef')
    def test_default_sec_grp_scenarios(self):
        self._test_default_sec_grp_scenarios()

    @decorators.idempotent_id('afae8654-a389-4887-b21d-7f07ec350177')
    def test_protocol_number_rule(self):
        self._test_protocol_number_rule()

    @decorators.idempotent_id('b51cc0eb-8f9a-49e7-96ab-61cd31243b67')
    def test_two_sec_groups(self):
        self._test_two_sec_groups()

    @decorators.idempotent_id('07985496-58da-4c1f-a6ef-2fdd88128a81')
    def test_ip_prefix(self):
        cidr = self.subnet['cidr']
        rule_list = [{'protocol': constants.PROTO_NUM_ICMP,
                      'direction': constants.INGRESS_DIRECTION,
                      'remote_ip_prefix': cidr}]
        self._test_ip_prefix(rule_list, should_succeed=True)

    @decorators.attr(type='negative')
    @decorators.idempotent_id('1ad469c4-0d8f-42ae-8ec3-46cc424565c4')
    def test_ip_prefix_negative(self):
        # define bad CIDR
        cidr = '10.100.0.254/32'
        rule_list = [{'protocol': constants.PROTO_NUM_ICMP,
                      'direction': constants.INGRESS_DIRECTION,
                      'remote_ip_prefix': cidr}]
        self._test_ip_prefix(rule_list, should_succeed=False)

    @decorators.idempotent_id('fa1e93bf-67c5-4590-9962-38ee1f43a46a')
    def test_remote_group(self):
        self._test_remote_group()

    @testtools.skipUnless(
        CONF.neutron_plugin_options.firewall_driver == 'openvswitch',
        "Openvswitch agent is required to run this test")
    @decorators.idempotent_id('9fae530d-2711-4c61-a4a5-8efe6e58ab14')
    @tempest_utils.requires_ext(extension="address-group", service="network")
    @tempest_utils.requires_ext(
        extension="security-groups-remote-address-group", service="network")
    def test_remote_group_and_remote_address_group(self):
        self._test_remote_group_and_remote_address_group()

    @decorators.idempotent_id('4f1eb6db-ae7f-4f26-b371-cbd8363f9b0b')
    def test_multiple_ports_secgroup_inheritance(self):
        self._test_multiple_ports_secgroup_inheritance()

    @decorators.idempotent_id('4043ca0a-eabb-4198-be53-3d3051cc0804')
    def test_multiple_ports_portrange_remote(self):
        self._test_multiple_ports_portrange_remote()

    @decorators.idempotent_id('bfe25138-ceac-4944-849a-b9b90aff100f')
    def test_overlapping_sec_grp_rules(self):
        self._test_overlapping_sec_grp_rules()

    @decorators.idempotent_id('e4340e47-39cd-49ed-967c-fc2c40b47c5a')
    def test_remove_sec_grp_from_active_vm(self):
        self._test_remove_sec_grp_from_active_vm()

    @decorators.idempotent_id('8d4753cc-cd7a-48a0-8ece-e11efce2af10')
    def test_reattach_sg_with_changed_mode(self):
        sg_kwargs = {'stateful': True}
        secgrp = self.os_primary.network_client.create_security_group(
            name=data_utils.rand_name('secgrp'), **sg_kwargs)['security_group']
        # add cleanup
        self.security_groups.append(secgrp)

        # now configure sec group to support required connectivity
        self.create_pingable_secgroup_rule(secgroup_id=secgrp['id'])
        # and create server
        ssh_clients, fips, servers = self.create_vm_testing_sec_grp(
            num_servers=1, security_groups=[{'name': secgrp['name']}])
        server_ports = self.network_client.list_ports(
            device_id=servers[0]['server']['id'])['ports']

        # make sure connectivity works
        self.ping_ip_address(fips[0]['floating_ip_address'],
                             should_succeed=True)
        # remove SG from ports
        for port in server_ports:
            self.network_client.update_port(port['id'], security_groups=[])
        # make sure there is now no connectivity as there's no SG attached
        # to the port
        self.ping_ip_address(fips[0]['floating_ip_address'],
                             should_succeed=False)

        # Update SG to be stateless
        self.os_primary.network_client.update_security_group(
            secgrp['id'], stateful=False)
        # Add SG back to the ports
        for port in server_ports:
            self.network_client.update_port(
                port['id'], security_groups=[secgrp['id']])
        # Make sure connectivity works fine again
        self.ping_ip_address(fips[0]['floating_ip_address'],
                             should_succeed=True)

    @decorators.idempotent_id('7ede9ab5-a615-46c5-9dea-cf2aa1ea43cb')
    def test_connectivity_between_vms_using_different_sec_groups(self):
        self._test_connectivity_between_vms_using_different_sec_groups()

    @testtools.skipUnless(
        (CONF.neutron_plugin_options.advanced_image_ref or
         CONF.neutron_plugin_options.default_image_is_advanced),
        "Advanced image is required to run this test.")
    @decorators.idempotent_id('c3bb8073-97a2-4bea-a6fb-0a9d2e4df13f')
    def test_packets_of_any_connection_state_can_reach_dest(self):
        TEST_TCP_PORT = 1022
        PKT_TYPES = [
            {'nping': 'syn', 'tcpdump': 'tcp-syn'},
            {'nping': 'ack', 'tcpdump': 'tcp-ack'},
            {'nping': 'syn,ack', 'tcpdump': 'tcp-syn|tcp-ack'},
            {'nping': 'rst', 'tcpdump': 'tcp-rst'},
            {'nping': 'fin', 'tcpdump': 'tcp-fin'},
            {'nping': 'psh', 'tcpdump': 'tcp-push'}]
        ssh_clients, fips, servers, _ = self._create_client_and_server_vms(
            TEST_TCP_PORT, use_advanced_image=True)

        self._check_cmd_installed_on_server(
            ssh_clients['server'], servers['server']['server'], 'nping')
        self._check_cmd_installed_on_server(
            ssh_clients['client'], servers['client']['server'], 'tcpdump')
        server_port = self.network_client.show_port(
            fips['server']['port_id'])['port']
        server_ip_command = ip.IPCommand(ssh_client=ssh_clients['server'])
        addresses = server_ip_command.list_addresses(port=server_port)
        port_iface = ip.get_port_device_name(addresses, server_port)

        def _get_file_suffix(pkt_type):
            return pkt_type['tcpdump'].replace(
                'tcp-', '').replace('|', '')

        for pkt_type in PKT_TYPES:
            file_suffix = _get_file_suffix(pkt_type)
            capture_script_path = "/tmp/capture_%s.sh" % file_suffix
            capture_out = "/tmp/capture_%s.out" % file_suffix
            capture_script = get_capture_script(
                port_iface, TEST_TCP_PORT, pkt_type['tcpdump'], capture_out)
            ssh_clients['server'].execute_script(
                'echo \'%s\' > %s' % (capture_script, capture_script_path))
            ssh_clients['server'].execute_script(
                "bash %s" % capture_script_path, become_root=True)

        for pkt_type in PKT_TYPES:
            ssh_clients['client'].execute_script(
                "nping --tcp -p %(tcp_port)s --flags %(tcp_flag)s --ttl 10 "
                "%(ip_address)s -c 3" % {
                    'tcp_port': TEST_TCP_PORT,
                    'tcp_flag': pkt_type['nping'],
                    'ip_address': fips['server']['fixed_ip_address']},
                become_root=True)

        def _packtet_received(pkt_type):
            file_suffix = _get_file_suffix(pkt_type)
            expected_msg = "1 packet captured"
            result = ssh_clients['server'].execute_script(
                "cat {path} || echo '{path} not exists yet'".format(
                    path="/tmp/capture_%s.out" % file_suffix))
            return expected_msg in result

        for pkt_type in PKT_TYPES:
            utils.wait_until_true(
                lambda: _packtet_received(pkt_type),
                timeout=10,
                exception=RuntimeError(
                    'No TCP packet of type %s received by server %s' % (
                        pkt_type['nping'],
                        fips['server']['fixed_ip_address'])))

    @testtools.skipUnless(
        (CONF.neutron_plugin_options.advanced_image_ref or
         CONF.neutron_plugin_options.default_image_is_advanced),
        "Advanced image is required to run this test.")
    @decorators.idempotent_id('14c4af2c-8077-4756-a6e3-6bebd642ed92')
    def test_fragmented_traffic_is_accepted(self):
        ssh_clients, fips, servers, security_groups = (
            self._create_client_and_server_vms(use_advanced_image=True))
        if CONF.neutron_plugin_options.default_image_is_advanced:
            username = CONF.validation.image_ssh_user
        else:
            username = CONF.neutron_plugin_options.advanced_image_ssh_user

        # make sure tcp connectivity to vms works fine
        for fip in fips.values():
            self.check_connectivity(
                fip['floating_ip_address'],
                username,
                self.keypair['private_key'])

        # Check that ICMP packets bigger than MTU aren't working without
        # fragmentation allowed
        self.check_remote_connectivity(
            ssh_clients['client'], fips['server']['fixed_ip_address'],
            mtu=self.network['mtu'] + 1, fragmentation=False,
            should_succeed=False)
        # and are working fine with fragmentation enabled:
        self.check_remote_connectivity(
            ssh_clients['client'], fips['server']['fixed_ip_address'],
            mtu=self.network['mtu'] + 1, fragmentation=True,
            should_succeed=True)


class StatelessSecGroupDualStackBase(BaseNetworkSecGroupTest):
    required_extensions = ['security-group', 'stateful-security-group']
    stateless_sg = True

    def _get_port_cidrs(self, port):
        ips = []
        subnet_cidrs = {}
        for fixed_ip in port['fixed_ips']:
            subnet_id = fixed_ip['subnet_id']
            subnet_cidr = subnet_cidrs.get('subnet_id')
            if not subnet_cidr:
                subnet = self.client.show_subnet(subnet_id)['subnet']
                subnet_cidr = netaddr.IPNetwork(subnet['cidr'])
                subnet_cidrs[subnet_id] = subnet_cidr
            ips.append(
                netaddr.IPNetwork(
                    "%s/%s" % (fixed_ip['ip_address'], subnet_cidr.prefixlen)))
        LOG.debug("On port %s found IP cidrs: %s", port['id'], ips)
        return ips

    def _test_default_sec_grp_scenarios(self):
        # Make "regular" test like for IPv4 case
        server_ssh_clients, _, servers = (
            super()._test_default_sec_grp_scenarios())

        # And additionally ensure that IPv6 addresses are configured properly
        # in the VM
        for ssh_client, server in zip(server_ssh_clients, servers):
            ip_cmd = ip.IPCommand(ssh_client=ssh_client)
            ports = self.client.list_ports(
                device_id=server['server']['id'])['ports']
            for port in ports:
                configured_cidrs = [ip.network for ip in
                                    ip_cmd.list_addresses(port=port)]
                for port_cidr in self._get_port_cidrs(port):
                    self.assertIn(port_cidr, configured_cidrs)


@testtools.skipIf(
    CONF.neutron_plugin_options.firewall_driver in ['openvswitch', 'None'],
    "Firewall driver other than 'openvswitch' is required to use "
    "stateless security groups.")
class StatelessSecGroupDualStackSlaacTest(StatelessSecGroupDualStackBase):
    ipv6_mode = 'slaac'

    @decorators.idempotent_id('e7d64384-ea6a-40aa-b454-854f0990153c')
    def test_default_sec_grp_scenarios(self):
        self._test_default_sec_grp_scenarios()


@testtools.skipIf(
    CONF.neutron_plugin_options.firewall_driver in ['openvswitch', 'None'],
    "Firewall driver other than 'openvswitch' is required to use "
    "stateless security groups.")
class StatelessSecGroupDualStackDHCPv6StatelessTest(
        StatelessSecGroupDualStackBase):
    ipv6_mode = 'dhcpv6-stateless'

    @decorators.idempotent_id('c61c127c-e08f-4ddf-87a3-58b3c86e5476')
    def test_default_sec_grp_scenarios(self):
        self._test_default_sec_grp_scenarios()
