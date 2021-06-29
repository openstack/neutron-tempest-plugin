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

from tempest.common import utils as tempest_utils
from tempest.common import waiters
from tempest.lib.common.utils import data_utils
from tempest.lib.common.utils import test_utils
from tempest.lib import decorators

from neutron_tempest_plugin.common import ssh
from neutron_tempest_plugin.common import utils
from neutron_tempest_plugin import config
from neutron_tempest_plugin.scenario import base
from neutron_tempest_plugin.scenario import constants as const

CONF = config.CONF


class NetworkSecGroupTest(base.BaseTempestTestCase):
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
        super(NetworkSecGroupTest, cls).setup_credentials()
        cls.project_id = cls.os_primary.credentials.tenant_id
        cls.network_client = cls.os_admin.network_client

    @classmethod
    def resource_setup(cls):
        super(NetworkSecGroupTest, cls).resource_setup()
        # setup basic topology for servers we can log into it
        cls.network = cls.create_network()
        cls.subnet = cls.create_subnet(cls.network)
        router = cls.create_router_by_client()
        cls.create_router_interface(router['id'], cls.subnet['id'])
        cls.keypair = cls.create_keypair()

    def setUp(self):
        super(NetworkSecGroupTest, self).setUp()
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        self.network_client.reset_quotas, self.project_id)
        self.network_client.update_quotas(self.project_id, security_group=-1)

    def create_vm_testing_sec_grp(self, num_servers=2, security_groups=None,
                                  ports=None):
        """Create instance for security group testing

        :param num_servers (int): number of servers to spawn
        :param security_groups (list): list of security groups
        :param ports* (list): list of ports
        *Needs to be the same length as num_servers
        """
        servers, fips, server_ssh_clients = ([], [], [])
        for i in range(num_servers):
            server_args = {
                'flavor_ref': CONF.compute.flavor_ref,
                'image_ref': CONF.compute.image_ref,
                'key_name': self.keypair['name'],
                'networks': [{'uuid': self.network['id']}],
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
                network_id=self.network['id'], device_id=server['server'][
                    'id'])['ports'][0]
            fips.append(self.create_floatingip(port=port))
            server_ssh_clients.append(ssh.Client(
                fips[i]['floating_ip_address'], CONF.validation.image_ssh_user,
                pkey=self.keypair['private_key']))
        return server_ssh_clients, fips, servers

    def _test_ip_prefix(self, rule_list, should_succeed):
        # Add specific remote prefix to VMs and check connectivity
        ssh_secgrp_name = data_utils.rand_name('ssh_secgrp')
        icmp_secgrp_name = data_utils.rand_name('icmp_secgrp_with_cidr')
        ssh_secgrp = self.os_primary.network_client.create_security_group(
            name=ssh_secgrp_name)
        self.create_loginable_secgroup_rule(
            secgroup_id=ssh_secgrp['security_group']['id'])
        icmp_secgrp = self.os_primary.network_client.create_security_group(
            name=icmp_secgrp_name)
        self.create_secgroup_rules(
            rule_list, secgroup_id=icmp_secgrp['security_group']['id'])
        for sec_grp in (ssh_secgrp, icmp_secgrp):
            self.security_groups.append(sec_grp['security_group'])
        security_groups_list = [{'name': ssh_secgrp_name},
                                {'name': icmp_secgrp_name}]
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

    @decorators.idempotent_id('3d73ec1a-2ec6-45a9-b0f8-04a283d9d764')
    def test_default_sec_grp_scenarios(self):
        server_ssh_clients, fips, servers = self.create_vm_testing_sec_grp()
        # Check ssh connectivity when you add sec group rule, enabling ssh
        self.create_loginable_secgroup_rule(
            self.os_primary.network_client.list_security_groups()[
                'security_groups'][0]['id']
        )
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

    @decorators.idempotent_id('3d73ec1a-2ec6-45a9-b0f8-04a283d9d864')
    def test_protocol_number_rule(self):
        # protocol number is added instead of str in security rule creation
        name = data_utils.rand_name("test_protocol_number_rule")
        security_group = self.create_security_group(name=name)
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

    @decorators.idempotent_id('3d73ec1a-2ec6-45a9-b0f8-04a283d9d964')
    def test_two_sec_groups(self):
        # add 2 sec groups to VM and test rules of both are working
        ssh_secgrp_name = data_utils.rand_name('ssh_secgrp')
        icmp_secgrp_name = data_utils.rand_name('icmp_secgrp')
        ssh_secgrp = self.os_primary.network_client.create_security_group(
            name=ssh_secgrp_name)
        self.create_loginable_secgroup_rule(
            secgroup_id=ssh_secgrp['security_group']['id'])
        icmp_secgrp = self.os_primary.network_client.create_security_group(
            name=icmp_secgrp_name)
        self.create_pingable_secgroup_rule(
            secgroup_id=icmp_secgrp['security_group']['id'])
        for sec_grp in (ssh_secgrp, icmp_secgrp):
            self.security_groups.append(sec_grp['security_group'])
        security_groups_list = [{'name': ssh_secgrp_name},
                                {'name': icmp_secgrp_name}]
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
            port_id, security_groups=[ssh_secgrp['security_group']['id']])

        # make sure ssh connectivity works
        self.check_connectivity(fips[0]['floating_ip_address'],
                                CONF.validation.image_ssh_user,
                                self.keypair['private_key'])

        # make sure ICMP connectivity doesn't work
        self.ping_ip_address(fips[0]['floating_ip_address'],
                             should_succeed=False)

        # update port with ssh and ICMP security groups
        self.os_primary.network_client.update_port(
            port_id, security_groups=[
                icmp_secgrp['security_group']['id'],
                ssh_secgrp['security_group']['id']])

        # make sure ssh connectivity  works after update
        self.check_connectivity(fips[0]['floating_ip_address'],
                                CONF.validation.image_ssh_user,
                                self.keypair['private_key'])

        # make sure ICMP connectivity works after update
        self.ping_ip_address(fips[0]['floating_ip_address'])

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

    @decorators.idempotent_id('01f0ddca-b049-47eb-befd-82acb502c9ec')
    def test_established_tcp_session_after_re_attachinging_sg(self):
        """Test existing connection remain open after sg has been re-attached

        Verifies that new packets can pass over the existing connection when
        the security group has been removed from the server and then added
        back
        """

        ssh_sg = self.create_security_group()
        self.create_loginable_secgroup_rule(secgroup_id=ssh_sg['id'])
        vm_ssh, fips, vms = self.create_vm_testing_sec_grp(
                security_groups=[{'name': ssh_sg['name']}])
        sg = self.create_security_group()
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

    @decorators.idempotent_id('7ed39b86-006d-40fb-887a-ae46693dabc9')
    def test_remote_group(self):
        # create a new sec group
        ssh_secgrp_name = data_utils.rand_name('ssh_secgrp')
        ssh_secgrp = self.os_primary.network_client.create_security_group(
            name=ssh_secgrp_name)
        # add cleanup
        self.security_groups.append(ssh_secgrp['security_group'])
        # configure sec group to support SSH connectivity
        self.create_loginable_secgroup_rule(
            secgroup_id=ssh_secgrp['security_group']['id'])
        # spawn two instances with the sec group created
        server_ssh_clients, fips, servers = self.create_vm_testing_sec_grp(
            security_groups=[{'name': ssh_secgrp_name}])
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
                      'remote_group_id': ssh_secgrp['security_group']['id']}]
        self.create_secgroup_rules(
            rule_list, secgroup_id=ssh_secgrp['security_group']['id'])
        # verify ICMP connectivity between instances works
        self.check_remote_connectivity(
            server_ssh_clients[0], fips[1]['fixed_ip_address'],
            servers=servers)
        # make sure ICMP connectivity doesn't work from framework
        self.ping_ip_address(fips[0]['floating_ip_address'],
                             should_succeed=False)

    @testtools.skipUnless(
        CONF.neutron_plugin_options.firewall_driver == 'openvswitch',
        "Openvswitch agent is required to run this test")
    @decorators.idempotent_id('678dd4c0-2953-4626-b89c-8e7e4110ec4b')
    @tempest_utils.requires_ext(extension="address-group", service="network")
    @tempest_utils.requires_ext(
        extension="security-groups-remote-address-group", service="network")
    def test_remote_group_and_remote_address_group(self):
        """Test SG rules with remote group and remote address group

        This test checks the ICMP connection among two servers using a security
        group rule with remote group and another rule with remote address
        group. The connection should be granted when at least one of the rules
        is applied. When both rules are applied (overlapped), removing one of
        them should not disable the connection.
        """
        # create a new sec group
        ssh_secgrp_name = data_utils.rand_name('ssh_secgrp')
        ssh_secgrp = self.os_primary.network_client.create_security_group(
            name=ssh_secgrp_name)
        # add cleanup
        self.security_groups.append(ssh_secgrp['security_group'])
        # configure sec group to support SSH connectivity
        self.create_loginable_secgroup_rule(
            secgroup_id=ssh_secgrp['security_group']['id'])
        # spawn two instances with the sec group created
        server_ssh_clients, fips, servers = self.create_vm_testing_sec_grp(
            security_groups=[{'name': ssh_secgrp_name}])
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
                      'remote_group_id': ssh_secgrp['security_group']['id']}]
        remote_sg_rid = self.create_secgroup_rules(
            rule_list, secgroup_id=ssh_secgrp['security_group']['id'])[0]['id']
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
            rule_list, secgroup_id=ssh_secgrp['security_group']['id'])[0]['id']
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

    @decorators.idempotent_id('f07d0159-8f9e-4faa-87f5-a869ab0ad488')
    def test_multiple_ports_secgroup_inheritance(self):
        """Test multiple port security group inheritance

        This test creates two ports with security groups, then
        boots two instances and verify that the security group was
        inherited properly and enforced in these instances.
        """
        # create a security group and make it loginable and pingable
        secgrp = self.os_primary.network_client.create_security_group(
            name=data_utils.rand_name('secgrp'))
        self.create_loginable_secgroup_rule(
            secgroup_id=secgrp['security_group']['id'])
        self.create_pingable_secgroup_rule(
            secgroup_id=secgrp['security_group']['id'])
        # add security group to cleanup
        self.security_groups.append(secgrp['security_group'])
        # create two ports with fixed IPs and the security group created
        ports = []
        for i in range(2):
            ports.append(self.create_port(
                self.network, fixed_ips=[{'subnet_id': self.subnets[0]['id']}],
                security_groups=[secgrp['security_group']['id']]))
        # spawn instances with the ports created
        server_ssh_clients, fips, servers = self.create_vm_testing_sec_grp(
            ports=ports)
        # verify ICMP reachability and ssh connectivity
        for fip in fips:
            self.ping_ip_address(fip['floating_ip_address'])
            self.check_connectivity(fip['floating_ip_address'],
                                    CONF.validation.image_ssh_user,
                                    self.keypair['private_key'])

    @decorators.idempotent_id('f07d0159-8f9e-4faa-87f5-a869ab0ad489')
    def test_multiple_ports_portrange_remote(self):
        ssh_clients, fips, servers = self.create_vm_testing_sec_grp(
            num_servers=3)
        secgroups = []
        ports = []

        # Create remote and test security groups
        for i in range(0, 2):
            secgroups.append(
                self.create_security_group(name='secgrp-%d' % i))
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
            self._verify_http_connection(
                ssh_clients[0],
                ssh_clients[2],
                test_ip, port,
                servers,
                should_pass=False)

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
        self.create_secgroup_rules(
            rule_list, secgroup_id=secgroups[1]['id'])

        # verify that conections are working
        for port in range(80, 84):
            self._verify_http_connection(
                ssh_clients[0],
                ssh_clients[2],
                test_ip, port,
                servers)

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
        secgrp_name = data_utils.rand_name('secgrp')
        secgrp = self.os_primary.network_client.create_security_group(
            name=secgrp_name)
        secgrp_id = secgrp['security_group']['id']
        # add security group to cleanup
        self.security_groups.append(secgrp['security_group'])

        # remove all rules and add ICMP, DHCP and metadata as egress,
        # and ssh as ingress.
        for sgr in secgrp['security_group']['security_group_rules']:
            self.client.delete_security_group_rule(sgr['id'])

        self.create_loginable_secgroup_rule(secgroup_id=secgrp_id)
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
        self.create_secgroup_rules(rule_list, secgroup_id=secgrp_id)

        # go vms, go!
        ssh_clients, fips, servers = self.create_vm_testing_sec_grp(
            num_servers=2, security_groups=[{'name': secgrp_name}])

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
                      'remote_group_id': secgrp_id}]
        self.create_secgroup_rules(rule_list, secgroup_id=secgrp_id)

        # try to ping instances with intra SG permission
        self.check_remote_connectivity(
            ssh_clients[0], fips[1]['fixed_ip_address'])
        self.check_remote_connectivity(
            ssh_clients[1], fips[0]['fixed_ip_address'])

    @decorators.idempotent_id('cd66b826-d86c-4fb4-ab37-17c8391753cb')
    def test_overlapping_sec_grp_rules(self):
        """Test security group rules with overlapping port ranges"""
        client_ssh, _, vms = self.create_vm_testing_sec_grp(num_servers=2)
        tmp_ssh, _, tmp_vm = self.create_vm_testing_sec_grp(num_servers=1)
        srv_ssh = tmp_ssh[0]
        srv_vm = tmp_vm[0]
        srv_port = self.client.list_ports(network_id=self.network['id'],
                device_id=srv_vm['server']['id'])['ports'][0]
        srv_ip = srv_port['fixed_ips'][0]['ip_address']
        secgrps = []
        for i, vm in enumerate(vms):
            sg = self.create_security_group(name='secgrp-%d' % i)
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
        # The conntrack entries are ruled by the OF definitions but conntrack
        # status can change the datapath. Let's check the rules in two
        # attempts
        for _ in range(2):
            self._verify_http_connection(client_ssh[0], srv_ssh, srv_ip,
                                         tcp_port, [])
            for port in range(tcp_port, tcp_port + 3):
                self._verify_http_connection(client_ssh[1], srv_ssh, srv_ip,
                                             port, [])
