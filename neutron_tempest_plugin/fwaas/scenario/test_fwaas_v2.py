# Copyright (c) 2016 Juniper Networks
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


from oslo_log import log as logging
from tempest import config
from tempest.lib.common.utils import data_utils
from tempest.lib import decorators

from neutron_tempest_plugin.common import ssh
from neutron_tempest_plugin.fwaas.scenario import fwaas_v2_base as base


CONF = config.CONF
LOG = logging.getLogger(__name__)


class TestFWaaS_v2(base.FWaaSScenarioTest_V2):

    """Config Requirement in tempest.conf:

    - project_network_cidr_bits- specifies the subnet range for each network
    - project_network_cidr
    - public_network_id
    """

    required_network_extensions = ['fwaas_v2', 'security-group', 'router']

    def setUp(self):
        LOG.debug("Initializing FWaaSScenarioTest Setup")
        super().setUp()
        LOG.debug("FWaaSScenarioTest Setup done.")

    def _check_connectivity_between_internal_networks(
            self, floating_ip1, keys1, network2, server2, should_connect=True):
        internal_ips = (p['fixed_ips'][0]['ip_address'] for p in
                        self.os_admin.ports_client.list_ports(
                            project_id=server2['project_id'],
                            network_id=network2['id'])['ports']
                        if p['device_owner'].startswith('network'))
        self._check_server_connectivity(
            floating_ip1, keys1, internal_ips, should_connect,
            servers=[server2])

    def _create_test_server(self, network):
        pub_network_id = CONF.network.public_network_id
        server, keys, port = self._create_server(network)
        private_key = keys['private_key']
        server_floating_ip = self.create_floatingip(
            external_network_id=pub_network_id, port=port)
        fixed_ip = port['fixed_ips'][0]['ip_address']
        return server, private_key, fixed_ip, server_floating_ip

    def _create_topology(self):
        """Topology diagram:

        +--------+             +-------------+
        |"server"|             | "subnet"    |
        |   VM-1 +-------------+ "network-1" |
        +--------+             +----+--------+
                                    |
                                    | router interface port
                               +----+-----+
                               | "router" |
                               +----+-----+
                                    | router interface port
                                    |
                                    |
        +--------+             +-------------+
        |"server"|             | "subnet"    |
        |   VM-2 +-------------+ "network-2" |
        +--------+             +----+--------+
        """

        LOG.debug('Starting Topology Creation')
        resp = {}
        # Create Network1 and Subnet1.
        network1, subnet1 = self._create_network_subnet(
            port_security_enabled=False)
        resp['network1'] = network1
        resp['subnet1'] = subnet1

        # Create Network2 and Subnet2.
        network2, subnet2 = self._create_network_subnet(
            port_security_enabled=False)
        resp['network2'] = network2
        resp['subnet2'] = subnet2

        # Create a router and attach Network1, Network2 and External Networks
        # to it.
        pub_network_id = CONF.network.public_network_id
        router = self.create_router(
            router_name=data_utils.rand_name('SCENARIO-TEST-ROUTER'),
            admin_state_up=True,
            external_network_id=pub_network_id)
        router_id = router['id']
        resp_add_intf = self.create_router_interface(
            router_id, subnet_id=subnet1['id'])
        router_portid_1 = resp_add_intf['port_id']
        resp_add_intf = self.create_router_interface(
            router_id, subnet_id=subnet2['id'])
        router_portid_2 = resp_add_intf['port_id']
        resp['router'] = router
        resp['router_portid_1'] = router_portid_1
        resp['router_portid_2'] = router_portid_2

        # Create a VM on each network and assign it a floating IP. Port
        # security is disabled because this test exercises L3 FWaaS rules on
        # the router interfaces, not security-group enforcement on VM ports.
        server1, private_key1, server_fixed_ip_1, server_floating_ip_1 = (
            self._create_test_server(network1))
        server2, private_key2, server_fixed_ip_2, server_floating_ip_2 = (
            self._create_test_server(network2))
        resp['server1'] = server1
        resp['private_key1'] = private_key1
        resp['server_fixed_ip_1'] = server_fixed_ip_1
        resp['server_floating_ip_1'] = server_floating_ip_1
        resp['server2'] = server2
        resp['private_key2'] = private_key2
        resp['server_fixed_ip_2'] = server_fixed_ip_2
        resp['server_floating_ip_2'] = server_floating_ip_2

        return resp

    @decorators.idempotent_id('77fdf3ea-82c1-453d-bfec-f7efe335625d')
    def test_icmp_reachability_scenarios(self):
        topology = self._create_topology()
        ssh_login = CONF.validation.image_ssh_user

        # TODO(slaweq): Revisit whether host-originated ICMP checks are
        # needed in addition to the SSH and east-west connectivity checks.
        self.ping_ip_address(
            topology['server_floating_ip_1']['floating_ip_address'])
        self.check_connectivity(
            host=topology['server_floating_ip_1']['floating_ip_address'],
            ssh_user=ssh_login,
            ssh_key=topology['private_key1'],
            servers=[topology['server1']])
        self.ping_ip_address(
            topology['server_floating_ip_2']['floating_ip_address'])
        self.check_connectivity(
            host=topology['server_floating_ip_2']['floating_ip_address'],
            ssh_user=ssh_login,
            ssh_key=topology['private_key2'],
            servers=[topology['server2']])

        # Scenario 1: Add allow ICMP rules between the two VMs.
        fw_allow_icmp_rule = self.create_firewall_rule(action="allow",
                                                       protocol="icmp")
        fw_allow_ssh_rule = self.create_firewall_rule(action="allow",
                                                      protocol="tcp",
                                                      destination_port=22)
        fw_rules = [fw_allow_icmp_rule['id'], fw_allow_ssh_rule['id']]
        if CONF.fwaas.driver == 'ovn':
            # OVN FWaaS uses stateless ACLs, so allow SSH replies explicitly.
            fw_allow_ssh_reply_rule = self.create_firewall_rule(
                action="allow", protocol="tcp", source_port=22)
            fw_rules.append(fw_allow_ssh_reply_rule['id'])
        fw_policy = self.create_firewall_policy(firewall_rules=fw_rules)
        fw_group = self.create_firewall_group(
            ports=[
                topology['router_portid_1'],
                topology['router_portid_2']],
            ingress_firewall_policy_id=fw_policy['id'],
            egress_firewall_policy_id=fw_policy['id'])
        self.addCleanup(self.update_firewall_group_and_wait, fw_group['id'],
                        ports=[])
        self._wait_firewall_group_active(fw_group['id'])
        LOG.debug('fw_allow_icmp_rule: %s\nfw_allow_ssh_rule: %s\n'
                  'fw_policy: %s\nfw_group: %s\n',
                  fw_allow_icmp_rule, fw_allow_ssh_rule, fw_policy, fw_group)

        # Check the connectivity between VM1 and VM2. It should Pass.
        self._check_server_connectivity(
            topology['server_floating_ip_1'],
            topology['private_key1'],
            address_list=[topology['server_fixed_ip_2']],
            should_connect=True,
            servers=[topology['server1'], topology['server2']])

        # Scenario 2: Now remove the allow_icmp rule add a deny_icmp rule and
        # check that ICMP gets blocked
        fw_deny_icmp_rule = self.create_firewall_rule(action="deny",
                                                      protocol="icmp")
        self.remove_firewall_rule_from_policy_and_wait(
            firewall_group_id=fw_group['id'],
            firewall_rule_id=fw_allow_icmp_rule['id'],
            firewall_policy_id=fw_policy['id'])
        self.insert_firewall_rule_in_policy_and_wait(
            firewall_group_id=fw_group['id'],
            firewall_rule_id=fw_deny_icmp_rule['id'],
            firewall_policy_id=fw_policy['id'])
        self._check_server_connectivity(
            topology['server_floating_ip_1'],
            topology['private_key1'],
            address_list=[topology['server_fixed_ip_2']],
            should_connect=False,
            servers=[topology['server1'], topology['server2']])

        # Scenario 3: Create a rule allowing ICMP only from server_fixed_ip_1
        # to server_fixed_ip_2 and check that traffic from opposite direction
        # is blocked (for ovs driver where rules are stateful).
        fw_allow_unidirectional_icmp_rule = self.create_firewall_rule(
            action="allow", protocol="icmp",
            source_ip_address=topology['server_fixed_ip_1'],
            destination_ip_address=topology['server_fixed_ip_2'])
        self.remove_firewall_rule_from_policy_and_wait(
            firewall_group_id=fw_group['id'],
            firewall_rule_id=fw_deny_icmp_rule['id'],
            firewall_policy_id=fw_policy['id'])
        self.insert_firewall_rule_in_policy_and_wait(
            firewall_group_id=fw_group['id'],
            firewall_rule_id=fw_allow_unidirectional_icmp_rule['id'],
            firewall_policy_id=fw_policy['id'])

        if CONF.fwaas.driver == 'ovn':
            # NOTE(slaweq): OVN driver in FWaaS implements only stateless rules
            # so allowing only unidirectional traffic is not enough as ICMP
            # replies are still blocked and to make it working additional rule
            # for the opposite direction is required also:
            fw_allow_icmp_reply_rule = self.create_firewall_rule(
                action="allow", protocol="icmp",
                source_ip_address=topology['server_fixed_ip_2'],
                destination_ip_address=topology['server_fixed_ip_1'])
            self.insert_firewall_rule_in_policy_and_wait(
                firewall_group_id=fw_group['id'],
                firewall_rule_id=fw_allow_icmp_reply_rule['id'],
                firewall_policy_id=fw_policy['id'])

        self._check_server_connectivity(
            topology['server_floating_ip_1'],
            topology['private_key1'],
            address_list=[topology['server_fixed_ip_2']],
            should_connect=True,
            servers=[topology['server1'], topology['server2']])
        self._check_server_connectivity(
            topology['server_floating_ip_2'],
            topology['private_key2'],
            address_list=[topology['server_fixed_ip_1']],
            should_connect=CONF.fwaas.driver == 'ovn',
            servers=[topology['server1'], topology['server2']])

        # Disassociate ports of this firewall group for cleanup resources
        self.update_firewall_group_and_wait(fw_group['id'], ports=[])

    def _create_fip_topology(self):
        """Create topology: network, subnet, router, VM with FIP.

        VM is created without security group (network has
        port_security_enabled=False).

        +--------+             +-------------+
        |"server"|             | "subnet"    |
        |   VM   +-------------+ "network"   |
        +--------+             +----+--------+
                                    |
                                    | router interface port
                               +----+-----+
                               | "router"|
                               +----+-----+
                                    |
                                    | external gateway
                                    |
                               [external network]
        """
        # No security group: network has port_security_enabled=False
        network, subnet = self._create_network_subnet(
            prefix='fwaas-ssh-fip-',
            port_security_enabled=False)
        pub_network_id = CONF.network.public_network_id
        router = self.create_router(
            router_name=data_utils.rand_name('fwaas-ssh-fip-router'),
            admin_state_up=True,
            external_network_id=pub_network_id)
        resp = self.create_router_interface(
            router['id'], subnet_id=subnet['id'])
        router_port_id = resp['port_id']
        server, keys, port = self._create_server(network)
        floating_ip = self.create_floatingip(
            external_network_id=pub_network_id, port=port)

        return {
            'server': server,
            'private_key': keys['private_key'],
            'floating_ip': floating_ip,
            'router_port_id': router_port_id,
        }

    @decorators.idempotent_id('a8c2e1f4-9b3d-4f5a-8e6c-7d9f2b1a0c3e')
    def test_ssh_via_fip_with_fwaas_rules(self):
        """Test SSH access to VM with FIP controlled by FWaaS rules.

        Verifies that:
        1. FWaaS is enabled (skipped in setUp if not)
        2. Baseline: VM reachable before firewall (SSH works)
        3. Firewall group with empty policy denies all traffic (SSH blocked)
        4. Adding allow SSH rules to ingress and egress policy permits SSH
        """
        topology = self._create_fip_topology()
        fip_address = topology['floating_ip']['floating_ip_address']
        ssh_login = CONF.validation.image_ssh_user
        private_key = topology['private_key']

        # Baseline: Ensure VM is reachable before applying firewall
        # TODO(slaweq): Revisit whether host-originated ICMP is needed here.
        self.ping_ip_address(fip_address)
        self.check_connectivity(
            host=fip_address,
            ssh_user=ssh_login,
            ssh_key=private_key,
            servers=[topology['server']])

        # Phase 1: Attach firewall group with empty policy - SSH blocked
        fw_policy = self.create_firewall_policy()
        fw_group = self.create_firewall_group(
            ports=[topology['router_port_id']],
            ingress_firewall_policy_id=fw_policy['id'],
            egress_firewall_policy_id=fw_policy['id'])
        self.addCleanup(self.update_firewall_group_and_wait, fw_group['id'],
                        ports=[])
        self._wait_firewall_group_active(fw_group['id'])
        LOG.debug('Firewall group with empty policy attached to router port')

        self.check_ssh_connectivity(
            ip_address=fip_address,
            username=ssh_login,
            private_key=private_key,
            should_connect=False)

        # Phase 2: Add allow SSH rules - ingress dport 22, egress sport 22
        fw_allow_ssh_rule = self.create_firewall_rule(
            action="allow", protocol="tcp", destination_port=22)
        fw_allow_egress_ssh_rule = self.create_firewall_rule(
            action="allow", protocol="tcp", source_port=22)
        self.insert_firewall_rule_in_policy_and_wait(
            firewall_group_id=fw_group['id'],
            firewall_rule_id=fw_allow_ssh_rule['id'],
            firewall_policy_id=fw_policy['id'])
        self.insert_firewall_rule_in_policy_and_wait(
            firewall_group_id=fw_group['id'],
            firewall_rule_id=fw_allow_egress_ssh_rule['id'],
            firewall_policy_id=fw_policy['id'])
        LOG.debug('Added allow SSH rules to ingress and egress policy')

        self.check_connectivity(
            host=fip_address,
            ssh_user=ssh_login,
            ssh_key=private_key,
            servers=[topology['server']])


class TestFWaaS_v2_L2(base.FWaaSScenarioTest_V2):
    """L2 FWaaS scenario tests for VM port connectivity.

    Firewall groups are attached directly to compute ports. VMs use the
    project default security group so port security stays enabled and L2
    FWaaS rules are applied by the OVS driver.
    """

    def setUp(self):
        if CONF.fwaas.driver == 'ovn':
            raise self.skipException(
                "FWaaS OVN driver does not support L2 ports.")
        super().setUp()

    def _create_l2_topology(self):
        """Create two VMs on the same network with one floating IP.

        +--------+             +-------------+
        | VM-1   |             |  subnet     |
        | (+FIP) +-------------+  network    |
        +--------+             +------+------+
                                    |
        +--------+                  |
        | VM-2   +------------------+
        | (fixed)|
        +--------+
               router (external gateway for FIP on VM-1)
        """
        network, subnet = self._create_network_subnet(
            prefix='fwaas-l2-',
            port_security_enabled=True)
        self._create_router_with_external_gateway(
            'fwaas-l2-router', subnet_id=subnet['id'])

        pub_network_id = CONF.network.public_network_id
        server1, keys1, port1 = self._create_server(network)
        server2, _, port2 = self._create_server(network)
        server1_floating_ip = self.create_floatingip(
            external_network_id=pub_network_id, port=port1)
        server1_fixed_ip = port1['fixed_ips'][0]['ip_address']
        server2_fixed_ip = port2['fixed_ips'][0]['ip_address']
        server1_port_id = port1['id']
        server2_port_id = port2['id']

        return {
            'network': network,
            'subnet': subnet,
            'server1': server1,
            'server2': server2,
            'server1_private_key': keys1['private_key'],
            'server1_floating_ip': server1_floating_ip,
            'server1_fixed_ip': server1_fixed_ip,
            'server2_fixed_ip': server2_fixed_ip,
            'server1_port_id': server1_port_id,
            'server2_port_id': server2_port_id,
        }

    @decorators.idempotent_id('c4f8a2b1-6d3e-4a7f-9b0c-1e2d3f4a5b6c')
    def test_vm_connectivity_with_fwaas_l2(self):
        """Verify east-west connectivity between VMs using L2 FWaaS rules.

        VM-1 uses a dedicated firewall group with allow SSH/ICMP so FIP access
        works while L2 FWaaS rules are enforced. VM-2 is moved to a dedicated
        L2 firewall group with a deny-ICMP rule until allow-ICMP is added.
        """
        topology = self._create_l2_topology()
        ssh_login = CONF.validation.image_ssh_user
        fip_address = topology['server1_floating_ip']['floating_ip_address']

        self._dissociate_ports_from_default_firewall_group(
            [topology['server1_port_id'], topology['server2_port_id']])

        (_, _, _, fw_ingress_policy,
         fw_egress_policy) = self._create_fip_access_policies()

        self.create_firewall_group_and_wait(
            ports=[topology['server1_port_id']],
            ingress_firewall_policy_id=fw_ingress_policy['id'],
            egress_firewall_policy_id=fw_egress_policy['id'])

        self.check_connectivity(
            host=fip_address,
            ssh_user=ssh_login,
            ssh_key=topology['server1_private_key'],
            servers=[topology['server1']])

        ssh_source = ssh.Client(
            fip_address,
            ssh_login,
            pkey=topology['server1_private_key'])

        fw_deny_icmp_rule = self.create_firewall_rule(action="deny",
                                                      protocol="icmp")
        fw_policy = self.create_firewall_policy(
            firewall_rules=[fw_deny_icmp_rule['id']])
        fw_group = self.create_firewall_group_and_wait(
            ports=[topology['server2_port_id']],
            ingress_firewall_policy_id=fw_policy['id'],
            egress_firewall_policy_id=fw_policy['id'])

        self._check_server_connectivity(
            topology['server1_floating_ip'],
            topology['server1_private_key'],
            address_list=[topology['server2_fixed_ip']],
            should_connect=False,
            ssh_source=ssh_source)

        fw_allow_icmp_rule = self.create_firewall_rule(action="allow",
                                                       protocol="icmp")
        self.insert_firewall_rule_in_policy_and_wait(
            firewall_group_id=fw_group['id'],
            firewall_rule_id=fw_allow_icmp_rule['id'],
            firewall_policy_id=fw_policy['id'],
            insert_before=fw_deny_icmp_rule['id'])

        self._check_server_connectivity(
            topology['server1_floating_ip'],
            topology['server1_private_key'],
            address_list=[topology['server2_fixed_ip']],
            should_connect=True,
            ssh_source=ssh_source)
