# Copyright 2018 Red Hat, Inc.
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
from tempest.common import compute
from tempest.common import utils
from tempest.lib.common.utils import data_utils
from tempest.lib import decorators

from neutron_tempest_plugin.common import ip as ip_utils
from neutron_tempest_plugin.common import ssh
from neutron_tempest_plugin import config
from neutron_tempest_plugin.scenario import base

CONF = config.CONF


class NetworkConnectivityTest(base.BaseTempestTestCase):
    credentials = ['primary', 'admin']

    @classmethod
    @utils.requires_ext(extension="router", service="network")
    def resource_setup(cls):
        super(NetworkConnectivityTest, cls).resource_setup()
        # Create keypair with admin privileges
        cls.keypair = cls.create_keypair()
        # Create security group with admin privileges
        cls.secgroup = cls.create_security_group(
            name=data_utils.rand_name('secgroup'))
        # Execute funcs to achieve ssh and ICMP capabilities
        cls.create_loginable_secgroup_rule(secgroup_id=cls.secgroup['id'])
        cls.create_pingable_secgroup_rule(secgroup_id=cls.secgroup['id'])

    def _create_servers(self, port_1, port_2):
        params = {
            'flavor_ref': CONF.compute.flavor_ref,
            'image_ref': CONF.compute.image_ref,
            'key_name': self.keypair['name']
        }
        vms = []
        vms.append(
            self.create_server(networks=[{'port': port_1['id']}], **params))

        if (CONF.compute.min_compute_nodes > 1 and
                compute.is_scheduler_filter_enabled("DifferentHostFilter")):
            params['scheduler_hints'] = {
                'different_host': [vms[0]['server']['id']]}

        vms.append(
            self.create_server(networks=[{'port': port_2['id']}], **params))

        for vm in vms:
            self.wait_for_server_active(vm['server'])

        return vms

    @decorators.idempotent_id('8944b90d-1766-4669-bd8a-672b5d106bb7')
    def test_connectivity_through_2_routers(self):
        ap1_net = self.create_network()
        ap2_net = self.create_network()
        wan_net = self.create_network()
        ap1_subnet = self.create_subnet(
            ap1_net, cidr="10.10.210.0/24", gateway="10.10.210.254")
        ap2_subnet = self.create_subnet(
            ap2_net, cidr="10.10.220.0/24", gateway="10.10.220.254")
        self.create_subnet(
            wan_net, cidr="10.10.200.0/24", gateway="10.10.200.254")

        ap1_rt = self.create_router(
            router_name=data_utils.rand_name("ap1_rt"),
            admin_state_up=True,
            external_network_id=CONF.network.public_network_id)
        ap2_rt = self.create_router(
            router_name=data_utils.rand_name("ap2_rt"),
            admin_state_up=True)

        ap1_internal_port = self.create_port(
            ap1_net, security_groups=[self.secgroup['id']])
        ap2_internal_port = self.create_port(
            ap2_net, security_groups=[self.secgroup['id']])
        ap1_wan_port = self.create_port(wan_net)
        ap2_wan_port = self.create_port(wan_net)

        self.client.add_router_interface_with_port_id(
            ap1_rt['id'], ap1_wan_port['id'])
        self.client.add_router_interface_with_port_id(
            ap2_rt['id'], ap2_wan_port['id'])
        self.create_router_interface(ap1_rt['id'], ap1_subnet['id'])
        self.create_router_interface(ap2_rt['id'], ap2_subnet['id'])

        self.client.update_router(
            ap1_rt['id'],
            routes=[{"destination": ap2_subnet['cidr'],
                     "nexthop": ap2_wan_port['fixed_ips'][0]['ip_address']}])
        self.client.update_router(
            ap2_rt['id'],
            routes=[{"destination": ap1_subnet['cidr'],
                     "nexthop": ap1_wan_port['fixed_ips'][0]['ip_address']}])

        servers = self._create_servers(ap1_internal_port, ap2_internal_port)

        ap1_fip = self.create_and_associate_floatingip(
            ap1_internal_port['id'])
        ap1_sshclient = ssh.Client(
            ap1_fip['floating_ip_address'], CONF.validation.image_ssh_user,
            pkey=self.keypair['private_key'])

        self.check_remote_connectivity(
            ap1_sshclient, ap2_internal_port['fixed_ips'][0]['ip_address'],
            servers=servers)

    @decorators.idempotent_id('b72c3b77-3396-4144-b05d-9cd3c0099893')
    def test_connectivity_router_east_west_traffic(self):
        """This case is intended to test router east west taffic

        The case can be used in various scenarios: legacy/distributed router,
        same/different host.
        """
        net_1 = self.create_network()
        net_2 = self.create_network()
        subnet_1 = self.create_subnet(net_1, cidr="10.10.1.0/24")
        subnet_2 = self.create_subnet(net_2, cidr="10.10.2.0/24")

        router = self.create_router(
            router_name=data_utils.rand_name("east_west_traffic_router"),
            admin_state_up=True,
            external_network_id=CONF.network.public_network_id)

        internal_port_1 = self.create_port(
            net_1, security_groups=[self.secgroup['id']])
        internal_port_2 = self.create_port(
            net_2, security_groups=[self.secgroup['id']])

        self.create_router_interface(router['id'], subnet_1['id'])
        self.create_router_interface(router['id'], subnet_2['id'])

        servers = self._create_servers(internal_port_1, internal_port_2)

        fip = self.create_and_associate_floatingip(
            internal_port_1['id'])
        sshclient = ssh.Client(
            fip['floating_ip_address'], CONF.validation.image_ssh_user,
            pkey=self.keypair['private_key'])

        self.check_remote_connectivity(
            sshclient, internal_port_2['fixed_ips'][0]['ip_address'],
            ping_count=10, servers=servers)

    @utils.requires_ext(extension="dvr", service="network")
    @decorators.idempotent_id('69d3650a-5c32-40bc-ae56-5c4c849ddd37')
    def test_connectivity_dvr_and_no_dvr_routers_in_same_subnet(self):
        """This test case tests connectivity between vm and 2 routers.

        Subnet is connected to dvr and non-dvr routers in the same time, test
        ensures that connectivity from VM to both routers is working.

        Test scenario: (NOTE: 10.1.0.0/24 private CIDR is used as an example)
        +----------------+                  +------------+
        | Non-dvr router |                  | DVR router |
        |                |                  |            |
        |    10.1.0.1    |                  |  10.1.0.x  |
        +-------+--------+                  +-----+------+
                |                                 |
                |         10.1.0.0/24             |
                +----------------+----------------+
                                 |
                               +-+-+
                               |VM |
                               +---+

        where:
        10.1.0.1 - is subnet's gateway IP address,
        10.1.0.x - is any other IP address taken from subnet's range

        Test ensures that both 10.1.0.1 and 10.1.0.x IP addresses are
        reachable from VM.
        """
        ext_network = self.client.show_network(self.external_network_id)
        for ext_subnetid in ext_network['network']['subnets']:
            ext_subnet = self.os_admin.network_client.show_subnet(ext_subnetid)
            ext_cidr = ext_subnet['subnet']['cidr']
            if ext_subnet['subnet']['ip_version'] == constants.IP_VERSION_4:
                break
        else:
            self.fail('No IPv4 subnet was found in external network %s' %
                      ext_network['network']['id'])

        subnet_cidr = ip_utils.find_valid_cidr(used_cidr=ext_cidr)
        gw_ip = netaddr.IPAddress(subnet_cidr.first + 1)

        network = self.create_network()
        subnet = self.create_subnet(
            network, cidr=str(subnet_cidr), gateway=str(gw_ip))

        non_dvr_router = self.create_router_by_client(
            tenant_id=self.client.tenant_id,
            is_admin=True,
            router_name=data_utils.rand_name("nondvr-2-routers-same-network"),
            admin_state_up=True,
            distributed=False)
        self.create_router_interface(non_dvr_router['id'], subnet['id'])

        dvr_router = self.create_router_by_client(
            tenant_id=self.client.tenant_id,
            is_admin=True,
            router_name=data_utils.rand_name("dvr-2-rotuers-same-network"),
            admin_state_up=True,
            distributed=True)
        dvr_router_port = self.create_port(network)
        self.client.add_router_interface_with_port_id(
            dvr_router['id'], dvr_router_port['id'])

        vm = self.create_server(
            flavor_ref=CONF.compute.flavor_ref,
            image_ref=CONF.compute.image_ref,
            key_name=self.keypair['name'],
            networks=[{'uuid': network['id']}],
            security_groups=[{'name': self.secgroup['name']}])
        self.wait_for_server_active(vm['server'])

        vm_port = self.client.list_ports(
            network_id=network['id'], device_id=vm['server']['id'])['ports'][0]
        fip = self.create_and_associate_floatingip(vm_port['id'])

        sshclient = ssh.Client(
            fip['floating_ip_address'], CONF.validation.image_ssh_user,
            pkey=self.keypair['private_key'])

        self.check_remote_connectivity(
            sshclient, str(gw_ip), ping_count=10, servers=[vm])
        self.check_remote_connectivity(
            sshclient, dvr_router_port['fixed_ips'][0]['ip_address'],
            ping_count=10, servers=[vm])
