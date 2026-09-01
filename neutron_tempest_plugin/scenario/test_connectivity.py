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
        super().resource_setup()
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
            self.wait_for_guest_os_ready(vm['server'])

        return vms

    def _create_two_router_topology(self, inner_cidr_base,
                                    outer_cidr_base, transit_cidr_base):
        outer_net = self.create_network()
        inner_net = self.create_network()
        transit_net = self.create_network()
        outer_cidr = f"{outer_cidr_base}.0/24"
        inner_cidr = f"{inner_cidr_base}.0/24"
        transit_cidr = f"{transit_cidr_base}.0/24"
        outer_subnet = self.create_subnet(
            outer_net, cidr=outer_cidr,
            gateway=f"{outer_cidr_base}.254")
        inner_subnet = self.create_subnet(
            inner_net, cidr=inner_cidr,
            gateway=f"{inner_cidr_base}.254")
        self.create_subnet(
            transit_net, cidr=transit_cidr,
            gateway=f"{transit_cidr_base}.254")

        outer_router = self.create_router(
            router_name=data_utils.rand_name("outer-router"),
            admin_state_up=True,
            external_network_id=CONF.network.public_network_id)
        inner_router = self.create_router(
            router_name=data_utils.rand_name("inner-router"),
            admin_state_up=True)
        self._wait_for_router_ha_active(outer_router['id'])
        self._wait_for_router_ha_active(inner_router['id'])

        outer_port = self.create_port(
            outer_net, security_groups=[self.secgroup['id']])
        inner_port = self.create_port(
            inner_net, security_groups=[self.secgroup['id']])
        outer_transit_port = self.create_port(transit_net)
        inner_transit_port = self.create_port(transit_net)

        self.client.add_router_interface_with_port_id(
            outer_router['id'], outer_transit_port['id'])
        self.client.add_router_interface_with_port_id(
            inner_router['id'], inner_transit_port['id'])
        self.create_router_interface(outer_router['id'], outer_subnet['id'])
        self.create_router_interface(inner_router['id'], inner_subnet['id'])

        return {
            'outer_port': outer_port,
            'inner_port': inner_port,
            'outer_router': outer_router,
            'inner_router': inner_router,
            'outer_subnet': outer_subnet,
            'inner_subnet': inner_subnet,
            'outer_transit_port': outer_transit_port,
            'inner_transit_port': inner_transit_port,
        }

    @decorators.idempotent_id('8944b90d-1766-4669-bd8a-672b5d106bb7')
    def test_connectivity_through_2_routers(self):
        topology = self._create_two_router_topology(
            inner_cidr_base="10.10.220", outer_cidr_base="10.10.210",
            transit_cidr_base="10.10.200")
        ap1_rt = topology['outer_router']
        ap2_rt = topology['inner_router']
        ap1_subnet = topology['outer_subnet']
        ap2_subnet = topology['inner_subnet']
        ap1_wan_port = topology['outer_transit_port']
        ap2_wan_port = topology['inner_transit_port']
        ap1_internal_port = topology['outer_port']
        ap2_internal_port = topology['inner_port']

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

    @utils.requires_ext(extension="floating-ip-router-writable",
                        service="network")
    @decorators.idempotent_id('f0b97c49-9cc0-4241-93c3-e1f86ca7a8a3')
    def test_connectivity_to_indirect_floatingip(self):
        """Validate a FIP hosted on the outer router reaches an inner VM."""
        topology = self._create_two_router_topology(
            inner_cidr_base="10.10.250", outer_cidr_base="10.10.240",
            transit_cidr_base="10.10.230")
        outer_router = topology['outer_router']
        inner_router = topology['inner_router']
        outer_transit_port = topology['outer_transit_port']
        inner_transit_port = topology['inner_transit_port']

        self.client.update_router(
            outer_router['id'],
            routes=[{"destination": topology['inner_subnet']['cidr'],
                     "nexthop":
                     inner_transit_port['fixed_ips'][0]['ip_address']}])
        self.client.update_router(
            inner_router['id'],
            routes=[{"destination": "0.0.0.0/0",
                     "nexthop":
                     outer_transit_port['fixed_ips'][0]['ip_address']}])

        server = self.create_server(
            flavor_ref=CONF.compute.flavor_ref,
            image_ref=CONF.compute.image_ref,
            key_name=self.keypair['name'],
            networks=[{'port': topology['inner_port']['id']}])
        self.wait_for_server_active(server['server'])
        self.wait_for_guest_os_ready(server['server'])

        floatingip = self.client.create_floatingip(
            floating_network_id=CONF.network.public_network_id,
            port_id=topology['inner_port']['id'],
            router_id=outer_router['id'])['floatingip']
        self.addCleanup(self.client.delete_floatingip, floatingip['id'])
        sshclient = ssh.Client(
            floatingip['floating_ip_address'],
            CONF.validation.image_ssh_user,
            pkey=self.keypair['private_key'])

        self.check_remote_connectivity(
            sshclient, topology['inner_port']['fixed_ips'][0]['ip_address'],
            servers=[server])

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
        self._wait_for_router_ha_active(router['id'])

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

        .. code-block:: HTML

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
            project_id=self.client.project_id,
            is_admin=True,
            router_name=data_utils.rand_name("nondvr-2-routers-same-network"),
            admin_state_up=True,
            distributed=False)
        self.create_router_interface(non_dvr_router['id'], subnet['id'])

        dvr_router = self.create_router_by_client(
            project_id=self.client.project_id,
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
        self.wait_for_guest_os_ready(vm['server'])

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
