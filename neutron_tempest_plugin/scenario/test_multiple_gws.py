# Copyright 2023 Canonical
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
import json
import os
import subprocess
import time
import typing

import netaddr
import testtools

from tempest.common import utils as tutils

from neutron_tempest_plugin import config
from neutron_tempest_plugin.scenario import base

from neutron_lib import constants as const

from oslo_log import log

from os_ken.tests.integrated.common import docker_base as ctn_base

from tempest.lib.common.utils import data_utils
from tempest.lib import decorators
from tempest.lib import exceptions as lib_exc

CONF = config.CONF
LOG = log.getLogger(__name__)
FRR_BASE_IMAGE = 'quay.io/nf-core/ubuntu:22.04'


class FRROCIImage(ctn_base.DockerImage):
    def __init__(
        self,
        daemons: typing.Tuple[str],
        baseimage: typing.Optional[str] = None,
        use_existing: bool = False,
    ):
        super().__init__(baseimage=baseimage or FRR_BASE_IMAGE)
        self.daemons = daemons
        self.tagname = 'frr-' + '-'.join(daemons)
        if use_existing and self.exist(self.tagname):
            return

        workdir = os.path.join(ctn_base.TEST_BASE_DIR, self.tagname)
        pkgs = ' '.join(('telnet', 'tcpdump', 'frr'))
        c = ctn_base.CmdBuffer()
        c << f'FROM {self.baseimage}'
        c << 'RUN apt-get update'
        c << f'RUN apt-get install -qy --no-install-recommends {pkgs}'
        c << 'RUN echo "#!/bin/sh" > /frr'
        c << 'RUN echo mkdir -p /run/frr >> /frr'
        c << 'RUN echo chmod 755 /run/frr >> /frr'
        c << 'RUN echo chown frr:frr /run/frr >> /frr'
        c << (
            'RUN echo exec /usr/lib/frr/watchfrr '
            f'-F traditional {" ".join(self.daemons)}>> /frr'
        )
        c << 'RUN chmod +x /frr'
        c << 'CMD /frr'

        self.cmd.sudo(f'rm -rf {workdir}')
        self.cmd.execute(f'mkdir -p {workdir}')
        self.cmd.execute(f"echo '{str(c)}' > {workdir}/Dockerfile")
        self.build(self.tagname, workdir)


class FRRContainer(ctn_base.Container):
    class veth_info(typing.NamedTuple):
        bridge_name: str
        bridge_type: str
        ctn_ifname: str
        host_ifname: str

    _veths: typing.List[veth_info]

    class route(typing.NamedTuple):
        dst: netaddr.IPNetwork
        next_hop: netaddr.IPNetwork

    _ctn_routes: typing.List[route]

    def __init__(
        self,
        name: str,
        image: FRROCIImage,
    ):
        self._veths = []
        self._ctn_routes = []
        super().__init__(name, image.tagname)

    # XXX upstream to os-ken
    def next_if_name(self) -> str:
        name = 'eth{0}'.format(len(self.eths))
        self.eths.append(name)
        return name

    # XXX upstream to os-ken
    def run(self, network: typing.Optional[str] = None) -> int:
        c = ctn_base.CmdBuffer(' ')
        c << "docker run --privileged=true"
        for sv in self.shared_volumes:
            c << "-v {0}:{1}".format(sv[0], sv[1])
        if network:
            c << "--network {0}".format(network)
        c << "--name {0} --hostname {0} -id {1}".format(
            self.docker_name(), self.image
        )
        self.id = self.dcexec(str(c), retry=True)
        self.is_running = True
        self.exec_on_ctn("ip li set up dev lo")
        ipv4 = None
        ipv6 = None
        if network and network != 'none':
            ifname = self.next_if_name()
            for line in self.exec_on_ctn(f"ip a show dev {ifname}").split(
                '\n'
            ):
                if line.strip().startswith("inet "):
                    elems = [e.strip() for e in line.strip().split(' ')]
                    ipv4 = elems[1]
                elif line.strip().startswith("inet6 "):
                    elems = [e.strip() for e in line.strip().split(' ')]
                    ipv6 = elems[1]
            self.set_addr_info(
                bridge='docker0', ipv4=ipv4, ipv6=ipv6, ifname=ifname
            )
        return 0

    def wait_for_frr_daemons_up(
        self,
        try_times: int = 30,
        interval: int = 1,
    ) -> ctn_base.CommandOut:
        return self.cmd.sudo(
            f'docker logs {self.docker_name()} '
            '|grep "WATCHFRR.*all daemons up"',
            try_times=try_times,
            interval=interval,
        )

    @staticmethod
    def hash_ifname(ifname: str) -> str:
        # Assuming IFNAMSIZ of 16, with null-termination gives 15 characters.
        return 'veth' + str(hash(ifname) % 10**11)

    @staticmethod
    def get_if_mac(ifname: str) -> netaddr.EUI:
        with open(f'/sys/class/net/{ifname}/address') as faddr:
            return faddr.readline().rstrip()

    def add_veth_to_bridge(
        self,
        bridge_name: str,
        bridge_type: str,
        ipv4_cidr: str,
        ipv6_cidr: str,
        ipv6_prefix: typing.Optional[netaddr.IPNetwork] = None,
        vlan: typing.Optional[int] = None,
    ) -> None:
        assert self.is_running, (
            'the container must be running before '
            'calling add_veth_to_bridge'
        )
        assert (
            bridge_type == ctn_base.BRIDGE_TYPE_OVS
        ), f'bridge_type must be {ctn_base.BRIDGE_TYPE_OVS}'
        veth_pair = (
            self.hash_ifname(f'{self.name}-int{len(self._veths)}'),
            self.hash_ifname(f'{self.name}-ext{len(self._veths)}'),
        )
        self.cmd.sudo(
            f'ip link add {veth_pair[0]} type veth peer name {veth_pair[1]}'
        )
        if ipv6_prefix and not ipv6_cidr:
            eui = netaddr.EUI(self.get_if_mac(veth_pair[0]))
            ipv6_cidr = (
                f'{eui.ipv6(ipv6_prefix.first)}/{ipv6_prefix.prefixlen}'
            )

        self.cmd.sudo(f'ip link set netns {self.get_pid()} dev {veth_pair[0]}')
        self.cmd.sudo(f'ovs-vsctl add-port {bridge_name} {veth_pair[1]}')
        if vlan:
            self.cmd.sudo(f'ovs-vsctl set port {veth_pair[1]} tag={vlan}')

        ifname = self.next_if_name()
        self.exec_on_ctn(f'ip link set name {ifname} {veth_pair[0]}')

        # Ensure IPv6 is not disabled in container
        self.exec_on_ctn('sysctl -w net.ipv6.conf.all.disable_ipv6=0')

        for cidr in (ipv4_cidr, ipv6_cidr):
            if not cidr:
                continue
            self.exec_on_ctn(f'ip addr add {cidr} dev {ifname}')
        self.exec_on_ctn(f'ip link set up dev {ifname}')
        self.cmd.sudo(f'ip link set up dev {veth_pair[1]}')
        self.set_addr_info(
            bridge_name, ipv4=ipv4_cidr, ipv6=ipv6_cidr, ifname=ifname
        )
        self._veths.append(
            self.veth_info(
                bridge_name=bridge_name,
                bridge_type=bridge_type,
                ctn_ifname=ifname,
                host_ifname=veth_pair[1],
            )
        )

    def add_ctn_route(self, route: route) -> None:
        self.exec_on_ctn(
            f'ip -{route.dst.version} route add '
            f'{str(route.dst.cidr)} via {str(route.next_hop.ip)}'
        )
        self._ctn_routes.append(route)

    def del_ctn_route(self, route: route) -> None:
        self.exec_on_ctn(
            f'ip -{route.dst.version} route del '
            f'{str(route.dst.cidr)} via {str(route.next_hop.ip)}'
        )
        self._ctn_routes.remove(route)

    def remove(self, check_exist=True) -> ctn_base.CommandOut:
        for veth in self._veths:
            # The veth pair itself will be destroyed as a side effect of
            # removing the container, so we only need to clean up the bridge
            # attachment.
            if veth.bridge_type == ctn_base.BRIDGE_TYPE_BRCTL:
                self.cmd.sudo(
                    'brctl delif ' f'{veth.bridge_name} ' f'{veth.host_ifname}'
                )
            elif veth.bridge_type == ctn_base.BRIDGE_TYPE_OVS:
                self.cmd.sudo(
                    'ovs-vsctl del-port '
                    f'{veth.bridge_name} '
                    f'{veth.host_ifname}'
                )
        super().remove(check_exist=check_exist)

    def vtysh(self, cmd: typing.List[str]) -> ctn_base.CommandOut:
        cmd_str = ' '.join(f"-c '{c}'" for c in cmd)
        return self.exec_on_ctn(f'vtysh {cmd_str}', capture=True)


class BFDContainer(FRRContainer):
    def __init__(
        self,
        name: str,
        image: typing.Optional[FRROCIImage] = None,
    ):
        image = image or FRROCIImage(
            daemons=('zebra', 'bfdd'), use_existing=True
        )
        super().__init__(name, image)
        assert 'bfdd' in image.daemons

    def add_bfd_peer(self, ip_address: str) -> None:
        self.vtysh(
            [
                'enable',
                'conf',
                'bfd',
                f'peer {ip_address} interface eth0',
            ]
        )

    def del_bfd_peer(self, ip_address: str) -> None:
        self.vtysh(
            [
                'enable',
                'conf',
                'bfd',
                f'no peer {ip_address} interface eth0',
            ]
        )

    def show_bfd_peer(self, peer: str) -> typing.Dict[str, typing.Any]:
        return json.loads(self.vtysh([f'show bfd peer {peer} json']))

    def wait_for_bfd_peer_status(
        self, peer: str, status: str, try_times=30, interval=1
    ) -> None:
        while try_times:
            peer_data = self.show_bfd_peer(peer)
            if peer_data['status'] == status:
                return
            time.sleep(interval)
            try_times -= 1
        raise lib_exc.TimeoutException


class NetworkMultipleGWTest(base.BaseAdminTempestTestCase):
    """Test the following topology

    +------------------------------------------------------------------+
    |                          test runner                             |
    |                                                                  |
    |                                 +-----------+ eth0 public VLAN N |
    | +-------- br-ex ----------+     | FRR w/BFD |                    |
    | | +---------------------+ |     +-----------+ eth1 public flat   |
    | | |   public physnet    | |     +-----------+ eth0 public VLAN N |
    | | +---------------------+ |     | FRR w/BFD |                    |
    | +-------------------------+     +-----------+ eth1 public flat   |
    |     |              |                                             |
    +-----|--------------|---------------------------------------------+
          | -  VLAN N  - |
     +-------------------------+
     |      project router     | - enable_default_route_{bfd,ecmp}=True
     +-------------------------+
                 |
           +----------+
           | instance |
           +----------+

    NOTE(fnordahl) At the time of writing, FRR provides a BFD daemon, but has
    not integrated it with static routes [0][1].  As a consequence the
    test will manually add/remove routes on test runner to ensure correct path
    is chosen for traffic from test runner to instance.  On the return path the
    BFD implementation in OVN will ensure the correct path is chosen
    automatically.

    In real world usage most vendors have BFD support for static routes.

    0: https://github.com/FRRouting/frr/wiki/Feature-Requests
    1: https://github.com/FRRouting/frr/issues/3369
    """
    class host_route(typing.NamedTuple):
        dst: netaddr.IPNetwork
        next_hop: netaddr.IPNetwork

    host_routes: typing.List[host_route] = []

    credentials = ['primary', 'admin']

    @classmethod
    def setup_clients(cls):
        super().setup_clients()
        if not cls.admin_client:
            cls.admin_client = cls.os_admin.network_client

    @classmethod
    @tutils.requires_ext(extension="external-gateway-multihoming",
                         service="network")
    def resource_setup(cls):
        super().resource_setup()

        # Ensure devstack configured public subnets are recorded, so that we
        # don't attempt to use them again.
        cls.reserve_external_subnet_cidrs()

        # We need to know prefixlength of the devstack configured public
        # subnets.
        for subnet_id in cls.admin_client.show_network(
                CONF.network.public_network_id)['network']['subnets']:
            subnet = cls.admin_client.show_subnet(subnet_id)['subnet']
            if subnet['ip_version'] == 4:
                cls.public_ipv4_subnet = subnet
                continue
            cls.public_ipv6_subnet = subnet
        cls.ext_networks = []
        for n in range(0, 2):
            ext_network = cls.create_provider_network(
                physnet_name='public',
                start_segmentation_id=4040 + n,
                external=True,
            )
            ext_ipv6_subnet = cls.create_subnet(
                ext_network,
                ip_version=const.IP_VERSION_6,
                client=cls.admin_client,
            )
            ext_ipv4_subnet = cls.create_subnet(
                ext_network,
                ip_version=const.IP_VERSION_4,
                client=cls.admin_client,
            )
            cls.ext_networks.append(
                (ext_network, ext_ipv6_subnet, ext_ipv4_subnet)
            )
        cls.host_routes = []
        cls.resource_setup_container()

    @classmethod
    def resource_setup_container(cls):
        cls.containers = []
        for n in range(0, 2):
            ext_network, ext_ipv6_subnet, ext_ipv4_subnet = cls.ext_networks[n]

            # frr container
            bfd_container = BFDContainer(data_utils.rand_name('frr'))
            cls.containers.append(bfd_container)

            bfd_container.run(network='none')
            public_ipv6_net = netaddr.IPNetwork(cls.public_ipv6_subnet['cidr'])
            public_ipv4_net = netaddr.IPNetwork(cls.public_ipv4_subnet['cidr'])
            ipv6_net = netaddr.IPNetwork(ext_ipv6_subnet['cidr'])
            ipv4_net = netaddr.IPNetwork(ext_ipv4_subnet['cidr'])
            # reserve an IP for container on the public network for routing
            # into the vlan network.
            fip_address = cls.create_floatingip()['floating_ip_address']
            cls.veths = [
                bfd_container.add_veth_to_bridge(
                    'br-ex',
                    ctn_base.BRIDGE_TYPE_OVS,
                    f'{ext_ipv4_subnet["gateway_ip"]}/{ipv4_net.prefixlen}',
                    f'{ext_ipv6_subnet["gateway_ip"]}/{ipv6_net.prefixlen}',
                    vlan=ext_network['provider:segmentation_id'],
                ),
                bfd_container.add_veth_to_bridge(
                    'br-ex',
                    ctn_base.BRIDGE_TYPE_OVS,
                    f'{fip_address}/{public_ipv4_net.prefixlen}',
                    '',
                    ipv6_prefix=public_ipv6_net,
                ),
            ]
            for subnet in (cls.public_ipv4_subnet, cls.public_ipv6_subnet):
                bfd_container.exec_on_ctn(
                    f'ip -{subnet["ip_version"]} route add default '
                    f'via {subnet["gateway_ip"]} dev eth1'
                )
            for ip_version in (6, 4):
                for addr_info in bfd_container.get_addr_info(
                    'br-ex', ip_version
                ).items():
                    if addr_info[1] == 'eth1':
                        if ip_version == 6:
                            dst_subnet = ext_ipv6_subnet
                        else:
                            dst_subnet = ext_ipv4_subnet
                        cls.add_host_route(
                            cls.host_routes,
                            cls.host_route(
                                netaddr.IPNetwork(dst_subnet["cidr"]),
                                netaddr.IPNetwork(addr_info[0]),
                            ),
                        )
            bfd_container.wait_for_frr_daemons_up()

    @classmethod
    def resource_cleanup(cls):
        # Ensure common cleanup code can clean up resources created by admin
        cls.client = cls.admin_client
        super().resource_cleanup()
        for ctn in cls.containers:
            try:
                ctn.stop()
            except ctn_base.CommandError:
                pass
            ctn.remove()
        # NOTE(fnordahl): the loop body modifies the list, so we need to
        # iterate on a copy.
        for route in cls.host_routes.copy():
            cls.del_host_route(cls.host_routes, route)

    @staticmethod
    def add_host_route(
        lst: typing.List[host_route],
        route: host_route
    ) -> None:
        subprocess.run(
            (
                'sudo',
                'ip',
                f'-{route.dst.version}',
                'route',
                'add',
                str(route.dst.cidr),
                'via',
                str(route.next_hop.ip),
            ),
            capture_output=True,
            check=True,
            universal_newlines=True,
        )
        lst.append(route)

    @staticmethod
    def del_host_route(
        lst: typing.List[host_route],
        route: host_route
    ) -> None:
        subprocess.run(
            (
                'sudo',
                'ip',
                f'-{route.dst.version}',
                'route',
                'del',
                str(route.dst.cidr),
                'via',
                str(route.next_hop.ip),
            ),
            capture_output=True,
            check=True,
            universal_newlines=True,
        )
        lst.remove(route)

    def add_ctn_route(
        self,
        ctn: BFDContainer,
        dst: netaddr.IPNetwork,
        next_hop: netaddr.IPNetwork,
    ):
        ctn_route = ctn.route(dst, next_hop)
        ctn.add_ctn_route(ctn_route)
        self.per_test_ctn_routes.append((ctn, ctn_route))

    def setUp(self):
        super().setUp()
        self.per_test_host_routes = []
        self.per_test_ctn_routes = []

    def tearDown(self):
        super().tearDown()
        # NOTE(fnordahl): the loop body modifies the list, so we need to
        # iterate on a copy.
        for ctn_route in self.per_test_ctn_routes.copy():
            ctn = ctn_route[0]
            route = ctn_route[1]
            ctn.del_ctn_route(route)
        for host_route in self.per_test_host_routes.copy():
            self.del_host_route(self.per_test_host_routes, host_route)

    def add_routes_for_router(
        self,
        router: typing.Dict[str, typing.Any],
        ctn: FRRContainer,
        add_ctn_route: bool = True,
        add_host_route: bool = True,
    ):
        for port in self.admin_client.list_router_interfaces(router['id'])[
            'ports'
        ]:
            if port['device_owner'] != const.DEVICE_OWNER_ROUTER_INTF:
                continue
            for fixed_ip in port['fixed_ips']:
                subnet = self.client.show_subnet(
                    fixed_ip['subnet_id'])['subnet']
                for addr_info in ctn.get_addr_info(
                    'br-ex',
                    subnet['ip_version'],
                ).items():
                    if addr_info[1] == 'eth0':
                        # container route
                        ctn_net = netaddr.IPNetwork(addr_info[0])
                        for gw_info in router['external_gateways']:
                            for ip_info in gw_info['external_fixed_ips']:
                                if (
                                    ip_info['ip_address'] in ctn_net and
                                    add_ctn_route
                                ):
                                    self.add_ctn_route(
                                        ctn,
                                        netaddr.IPNetwork(subnet['cidr']),
                                        netaddr.IPNetwork(
                                            ip_info['ip_address']
                                        ),
                                    )
                    elif addr_info[1] == 'eth1' and add_host_route:
                        self.add_host_route(
                            self.per_test_host_routes,
                            self.host_route(
                                netaddr.IPNetwork(self.subnet['cidr']),
                                netaddr.IPNetwork(addr_info[0]),
                            ),
                        )

    @testtools.skipUnless(
        CONF.compute.min_compute_nodes == 1,
        'More than 1 compute node, test only works on '
        'single node configurations.',
    )
    @decorators.idempotent_id('9baa05e6-ba10-4850-93e3-695f4d97b8f8')
    def test_create_router_single_gw_bfd(self):
        ext_network_id = self.ext_networks[0][0]['id']
        bfd_container = self.containers[0]
        router = self.create_admin_router(
            router_name=data_utils.rand_name('router'),
            admin_state_up=True,
            enable_snat=False,
            enable_default_route_bfd=True,
            external_network_id=ext_network_id,
        )
        self.assertTrue(router['enable_default_route_bfd'])

        # Add BFD peers on bfd_container.
        for gw_info in router['external_gateways']:
            for ip_info in gw_info['external_fixed_ips']:
                bfd_container.add_bfd_peer(ip_info["ip_address"])
                bfd_container.wait_for_bfd_peer_status(
                    ip_info['ip_address'], 'up'
                )

        self.setup_network_and_server(
            router=router,
            create_fip=False,
            router_client=self.admin_client,
        )

        self.add_routes_for_router(router, bfd_container)

        # check connectivity
        self.check_connectivity(
            self.port['fixed_ips'][0]['ip_address'],
            CONF.validation.image_ssh_user,
            self.keypair['private_key'],
        )

    @testtools.skipUnless(
        CONF.compute.min_compute_nodes == 1,
        'More than 1 compute node, test only works on '
        'single node configurations.',
    )
    @decorators.idempotent_id('75202251-c384-4962-8685-60cf2c530906')
    def test_update_router_single_gw_bfd(self):
        ext_network_id = self.ext_networks[0][0]['id']
        bfd_container = self.containers[0]
        router = self.create_router(
            router_name=data_utils.rand_name('router'),
            admin_state_up=True,
            enable_snat=False,
            external_network_id=ext_network_id,
        )
        self.assertFalse(router['enable_default_route_bfd'])

        self.setup_network_and_server(
            router=router,
            create_fip=False,
            router_client=self.admin_client,
        )

        self.add_routes_for_router(router, bfd_container)

        # check connectivity
        self.check_connectivity(
            self.port['fixed_ips'][0]['ip_address'],
            CONF.validation.image_ssh_user,
            self.keypair['private_key'],
        )

        # Enable BFD on router.
        #
        # NOTE(fnordahl): We need to repeat the `enable_snat` state, otherwise
        # the state will be toggled to the default value of 'True'.
        router = self.admin_client.update_router_with_snat_gw_info(
            router['id'],
            enable_snat=False,
            enable_default_route_bfd=True,
        )['router']
        self.assertTrue(router['enable_default_route_bfd'])

        # Add BFD peers on bfd_container.
        for gw_info in router['external_gateways']:
            for ip_info in gw_info['external_fixed_ips']:
                bfd_container.add_bfd_peer(ip_info["ip_address"])
                bfd_container.wait_for_bfd_peer_status(
                    ip_info['ip_address'], 'up'
                )

        # check connectivity
        self.check_connectivity(
            self.port['fixed_ips'][0]['ip_address'],
            CONF.validation.image_ssh_user,
            self.keypair['private_key'],
        )

    @testtools.skipUnless(
        CONF.compute.min_compute_nodes == 1,
        'More than 1 compute node, test only works on '
        'single node configurations.',
    )
    @decorators.idempotent_id('5117587d-9633-48b7-aa8f-ec9d59a601a5')
    def test_create_router_multiple_gw_bfd_and_ecmp(self):
        router = self.create_admin_router(
            router_name=data_utils.rand_name('router'),
            admin_state_up=True,
            enable_default_route_bfd=True,
            enable_default_route_ecmp=True,
        )
        router = self.admin_client.router_add_external_gateways(
            router['id'],
            [
                {
                    'network_id': self.ext_networks[0][0]['id'],
                    'enable_snat': False,
                },
                {
                    'network_id': self.ext_networks[1][0]['id'],
                    'enable_snat': False,
                },
            ],
        )['router']

        self.setup_network_and_server(
            router=router,
            create_fip=False,
            router_client=self.admin_client,
        )

        # Add BFD peers on bfd_containers.
        for gw_info in router['external_gateways']:
            for ip_info in gw_info['external_fixed_ips']:
                ip = netaddr.IPAddress(ip_info['ip_address'])
                for ctn in self.containers:
                    for addr_info in ctn.get_addr_info(
                        'br-ex',
                        ip.version,
                    ).items():
                        if addr_info[1] == 'eth0':
                            ctn_net = netaddr.IPNetwork(addr_info[0])
                            if ip not in ctn_net:
                                break
                            ctn.add_bfd_peer(str(ip))
                            ctn.wait_for_bfd_peer_status(str(ip), 'up')

        # Add route to project network on all containers.
        for ctn in self.containers:
            self.add_routes_for_router(router, ctn, True, False)

        # Add host route to project network via FRR container and confirm
        # connectivity one by one.
        #
        # We deliberately don't add both host routes at once as that would be
        # testing test runner configuration and linux kernel ECMP, which is out
        # of scope for our test.
        for ctn in self.containers:
            self.add_routes_for_router(router, ctn, False, True)

            # check connectivity
            self.check_connectivity(
                self.port['fixed_ips'][0]['ip_address'],
                CONF.validation.image_ssh_user,
                self.keypair['private_key'],
            )
            for host_route in self.per_test_host_routes.copy():
                self.del_host_route(self.per_test_host_routes, host_route)
