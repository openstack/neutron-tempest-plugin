# Copyright (C) 2016 VA Linux Systems Japan K.K.
# Copyright (C) 2016 Fumihiko Kakuma <kakuma at valinux co jp>
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

from tempest import config
from tempest.lib import decorators

from neutron_tempest_plugin.neutron_dynamic_routing.scenario import base
from neutron_tempest_plugin.neutron_dynamic_routing.scenario\
    import base_test_proto as test_base

from os_ken.tests.integrated.common import docker_base as ctn_base
from os_ken.tests.integrated.common import quagga

CONF = config.CONF


class BgpSpeakerIpv4Test(test_base.BgpSpeakerProtoTestBase):

    RAS_MAX = 3
    ip_version = 4
    public_gw = '192.168.11.1'
    MyScope = base.Scope(name='my-scope')
    PNet = base.Net(name='', net='172.24.6.0', mask=24,
                    cidr='172.24.6.0/24', router=None)
    PPool = base.Pool(name='test-pool-ext', prefixlen=PNet.mask,
                      prefixes=[PNet.net + '/8'])
    PSubNet = base.SubNet(name='', cidr=PNet.cidr, mask=PNet.mask)
    TPool = base.Pool(name='tenant-test-pool', prefixlen=28,
                      prefixes=['10.10.0.0/16'])
    L_AS = base.AS(asn='64512', router_id='192.168.0.2', adv_net='')
    ras_l = [
        base.AS(asn='64522', router_id='192.168.0.12',
                adv_net='192.168.162.0/24'),
        base.AS(asn='64523', router_id='192.168.0.13',
                adv_net='192.168.163.0/24'),
        base.AS(asn='64524', router_id='192.168.0.14',
                adv_net='192.168.164.0/24')
    ]

    bgp_speaker_args = {
        'local_as': L_AS.asn,
        'ip_version': ip_version,
        'name': 'my-bgp-speaker1',
        'advertise_floating_ip_host_routes': True,
        'advertise_tenant_networks': True
    }
    bgp_peer_args = [
        {'remote_as': ras_l[0].asn,
         'name': 'my-bgp-peer1',
         'peer_ip': None,
         'auth_type': 'none'},
        {'remote_as': ras_l[1].asn,
         'name': 'my-bgp-peer2',
         'peer_ip': None,
         'auth_type': 'none'},
        {'remote_as': ras_l[2].asn,
         'name': 'my-bgp-peer3',
         'peer_ip': None,
         'auth_type': 'none'}
    ]

    def setUp(self):
        super(BgpSpeakerIpv4Test, self).setUp()

    @classmethod
    def resource_setup_container(cls):
        cls.brdc = ctn_base.Bridge(name='br-docker-ipv4',
                                   subnet='192.168.11.0/24',
                                   start_ip='192.168.11.128',
                                   end_ip='192.168.11.254',
                                   self_ip=True,
                                   fixed_ip=cls.public_gw + '/24',
                                   br_type=base.BRIDGE_TYPE)
        cls.bridges.append(cls.brdc)
        # This is dummy container object for a dr service.
        # This keeps data which passes to a quagga container.
        cls.dr = ctn_base.BGPContainer(name='dr', asn=int(cls.L_AS.asn),
                                       router_id=cls.L_AS.router_id)
        cls.dr.set_addr_info(bridge='br-docker-ipv4', ipv4=cls.public_gw)
        # quagga container
        cls.dockerimg = ctn_base.DockerImage(baseimage=cls.baseimage)
        cls.q_img = cls.dockerimg.create_quagga(check_exist=True)
        cls.images.append(cls.q_img)
        for i in range(cls.RAS_MAX):
            qg = quagga.QuaggaBGPContainer(name='q' + str(i + 1),
                                           asn=int(cls.ras_l[i].asn),
                                           router_id=cls.ras_l[i].router_id,
                                           ctn_image_name=cls.q_img)
            cls.containers.append(qg)
            cls.r_ass.append(qg)
            qg.add_route(cls.ras_l[i].adv_net)
            qg.run(wait=True)
            cls.r_as_ip.append(cls.brdc.addif(qg))
            qg.add_peer(cls.dr, bridge=cls.brdc.name,
                        peer_info={'passive': True})
        cls.tnet_gen = cls.get_subnet(start='10.10.1.0', end='10.10.255.0',
                                      step=256)

    @decorators.idempotent_id('7f2acbc2-ff88-4a63-aa02-a2f9feb3f5b0')
    def test_check_neighbor_established(self):
        self._test_check_neighbor_established(self.ip_version)

    @decorators.idempotent_id('f32245fc-aeab-4244-acfa-3af9dd662e8d')
    def test_check_advertised_tenant_network(self):
        self._test_check_advertised_tenant_network(self.ip_version)

    @decorators.idempotent_id('a5c238de-b750-499c-aaa2-b44a057e9ed3')
    def test_check_advertised_multiple_tenant_network(self):
        self._test_check_advertised_multiple_tenant_network(self.ip_version)

    @decorators.idempotent_id('e4961cc1-0c47-4081-a896-caaa9342ca75')
    def test_check_neighbor_established_with_multiple_peers(self):
        self._test_check_neighbor_established_with_multiple_peers(
            self.ip_version)

    @decorators.idempotent_id('91971dfb-c129-4744-9fbb-ac4f9e8d56c0')
    def test_check_advertised_tenant_network_with_multiple_peers(self):
        self._test_check_advertised_tenant_network_with_multiple_peers(
            self.ip_version)
