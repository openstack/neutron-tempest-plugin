# Copyright 2026 Red Hat, Inc.
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

from tempest.lib.common.utils import data_utils
from tempest.lib import decorators

import neutron_tempest_plugin.common.evpn_provisioner as evpn_provisioner
from neutron_tempest_plugin import config
from neutron_tempest_plugin.scenario import base


CONF = config.CONF


class NetworkEvpnTest(base.BaseAdminTempestTestCase):
    credentials = ['primary', 'admin']
    required_extensions = ['evpn']

    _ip_version = 4

    @classmethod
    def _init_vni_provisioner(cls):
        opts = CONF.neutron_plugin_options
        if opts.evpn_vtep_ip:
            cls.vni_provisioner = evpn_provisioner.EVPNVNIProvisioner(
                vtep_ip=opts.evpn_vtep_ip,
                datapath_ip=opts.evpn_datapath_ip,
                vxlan_port=opts.evpn_vxlan_port,
                asn=opts.evpn_asn,
                peer_asn=opts.evpn_peer_asn,
                vni_range_start=opts.evpn_vni_range_start,
                vni_range_end=opts.evpn_vni_range_end)
        else:
            cls.vni_provisioner = None

    @classmethod
    def _allocate_vni(cls):
        if cls.vni_provisioner:
            vni = cls.vni_provisioner.allocate_vni()
            cls.addClassResourceCleanup(
                cls.vni_provisioner.delete_vni, vni)
            return vni
        return CONF.neutron_plugin_options.evpn_vni

    @classmethod
    def resource_setup(cls):
        super().resource_setup()
        cls._init_vni_provisioner()
        cls.network = cls.create_network()
        cls.subnet = cls.create_subnet(cls.network)
        cls.keypair = cls.create_keypair()

        cls.secgroup = cls.create_security_group(
            name=data_utils.rand_name('evpn-secgroup'))
        cls.create_loginable_secgroup_rule(
            secgroup_id=cls.secgroup['id'])
        cls.create_pingable_secgroup_rule(
            secgroup_id=cls.secgroup['id'])

        # No external gateway: an external network would add an ECMP
        # path for the EVPN learned route, causing OVN to load-balance
        # return traffic between the EVPN tunnel and the public network.
        cls.router = cls.create_router_by_client(
            is_admin=True,
            external_network_id=None,
            evpn_vni=cls._allocate_vni())
        cls.admin_client.add_router_interface_with_subnet_id(
            cls.router['id'], cls.subnet['id'],
            advertise_host=True)

    @decorators.idempotent_id('a1b2c3d4-e5f6-7890-abcd-ef1234567890')
    def test_basic_instance_evpn(self):
        server = self.create_server(
            flavor_ref=CONF.compute.flavor_ref,
            image_ref=CONF.compute.image_ref,
            key_name=self.keypair['name'],
            networks=[{'uuid': self.network['id']}],
            security_groups=[
                {'name': self.secgroup['name']}])
        port = self.client.list_ports(
            network_id=self.network['id'],
            device_id=server['server']['id'])['ports'][0]
        private_ip = port['fixed_ips'][0]['ip_address']
        self.check_connectivity(private_ip,
                                CONF.validation.image_ssh_user,
                                self.keypair['private_key'])
