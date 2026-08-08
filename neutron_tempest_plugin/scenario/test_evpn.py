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

import testtools

from tempest.common import waiters
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

    @classmethod
    def resource_cleanup(cls):
        cls._try_delete_resource(
            cls.admin_client.remove_router_interface_with_subnet_id,
            cls.router['id'], cls.subnet['id'])
        super().resource_cleanup()

    def _create_evpn_server(self):
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
        return server['server'], port, private_ip

    def _check_evpn_connectivity(self, ip):
        self.check_connectivity(ip,
                                CONF.validation.image_ssh_user,
                                self.keypair['private_key'])

    def _get_server_host(self, server_id):
        server = self.os_admin.servers_client.show_server(
            server_id)['server']
        return server['OS-EXT-SRV-ATTR:host']

    def _test_evpn_server_connectivity_action(self, action,
                                              return_action,
                                              expected_state):
        server, _, private_ip = self._create_evpn_server()
        self._check_evpn_connectivity(private_ip)
        action(server['id'])
        self.wait_for_server_status(server, expected_state)
        self.ping_ip_address(private_ip, should_succeed=False)
        return_action(server['id'])
        self.wait_for_server_active(server)
        self._check_evpn_connectivity(private_ip)

    @decorators.idempotent_id('a1b2c3d4-e5f6-7890-abcd-ef1234567890')
    def test_basic_instance_evpn(self):
        _, _, private_ip = self._create_evpn_server()
        self._check_evpn_connectivity(private_ip)

    @decorators.idempotent_id('b2c3d4e5-f6a7-8901-bcde-f12345678901')
    def test_evpn_server_connectivity_stop_start(self):
        self._test_evpn_server_connectivity_action(
            action=self.os_primary.servers_client.stop_server,
            return_action=self.os_primary.servers_client.start_server,
            expected_state='SHUTOFF')

    @decorators.idempotent_id('c3d4e5f6-a7b8-9012-cdef-123456789012')
    def test_evpn_server_connectivity_reboot(self):
        server, _, private_ip = self._create_evpn_server()
        self._check_evpn_connectivity(private_ip)
        self.os_primary.servers_client.reboot_server(
            server['id'], type='SOFT')
        self.wait_for_server_active(server)
        self._check_evpn_connectivity(private_ip)

    @decorators.idempotent_id('0a1b2c3d-4e5f-6789-0abc-def123456789')
    def test_evpn_server_reuse_port(self):
        port = self.create_port(
            self.network,
            security_groups=[self.secgroup['id']])
        private_ip = port['fixed_ips'][0]['ip_address']
        server = self.create_server(
            flavor_ref=CONF.compute.flavor_ref,
            image_ref=CONF.compute.image_ref,
            key_name=self.keypair['name'],
            networks=[{'port': port['id']}],
            security_groups=[
                {'name': self.secgroup['name']}])
        self._check_evpn_connectivity(private_ip)
        self.os_primary.servers_client.delete_server(
            server['server']['id'])
        waiters.wait_for_server_termination(
            self.os_primary.servers_client,
            server['server']['id'])
        self.create_server(
            flavor_ref=CONF.compute.flavor_ref,
            image_ref=CONF.compute.image_ref,
            key_name=self.keypair['name'],
            networks=[{'port': port['id']}],
            security_groups=[
                {'name': self.secgroup['name']}])
        self._check_evpn_connectivity(private_ip)

    @decorators.idempotent_id('e5f6a7b8-c9d0-1234-efab-345678901234')
    @testtools.skipUnless(CONF.compute_feature_enabled.pause,
                          'Pause is not available.')
    def test_evpn_server_connectivity_pause_unpause(self):
        self._test_evpn_server_connectivity_action(
            action=self.os_primary.servers_client.pause_server,
            return_action=self.os_primary.servers_client.unpause_server,
            expected_state='PAUSED')

    @decorators.idempotent_id('f6a7b8c9-d0e1-2345-fabc-456789012345')
    @testtools.skipUnless(CONF.compute_feature_enabled.suspend,
                          'Suspend is not available.')
    def test_evpn_server_connectivity_suspend_resume(self):
        self._test_evpn_server_connectivity_action(
            action=self.os_primary.servers_client.suspend_server,
            return_action=self.os_primary.servers_client.resume_server,
            expected_state='SUSPENDED')

    @decorators.idempotent_id('a7b8c9d0-e1f2-3456-abcd-567890123456')
    @testtools.skipUnless(CONF.compute_feature_enabled.resize,
                          'Resize is not available.')
    def test_evpn_server_connectivity_resize(self):
        server, _, private_ip = self._create_evpn_server()
        self._check_evpn_connectivity(private_ip)
        self.os_primary.servers_client.resize_server(
            server['id'], flavor_ref=CONF.compute.flavor_ref_alt)
        self.wait_for_server_status(server, 'VERIFY_RESIZE')
        self.os_primary.servers_client.confirm_resize_server(
            server['id'])
        self.wait_for_server_active(server)
        self._check_evpn_connectivity(private_ip)

    @decorators.idempotent_id('b8c9d0e1-f2a3-4567-bcde-678901234567')
    @testtools.skipUnless(CONF.compute_feature_enabled.cold_migration,
                          'Cold migration is not available.')
    @testtools.skipUnless(CONF.compute.min_compute_nodes > 1,
                          'Less than 2 compute nodes, skipping multinode '
                          'tests.')
    def test_evpn_server_connectivity_cold_migration(self):
        server, _, private_ip = self._create_evpn_server()
        self._check_evpn_connectivity(private_ip)
        src_host = self._get_server_host(server['id'])
        self.os_admin.servers_client.migrate_server(server['id'])
        self.wait_for_server_status(server, 'VERIFY_RESIZE')
        self.os_primary.servers_client.confirm_resize_server(
            server['id'])
        self.wait_for_server_active(server)
        self._check_evpn_connectivity(private_ip)
        dst_host = self._get_server_host(server['id'])
        self.assertNotEqual(src_host, dst_host)

    @decorators.idempotent_id('c9d0e1f2-a3b4-5678-cdef-789012345678')
    @testtools.skipUnless(CONF.compute_feature_enabled.live_migration,
                          'Live migration is not available.')
    @testtools.skipUnless(CONF.compute.min_compute_nodes > 1,
                          'Less than 2 compute nodes, skipping multinode '
                          'tests.')
    def test_evpn_server_connectivity_live_migration(self):
        server, _, private_ip = self._create_evpn_server()
        self._check_evpn_connectivity(private_ip)
        src_host = self._get_server_host(server['id'])
        block_migration = (CONF.compute_feature_enabled.
                           block_migration_for_live_migration)
        migration_kwargs = dict(
            host=None, block_migration=block_migration)
        if CONF.compute.min_microversion is None:
            migration_kwargs['disk_over_commit'] = False
        self.os_admin.servers_client.live_migrate_server(
            server['id'], **migration_kwargs)
        self.wait_for_server_active(server)
        self._check_evpn_connectivity(private_ip)
        dst_host = self._get_server_host(server['id'])
        self.assertNotEqual(src_host, dst_host)

    @decorators.idempotent_id('1e2f3a4b-5c6d-7890-abcd-ef123456789a')
    @testtools.skipUnless(
        CONF.neutron_plugin_options.evpn_vtep_ip,
        'Dynamic VNI provisioning is not configured.')
    def test_evpn_subnet_move_between_vnis(self):
        # Move a subnet between two EVPN routers that use different
        # dynamically allocated VNIs and verify connectivity on each.
        vni1 = self._allocate_vni()
        vni2 = self._allocate_vni()
        network = self.create_network()
        subnet = self.create_subnet(network)
        router1 = self.create_router_by_client(
            is_admin=True,
            external_network_id=None,
            evpn_vni=vni1)
        router2 = self.create_router_by_client(
            is_admin=True,
            external_network_id=None,
            evpn_vni=vni2)

        self.admin_client.add_router_interface_with_subnet_id(
            router1['id'], subnet['id'], advertise_host=True)
        self.addCleanup(
            self._try_delete_resource,
            self.admin_client.remove_router_interface_with_subnet_id,
            router1['id'], subnet['id'])
        self.addCleanup(
            self._try_delete_resource,
            self.admin_client.remove_router_interface_with_subnet_id,
            router2['id'], subnet['id'])

        server = self.create_server(
            flavor_ref=CONF.compute.flavor_ref,
            image_ref=CONF.compute.image_ref,
            key_name=self.keypair['name'],
            networks=[{'uuid': network['id']}],
            security_groups=[
                {'name': self.secgroup['name']}])
        port = self.client.list_ports(
            network_id=network['id'],
            device_id=server['server']['id'])['ports'][0]
        private_ip = port['fixed_ips'][0]['ip_address']

        self._check_evpn_connectivity(private_ip)

        self.admin_client.remove_router_interface_with_subnet_id(
            router1['id'], subnet['id'])
        self.ping_ip_address(private_ip, should_succeed=False)

        self.admin_client.add_router_interface_with_subnet_id(
            router2['id'], subnet['id'], advertise_host=True)
        self._check_evpn_connectivity(private_ip)
