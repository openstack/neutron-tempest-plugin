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

from neutron_lib.services.pvlan import constants as pvlan_const
from oslo_log import log
from tempest.lib.common import api_microversion_fixture
from tempest.lib.common import api_version_utils
from tempest.lib.common.utils import data_utils
from tempest.lib import decorators

from neutron_tempest_plugin.common import ssh
from neutron_tempest_plugin import config
from neutron_tempest_plugin.scenario import base

CONF = config.CONF
LOG = log.getLogger(__name__)

COMMUNITY_1 = 'community_1'

# migrate host= requires compute API microversion >= 2.56
MIGRATE_HOST_MICROVERSION = '2.56'

PVLAN_REQUIRED_EXTENSIONS = ('pvlan', 'port-security', 'router')

# Host index 0: promiscuous + community. Host index 1: community + isolated.
# Placement uses availability_zone:<host> (no SameHost/DifferentHost filters).
VM_PORT_SPECS = (
    ('vm_prom', {
        pvlan_const.PVLAN_TYPE: pvlan_const.PROMISCUOUS_TYPE,
    }, 0),
    ('vm_comm_h1', {
        pvlan_const.PVLAN_TYPE: pvlan_const.COMMUNITY_TYPE,
        pvlan_const.PVLAN_COMMUNITY: COMMUNITY_1,
    }, 0),
    ('vm_comm_h2', {
        pvlan_const.PVLAN_TYPE: pvlan_const.COMMUNITY_TYPE,
        pvlan_const.PVLAN_COMMUNITY: COMMUNITY_1,
    }, 1),
    ('vm_iso_h2', {
        pvlan_const.PVLAN_TYPE: pvlan_const.ISOLATED_TYPE,
    }, 1),
)

# Promiscuous reaches every VM; community members reach each other;
# isolated cannot reach community peers.
PVLAN_CONNECTIVITY_MATRIX = (
    ('vm_prom', 'vm_comm_h1', True),
    ('vm_prom', 'vm_comm_h2', True),
    ('vm_prom', 'vm_iso_h2', True),
    ('vm_comm_h1', 'vm_comm_h2', True),
    ('vm_comm_h2', 'vm_comm_h1', True),
    ('vm_iso_h2', 'vm_comm_h1', False),
    ('vm_iso_h2', 'vm_comm_h2', False),
)


class PvlanMigrationTest(base.BaseTempestTestCase):
    """PVLAN L2 connectivity across compute nodes with cold migration.

    NOTE: This test is intended for a two-compute topology only. It selects
    exactly two nova-compute hosts from the same AZ and migrates VMs between
    those two hosts. Extra computes in the cloud are ignored for placement.

    Four VMs on two compute hosts:
      * host 1: promiscuous, community
      * host 2: community, isolated

    After initial connectivity checks, the community VM on host 1 and the
    isolated VM on host 2 are cold-migrated to the opposite host. ICMP
    connectivity is re-validated afterward.

    Cold migrate pins the destination host (compute API >= 2.56) so that,
    if the AZ has more than two computes, Nova still moves the VM onto the
    peer host used by this two-node scenario rather than an unrelated host.
    """

    credentials = ['primary', 'admin']
    required_extensions = list(PVLAN_REQUIRED_EXTENSIONS)
    compute_min_microversion = MIGRATE_HOST_MICROVERSION
    compute_max_microversion = 'latest'

    @classmethod
    def skip_checks(cls):
        super().skip_checks()
        api_version_utils.check_skip_with_microversion(
            cls.compute_min_microversion,
            cls.compute_max_microversion,
            CONF.compute.min_microversion,
            CONF.compute.max_microversion)
        # Skip before resource_setup so no network/SG is created when the
        # cloud cannot run this scenario.
        if CONF.compute.min_compute_nodes <= 1:
            raise cls.skipException('Test needs more than 1 compute')
        if not CONF.compute_feature_enabled.cold_migration:
            raise cls.skipException('Cold migration is not available.')

    @classmethod
    def _skip_unless_ovn_backend(cls):
        if not cls._is_driver_ovn():
            raise cls.skipException(
                'PVLAN scenario tests require an ML2/OVN deployment.')

    @classmethod
    def resource_setup(cls):
        super().resource_setup()
        cls._skip_unless_ovn_backend()
        cls.compute_request_microversion = (
            api_version_utils.select_request_microversion(
                cls.compute_min_microversion,
                CONF.compute.min_microversion))
        # AZ:host boot uses the admin Nova client, so keypair and security
        # group must belong to the admin project (see admin/test_floatingip).
        cls.keypair = cls.create_keypair(
            client=cls.os_admin.keypairs_client)
        cls.network = cls.create_network(
            name=data_utils.rand_name('pvlan-net-'),
            pvlan=True, port_security_enabled=True)
        cls.subnet = cls.create_subnet(cls.network, reserve_cidr=True)
        cls.router = cls.create_router_by_client()
        cls.create_router_interface(cls.router['id'], cls.subnet['id'])
        cls.admin_network_client = cls.os_admin.network_client
        cls.secgroup = cls.create_security_group(
            name=data_utils.rand_name('pvlan-secgroup'),
            client=cls.admin_network_client)
        cls.create_loginable_secgroup_rule(
            secgroup_id=cls.secgroup['id'],
            client=cls.admin_network_client)
        cls.create_pingable_secgroup_rule(
            secgroup_id=cls.secgroup['id'],
            client=cls.admin_network_client)

    def setUp(self):
        super().setUp()
        self.useFixture(api_microversion_fixture.APIMicroversionFixture(
            compute_microversion=self.compute_request_microversion))
        self.vms = {}
        self.all_servers = []
        # Two-node scenario only: pick exactly two computes from one AZ.
        self.compute_azs = self._get_compute_hosts(count=2)

    def _get_compute_hosts(self, count=2):
        """Return [(az_name, hypervisor_hostname), ...] from one AZ.

        Cold migration stays within an AZ.
        """
        az_list = self.os_admin.az_client.list_availability_zones(
            detail=True)['availabilityZoneInfo']
        hv_list = self.os_admin.hv_client.list_hypervisors()['hypervisors']
        for az in az_list:
            if not az['zoneState']['available']:
                continue
            hosts = []
            seen = set()
            for host, services in az['hosts'].items():
                for service, info in services.items():
                    if not (service == 'nova-compute' and
                            info['active'] and info['available']):
                        continue
                    hv = [
                        h for h in hv_list
                        if (h['hypervisor_hostname'].startswith(host) and
                            h['state'] == 'up' and
                            h['status'] == 'enabled')
                    ]
                    if not hv:
                        continue
                    hostname = hv[0]['hypervisor_hostname']
                    if hostname in seen:
                        continue
                    seen.add(hostname)
                    hosts.append((az['zoneName'], hostname))
            if len(hosts) >= count:
                LOG.info(
                    'Using AZ %s computes: %s',
                    az['zoneName'],
                    [h[1] for h in hosts[:count]])
                return hosts[:count]
        raise self.skipException(
            'Test needs one AZ with at least %s nova-compute hosts' % count)

    def _get_host_for_server(self, server_id):
        server_details = self.os_admin.servers_client.show_server(server_id)
        return server_details['server']['OS-EXT-SRV-ATTR:host']

    def _create_pvlan_vm(self, name, pvlan_kwargs, host_index):
        """Boot a pinned VM, then set the PVLAN role on its port."""
        az_name, hypervisor = self.compute_azs[host_index]
        server = self.create_server(
            flavor_ref=CONF.compute.flavor_ref,
            image_ref=CONF.compute.image_ref,
            key_name=self.keypair['name'],
            security_groups=[{'name': self.secgroup['name']}],
            name=data_utils.rand_name(name),
            networks=[{'uuid': self.network['id']}],
            availability_zone='%s:%s' % (az_name, hypervisor))
        port = self.admin_network_client.list_ports(
            network_id=self.network['id'],
            device_id=server['server']['id'])['ports'][0]
        port = self.admin_network_client.update_port(
            port['id'], **pvlan_kwargs)['port']
        fip = self.create_floatingip(
            port=port, client=self.admin_network_client)
        ssh_client = ssh.Client(
            fip['floating_ip_address'],
            CONF.validation.image_ssh_user,
            pkey=self.keypair['private_key'])
        self.vms[name] = {
            'server': server,
            'port': port,
            'fip': fip,
            'ssh': ssh_client,
            'ip': port['fixed_ips'][0]['ip_address'],
        }
        self.all_servers.append(server)
        LOG.info(
            'Created %s on %s:%s (fixed_ip=%s, pvlan=%s)',
            name, az_name, hypervisor,
            port['fixed_ips'][0]['ip_address'], pvlan_kwargs)

    def _setup_vms(self):
        for name, pvlan_kwargs, host_index in VM_PORT_SPECS:
            self._create_pvlan_vm(name, pvlan_kwargs, host_index)
        self._verify_host_groups(
            ('vm_prom', 'vm_comm_h1'),
            ('vm_comm_h2', 'vm_iso_h2'),
            phase='initial_placement')

    def _server_host(self, vm_name):
        server_id = self.vms[vm_name]['server']['server']['id']
        return self._get_host_for_server(server_id).split('.')[0]

    def _verify_host_groups(self, host1_group, host2_group, phase):
        host1_placement = {
            vm: self._server_host(vm) for vm in host1_group}
        host2_placement = {
            vm: self._server_host(vm) for vm in host2_group}
        host1_hosts = set(host1_placement.values())
        host2_hosts = set(host2_placement.values())
        LOG.info(
            'PVLAN %s host placement: group1=%s group2=%s',
            phase, host1_placement, host2_placement)
        self.assertEqual(
            1, len(host1_hosts),
            '%s: VMs %s should share one compute host (placement=%s)' % (
                phase, host1_group, host1_placement))
        self.assertEqual(
            1, len(host2_hosts),
            '%s: VMs %s should share one compute host (placement=%s)' % (
                phase, host2_group, host2_placement))
        self.assertNotEqual(
            host1_hosts, host2_hosts,
            '%s: host groups must run on different compute nodes '
            '(group1=%s group2=%s)' % (
                phase, host1_placement, host2_placement))
        LOG.info(
            'PVLAN %s host groups OK: group1 on %s, group2 on %s',
            phase, host1_hosts, host2_hosts)

    def _check_icmp(self, src_name, dst_name, should_succeed):
        src = self.vms[src_name]
        dst_ip = self.vms[dst_name]['ip']
        self.check_remote_connectivity(
            src['ssh'], dst_ip,
            should_succeed=should_succeed,
            servers=self.all_servers,
            ping_count=3)

    def _check_pvlan_connectivity(self, phase_name):
        for case_num, (src, dst, allowed) in enumerate(
                PVLAN_CONNECTIVITY_MATRIX, start=1):
            with self.subTest(phase=phase_name, case=case_num,
                              src=src, dst=dst, allowed=allowed):
                LOG.info(
                    'PVLAN %s case %s: %s -> %s (allow=%s)',
                    phase_name, case_num, src, dst, allowed)
                self._check_icmp(src, dst, allowed)

    def _cold_migrate_vm(self, vm_name, target_vm_name):
        server = self.vms[vm_name]['server']['server']
        old_host = self._server_host(vm_name)
        # Pin destination so 3+ node AZs do not schedule onto a third host.
        # Requires compute API microversion >= 2.56 (see setUp fixture).
        target_server_id = self.vms[target_vm_name]['server']['server']['id']
        dest_host = self._get_host_for_server(target_server_id)
        client = self.os_admin.servers_client
        LOG.info(
            'Cold migrating %s from %s to %s (peer %s)',
            vm_name, old_host, dest_host, target_vm_name)
        client.migrate_server(server['id'], host=dest_host)
        self.wait_for_server_status(
            server, 'VERIFY_RESIZE', client=client)
        client.confirm_resize_server(server['id'])
        self.wait_for_server_active(server, client=client)
        self.wait_for_guest_os_ready(server, client=client)
        new_host = self._server_host(vm_name)
        self.assertNotEqual(
            old_host, new_host, '%s did not migrate' % vm_name)
        self.assertEqual(
            self._server_host(target_vm_name), new_host,
            '%s should share host with %s after migration' % (
                vm_name, target_vm_name))

    @decorators.idempotent_id('b7c4e8f2-3a1d-4e5f-9b6c-7d8e9f0a1b2c')
    @decorators.attr(type='slow')
    def test_pvlan_connectivity_cold_migration(self):
        """PVLAN segmentation survives cold migration across compute nodes.

        Designed for exactly two compute hosts.
        """
        self._setup_vms()
        self._check_pvlan_connectivity('before_migration')

        self._cold_migrate_vm('vm_comm_h1', 'vm_comm_h2')
        self._cold_migrate_vm('vm_iso_h2', 'vm_prom')
        self._verify_host_groups(
            ('vm_prom', 'vm_iso_h2'),
            ('vm_comm_h1', 'vm_comm_h2'),
            phase='post_migration_placement')
        self._check_pvlan_connectivity('after_migration')
