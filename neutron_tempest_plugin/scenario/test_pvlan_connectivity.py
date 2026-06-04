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
from tempest.common import utils
from tempest.common import waiters
from tempest.lib.common.utils import data_utils
from tempest.lib import decorators

from neutron_tempest_plugin.common import ssh
from neutron_tempest_plugin import config
from neutron_tempest_plugin.scenario import base
from neutron_tempest_plugin.scenario import constants as const

CONF = config.CONF
LOG = log.getLogger(__name__)

COMMUNITY_1 = 'community_1'
COMMUNITY_2 = 'community_2'

PVLAN_REQUIRED_EXTENSIONS = ('pvlan', 'port-security', 'router')

# Three VMs; only vm_a changes PVLAN role across phases.
#   vm_a: promiscuous -> isolated -> community_1 -> community_2
#   vm_b: community_1
#   vm_c: isolated
INITIAL_PORT_SPECS = (
    ('vm_a', {
        pvlan_const.PVLAN_TYPE: pvlan_const.PROMISCUOUS_TYPE,
    }),
    ('vm_b', {
        pvlan_const.PVLAN_TYPE: pvlan_const.COMMUNITY_TYPE,
        pvlan_const.PVLAN_COMMUNITY: COMMUNITY_1,
    }),
    ('vm_c', {
        pvlan_const.PVLAN_TYPE: pvlan_const.ISOLATED_TYPE,
    }),
)

# Directed checks per phase: (source, destination, should_succeed).
PHASE1_PROM_COMM_ISO = (
    ('vm_a', 'vm_c', True),   # promiscuous -> isolated
    ('vm_a', 'vm_b', True),   # promiscuous -> community
    ('vm_b', 'vm_c', False),  # community -> isolated
)

PHASE2_VM_A_ISOLATED = (
    ('vm_a', 'vm_b', False),  # isolated -> community
    ('vm_a', 'vm_c', False),  # isolated -> isolated
)

PHASE3_VM_A_COMM_SAME = (
    ('vm_a', 'vm_b', True),   # vm_a in community_1 with vm_b
    ('vm_a', 'vm_c', False),  # community -> isolated
)

PHASE4_VM_A_COMM_DIFF = (
    ('vm_a', 'vm_b', False),  # vm_a in community_2, vm_b in community_1
    ('vm_a', 'vm_c', False),
)


def _expected_port_pvlan_spec(pvlan_type, pvlan_community=None):
    """Build expected port PVLAN attrs with explicit community."""
    spec = {pvlan_const.PVLAN_TYPE: pvlan_type}
    spec[pvlan_const.PVLAN_COMMUNITY] = None
    if pvlan_type == pvlan_const.COMMUNITY_TYPE:
        spec[pvlan_const.PVLAN_COMMUNITY] = pvlan_community
    return spec


def _port_pvlan_specs_from_initial():
    specs = {}
    for name, kwargs in INITIAL_PORT_SPECS:
        pvlan_type = kwargs[pvlan_const.PVLAN_TYPE]
        community = kwargs.get(pvlan_const.PVLAN_COMMUNITY)
        specs[name] = _expected_port_pvlan_spec(pvlan_type, community)
    return specs


# Expected PVLAN API attributes per VM after each port update phase.
EXPECTED_PORT_PVLAN_PHASE1 = _port_pvlan_specs_from_initial()
EXPECTED_PORT_PVLAN_PHASE2 = {
    'vm_a': _expected_port_pvlan_spec(pvlan_const.ISOLATED_TYPE),
    'vm_b': _expected_port_pvlan_spec(
        pvlan_const.COMMUNITY_TYPE, COMMUNITY_1),
    'vm_c': _expected_port_pvlan_spec(pvlan_const.ISOLATED_TYPE),
}
EXPECTED_PORT_PVLAN_PHASE3 = {
    'vm_a': _expected_port_pvlan_spec(
        pvlan_const.COMMUNITY_TYPE, COMMUNITY_1),
    'vm_b': _expected_port_pvlan_spec(
        pvlan_const.COMMUNITY_TYPE, COMMUNITY_1),
    'vm_c': _expected_port_pvlan_spec(pvlan_const.ISOLATED_TYPE),
}
EXPECTED_PORT_PVLAN_PHASE4 = {
    'vm_a': _expected_port_pvlan_spec(
        pvlan_const.COMMUNITY_TYPE, COMMUNITY_2),
    'vm_b': _expected_port_pvlan_spec(
        pvlan_const.COMMUNITY_TYPE, COMMUNITY_1),
    'vm_c': _expected_port_pvlan_spec(pvlan_const.ISOLATED_TYPE),
}


class PvlanConnectivityTest(base.BaseTempestTestCase):
    """PVLAN L2 connectivity with three VMs and in-place port role changes.

    Phase 1: vm_a promiscuous, vm_b community_1, vm_c isolated.
    Phase 2: vm_a promiscuous -> isolated.
    Phase 3: vm_a isolated -> community_1 (same as vm_b).
    Phase 4: vm_a community_1 -> community_2 (different from vm_b).

    Port updates follow the same pattern as scenario/test_security_groups.py:
    update_port() then immediate ICMP connectivity checks.
    """

    credentials = ['primary', 'admin']
    required_extensions = list(PVLAN_REQUIRED_EXTENSIONS)

    @classmethod
    def _skip_unless_pvlan_supported(cls):
        """Skip before creating scenario resources if PVLAN is unavailable."""
        for ext in PVLAN_REQUIRED_EXTENSIONS:
            if not utils.is_extension_enabled(ext, 'network'):
                raise cls.skipException(
                    '%s extension not enabled.' % ext)

    @classmethod
    def _skip_unless_ovn_backend(cls):
        if not cls._is_driver_ovn():
            raise cls.skipException(
                'PVLAN scenario tests require an ML2/OVN deployment.')

    @classmethod
    def resource_setup(cls):
        cls._skip_unless_pvlan_supported()
        super().resource_setup()
        cls._skip_unless_ovn_backend()

        cls.keypair = cls.create_keypair()
        cls.network = cls.create_network(
            name=data_utils.rand_name('pvlan-net-'),
            pvlan=True, port_security_enabled=True)
        cls.subnet = cls.create_subnet(cls.network, reserve_cidr=True)
        cls.router = cls.create_router_by_client()
        cls.create_router_interface(cls.router['id'], cls.subnet['id'])

        cls.secgroup = cls.create_security_group(
            name=data_utils.rand_name('pvlan-secgroup'))
        cls.create_loginable_secgroup_rule(secgroup_id=cls.secgroup['id'])
        cls.create_pingable_secgroup_rule(secgroup_id=cls.secgroup['id'])

    def setUp(self):
        super().setUp()
        self._skip_unless_pvlan_supported()
        self._setup_vms()

    def _setup_vms(self):
        """Create PVLAN ports and boot servers."""
        sg = [{'name': self.secgroup['name']}]
        server_params = {
            'flavor_ref': CONF.compute.flavor_ref,
            'image_ref': CONF.compute.image_ref,
            'key_name': self.keypair['name'],
            'security_groups': sg,
        }
        self.vms = {}
        for name, pvlan_kwargs in INITIAL_PORT_SPECS:
            port = self.create_port(
                self.network,
                name=data_utils.rand_name(name),
                security_groups=[self.secgroup['id']],
                port_security_enabled=True,
                **pvlan_kwargs)
            server = self.create_server(
                networks=[{'port': port['id']}],
                name=data_utils.rand_name(name),
                **server_params)
            waiters.wait_for_server_status(
                self.os_primary.servers_client, server['server']['id'],
                const.SERVER_STATUS_ACTIVE)
            fip = self.create_floatingip(port=port)
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
        self.all_servers = [vm['server'] for vm in self.vms.values()]
        self._verify_ports_pvlan(EXPECTED_PORT_PVLAN_PHASE1, 'initial_setup')

    @staticmethod
    def _port_pvlan_community(port):
        community = port.get(pvlan_const.PVLAN_COMMUNITY)
        if community in (None, ''):
            return None
        return community

    def _assert_port_pvlan(self, port_id, vm_name, expected_attrs):
        """Confirm port pvlan_type and pvlan_community via show_port."""
        port = self.client.show_port(port_id)['port']
        expected_type = expected_attrs[pvlan_const.PVLAN_TYPE]
        expected_community = expected_attrs[pvlan_const.PVLAN_COMMUNITY]
        actual_type = port.get(pvlan_const.PVLAN_TYPE)
        actual_community = self._port_pvlan_community(port)

        self.assertEqual(
            expected_type, actual_type,
            'Port %s (%s): expected pvlan_type %r, got %r' % (
                port_id, vm_name, expected_type, actual_type))
        self.assertEqual(
            expected_community, actual_community,
            'Port %s (%s): expected pvlan_community %r, got %r' % (
                port_id, vm_name, expected_community, actual_community))
        if expected_type == pvlan_const.COMMUNITY_TYPE:
            self.assertIsNotNone(
                actual_community,
                'Port %s (%s): community port must have '
                'pvlan_community set' % (port_id, vm_name))
        else:
            self.assertNotIn(
                actual_community, (COMMUNITY_1, COMMUNITY_2),
                'Port %s (%s): non-community port must not retain '
                'pvlan_community %r' % (port_id, vm_name, actual_community))
        return port

    def _assert_phase_community_relationships(self, phase_name):
        """Cross-port checks that communities changed as intended."""
        vm_a_community = self._port_pvlan_community(
            self.vms['vm_a']['port'])
        vm_b_community = self._port_pvlan_community(
            self.vms['vm_b']['port'])

        if phase_name in ('phase3_vm_a_community_1',):
            self.assertEqual(
                COMMUNITY_1, vm_a_community,
                'vm_a should be in %s after phase 3 update' % COMMUNITY_1)
            self.assertEqual(
                COMMUNITY_1, vm_b_community,
                'vm_b should remain in %s' % COMMUNITY_1)
            self.assertEqual(
                vm_a_community, vm_b_community,
                'vm_a and vm_b should share the same pvlan_community')
        elif phase_name in ('phase4_vm_a_community_2',):
            self.assertEqual(
                COMMUNITY_2, vm_a_community,
                'vm_a should be in %s after phase 4 update' % COMMUNITY_2)
            self.assertEqual(
                COMMUNITY_1, vm_b_community,
                'vm_b should remain in %s' % COMMUNITY_1)
            self.assertNotEqual(
                vm_a_community, vm_b_community,
                'vm_a and vm_b must be in different pvlan_community values')

    def _verify_ports_pvlan(self, expected_by_vm, phase_name):
        for vm_name, expected_attrs in expected_by_vm.items():
            with self.subTest(phase=phase_name, port=vm_name):
                port_id = self.vms[vm_name]['port']['id']
                port = self._assert_port_pvlan(
                    port_id, vm_name, expected_attrs)
                self.vms[vm_name]['port'] = port
        self._assert_phase_community_relationships(phase_name)

    def _update_port_pvlan(self, vm_name, phase_name, expected_by_vm,
                           **update_kwargs):
        port_id = self.vms[vm_name]['port']['id']
        body = self.client.update_port(port_id, **update_kwargs)
        self.vms[vm_name]['port'] = body['port']
        self._verify_ports_pvlan(expected_by_vm, phase_name)

    def _check_icmp(self, src_name, dst_name, should_succeed):
        src = self.vms[src_name]
        dst_ip = self.vms[dst_name]['ip']
        self.check_remote_connectivity(
            src['ssh'], dst_ip,
            should_succeed=should_succeed,
            servers=self.all_servers,
            ping_count=3)

    def _check_connectivity_matrix(self, phase_name, matrix):
        for case_num, (src, dst, allowed) in enumerate(matrix, start=1):
            with self.subTest(phase=phase_name, case=case_num,
                              src=src, dst=dst, allowed=allowed):
                LOG.info(
                    'PVLAN phase %s case %s: %s -> %s (allow=%s)',
                    phase_name, case_num, src, dst, allowed)
                self._check_icmp(src, dst, allowed)

    @decorators.idempotent_id('a8f3c2e1-4b5d-6e7f-8a9b-0c1d2e3f4a5b')
    def test_pvlan_three_vm_role_transitions(self):
        """Exercise PVLAN segmentation with three VMs and port role updates."""
        # Phase 1: promiscuous, community, isolated.
        self._verify_ports_pvlan(EXPECTED_PORT_PVLAN_PHASE1, 'phase1_initial')
        self._check_connectivity_matrix(
            'prom_comm_iso', PHASE1_PROM_COMM_ISO)

        # Phase 2: vm_a promiscuous -> isolated.
        self._update_port_pvlan(
            'vm_a', 'phase2_vm_a_isolated', EXPECTED_PORT_PVLAN_PHASE2,
            pvlan_type=pvlan_const.ISOLATED_TYPE)
        self._check_connectivity_matrix(
            'vm_a_isolated', PHASE2_VM_A_ISOLATED)

        # Phase 3: vm_a isolated -> community_1 (same as vm_b).
        self._update_port_pvlan(
            'vm_a', 'phase3_vm_a_community_1', EXPECTED_PORT_PVLAN_PHASE3,
            pvlan_type=pvlan_const.COMMUNITY_TYPE,
            pvlan_community=COMMUNITY_1)
        self._check_connectivity_matrix(
            'vm_a_comm_same', PHASE3_VM_A_COMM_SAME)

        # Phase 4: vm_a community_1 -> community_2.
        self._update_port_pvlan(
            'vm_a', 'phase4_vm_a_community_2', EXPECTED_PORT_PVLAN_PHASE4,
            pvlan_community=COMMUNITY_2)
        self._check_connectivity_matrix(
            'vm_a_comm_diff', PHASE4_VM_A_COMM_DIFF)
