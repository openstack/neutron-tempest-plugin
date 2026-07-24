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

import subprocess
import tempfile

from oslo_concurrency import lockutils
from oslo_log import log as logging
from tempest.lib import exceptions as lib_exc

from neutron_tempest_plugin.common import ssh
from neutron_tempest_plugin import config

CONF = config.CONF

LOG = logging.getLogger(__name__)

_FRR_CREATE_TEMPLATE = """\
vrf evpnvrf-{vni}
 vni {vni}
exit-vrf
!
router bgp {asn} vrf evpnvrf-{vni}
 no bgp ebgp-requires-policy
 address-family ipv4 unicast
  redistribute kernel
  redistribute connected
 exit-address-family
!
 address-family ipv6 unicast
  redistribute kernel
  redistribute connected
 exit-address-family
!
 address-family l2vpn evpn
  advertise ipv4 unicast
  advertise ipv6 unicast
  route-target import {peer_asn}:{vni}
 exit-address-family
exit
!
router bgp {asn}
 address-family ipv4 unicast
  import vrf evpnvrf-{vni}
 exit-address-family
exit
"""

_FRR_DELETE_TEMPLATE = """\
router bgp {asn}
 address-family ipv4 unicast
  no import vrf evpnvrf-{vni}
 exit-address-family
exit
!
vrf evpnvrf-{vni}
 no vni {vni}
exit-vrf
!
no router bgp {asn} vrf evpnvrf-{vni}
!
no vrf evpnvrf-{vni}
"""


class EVPNVNIProvisioner:
    """Provisions EVPN VNI infrastructure on the test machine.

    Creates Linux VRF + bridge + VXLAN interfaces and configures
    FRR with EVPN extension of BGP router.
    """

    _COUNTER_FILE = '/tmp/evpn-vni-counter'

    def __init__(self, vtep_ip, datapath_ip, vxlan_port=4789,
                 asn=65000, peer_asn=64999,
                 vni_range_start=1000, vni_range_end=1100):
        self.vtep_ip = vtep_ip
        self.datapath_ip = datapath_ip
        self.vxlan_port = vxlan_port
        self.asn = asn
        self.peer_asn = peer_asn
        self._vni_range_start = vni_range_start
        self._vni_range_end = vni_range_end
        opts = CONF.neutron_plugin_options
        if opts.evpn_vtep_host:
            self._ssh_client = ssh.Client(
                opts.evpn_vtep_host,
                opts.evpn_vtep_username,
                key_filename=opts.evpn_vtep_keyfile)
        else:
            self._ssh_client = None

    def _run(self, cmd):
        full_cmd = 'sudo ' + ' '.join(cmd)
        LOG.debug('EVPNVNIProvisioner: %s', full_cmd)
        if self._ssh_client:
            self._ssh_client.exec_command(full_cmd)
        else:
            subprocess.run(
                ['sudo'] + cmd,
                check=True, capture_output=True, text=True)

    def _run_vtysh(self, config):
        LOG.debug('EVPNVNIProvisioner vtysh config:\n%s', config)
        if self._ssh_client:
            tmpf = self._ssh_client.exec_command(
                'mktemp --suffix=.conf').strip()
            self._ssh_client.exec_command(
                "cat > %s << 'EVPN_EOF'\n%s\nEVPN_EOF" % (tmpf, config))
            self._ssh_client.exec_command(
                'sudo vtysh -f %s' % tmpf)
            self._ssh_client.exec_command(
                'sudo vtysh -c "write memory"')
        else:
            with tempfile.NamedTemporaryFile(
                    mode='w', suffix='.conf', delete=True) as f:
                f.write(config)
                f.flush()
                subprocess.run(
                    ['/usr/bin/sudo', 'vtysh', '-f', f.name],
                    check=True, capture_output=True, text=True)
                subprocess.run(
                    ['/usr/bin/sudo', 'vtysh', '-c', 'write memory'],
                    check=True, capture_output=True, text=True)

    def _create_vni_unlocked(self, vni):
        LOG.info('Creating EVPN VNI %d infrastructure', vni)
        vrf = 'evpnvrf-%d' % vni
        bridge = 'br-%d' % vni
        vxlan = 'vxlan-%d' % vni

        self._run(
            ['ip', 'link', 'add', vrf,
             'type', 'vrf', 'table', str(vni)])
        self._run(['ip', 'link', 'set', vrf, 'up'])
        self._run(['ip', 'link', 'add', bridge, 'type', 'bridge'])
        self._run(['ip', 'link', 'set', bridge, 'master', vrf])
        self._run(
            ['ip', 'link', 'add', vxlan,
             'type', 'vxlan', 'id', str(vni),
             'local', self.vtep_ip,
             'dstport', str(self.vxlan_port), 'nolearning'])
        self._run(['ip', 'link', 'set', vxlan, 'master', bridge])
        self._run(
            ['bridge', 'link', 'set', 'dev', vxlan,
             'neigh_suppress', 'on'])
        self._run(['ip', 'link', 'set', bridge, 'up'])
        self._run(['ip', 'link', 'set', vxlan, 'up'])
        self._run(
            ['ip', 'addr', 'add',
             '%s/32' % self.datapath_ip, 'dev', bridge])

        self._run_vtysh(_FRR_CREATE_TEMPLATE.format(
            vni=vni, asn=self.asn, peer_asn=self.peer_asn))

    @lockutils.synchronized('evpn-vni-provisioner', external=True,
                            lock_path='/tmp')
    def delete_vni(self, vni):
        LOG.info('Deleting EVPN VNI %d infrastructure', vni)
        # Delete kernel devices first (reverse of create). FRR rejects
        # "no vrf" while the VRF is still active / has an L3VNI tied to
        # live interfaces ("Only inactive VRFs can be deleted").
        for dev in ('vxlan-%d' % vni, 'br-%d' % vni, 'evpnvrf-%d' % vni):
            try:
                self._run(['ip', 'link', 'del', dev])
            except (subprocess.CalledProcessError,
                    lib_exc.SSHExecCommandFailed):
                LOG.warning('Failed to delete %s (may not exist)', dev)

        self._run_vtysh(_FRR_DELETE_TEMPLATE.format(
            vni=vni, asn=self.asn))

    def _next_vni(self):
        """Atomically read and increment the shared VNI counter file.

        The caller must hold the external lock.
        """
        try:
            with open(self._COUNTER_FILE) as f:
                vni = int(f.read().strip())
        except (FileNotFoundError, ValueError):
            vni = self._vni_range_start
        if vni > self._vni_range_end:
            raise RuntimeError(  # noqa: N534
                'EVPN VNI range exhausted (%d-%d)' % (
                    self._vni_range_start, self._vni_range_end))
        with open(self._COUNTER_FILE, 'w') as f:
            f.write(str(vni + 1))
        return vni

    @lockutils.synchronized('evpn-vni-provisioner', external=True,
                            lock_path='/tmp')
    def allocate_vni(self):
        vni = self._next_vni()
        self._create_vni_unlocked(vni)
        return vni
