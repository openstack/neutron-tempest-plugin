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

from oslo_concurrency import lockutils
from oslo_log import log as logging

from neutron_tempest_plugin.common import ip
from neutron_tempest_plugin.common import shell
from neutron_tempest_plugin.common import ssh
from neutron_tempest_plugin import config
from neutron_tempest_plugin import exceptions

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
        # ``IPCommand`` runs commands locally when ssh_client is None and
        # remotely (on the VTEP host) otherwise.
        self._ip_cmd = ip.IPCommand(ssh_client=self._ssh_client)

    def _run_vtysh(self, config):
        LOG.debug('EVPNVNIProvisioner vtysh config:\n%s', config)
        # Write the config to a temporary file and apply it with vtysh, one
        # step at a time through shell.execute so it works both locally and
        # remotely.
        tmpf = shell.execute("mktemp --suffix=.conf",
                             ssh_client=self._ssh_client).stdout.strip()
        shell.execute("cat > %s << 'EVPN_EOF'\n%s\nEVPN_EOF" % (tmpf, config),
                      ssh_client=self._ssh_client)
        shell.execute("sudo vtysh -f %s" % tmpf, ssh_client=self._ssh_client)
        shell.execute('sudo vtysh -c "write memory"',
                      ssh_client=self._ssh_client)

    def _create_vni_unlocked(self, vni):
        LOG.info('Creating EVPN VNI %d infrastructure', vni)
        vrf = 'evpnvrf-%d' % vni
        bridge = 'br-%d' % vni
        vxlan = 'vxlan-%d' % vni

        self._ip_cmd.add_link(name=vrf, link_type='vrf', table=vni)
        self._ip_cmd.set_link(device=vrf, state='up')
        self._ip_cmd.add_link(name=bridge, link_type='bridge')
        self._ip_cmd.set_link(device=bridge, master=vrf)
        self._ip_cmd.add_link(
            name=vxlan, link_type='vxlan', segmentation_id=vni,
            local=self.vtep_ip, dstport=self.vxlan_port, nolearning=True)
        self._ip_cmd.set_link(device=vxlan, master=bridge)
        shell.execute(
            'sudo bridge link set dev %s neigh_suppress on' % vxlan,
            ssh_client=self._ssh_client)
        self._ip_cmd.set_link(device=bridge, state='up')
        self._ip_cmd.set_link(device=vxlan, state='up')
        self._ip_cmd.add_address(address='%s/32' % self.datapath_ip,
                             device=bridge)

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
                self._ip_cmd.delete_link(dev)
            except exceptions.ShellCommandFailed:
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
