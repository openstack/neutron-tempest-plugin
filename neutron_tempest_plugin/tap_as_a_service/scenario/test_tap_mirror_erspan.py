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

import re
import socket

from tempest.common import utils
from tempest import config
from tempest.lib.common.utils import data_utils
from tempest.lib import decorators

from neutron_tempest_plugin.tap_as_a_service.scenario import manager
from neutron_tempest_plugin.tap_as_a_service.scenario import test_tap_mirror

CONF = config.CONF


class TestTapMirrorErspan(manager.BaseTaasScenarioTests):
    """Scenario tests for tap mirror using the ERSPAN protocol (erspanv1).

    ERSPAN runs over GRE with protocol 0x88be.  Unlike plain GRE tap mirrors,
    ERSPAN frames carry no GRE tunnel key, so direction is verified by decoding
    the inner mirrored frame (ICMP type: 8=request for IN, 0=reply for OUT).
    """

    @classmethod
    @utils.requires_ext(extension='security-group', service='network')
    @utils.requires_ext(extension='tap-mirror', service='network')
    def skip_checks(cls):
        super().skip_checks()
        # resource_setup boots the monitor VMs (advanced/taas cloud image)
        # for the whole class up front, so this has to be checked here
        # rather than per-test: by the time a per-test skipUnless would
        # run, resource_setup has already tried (and failed) to boot them.
        if not (CONF.neutron_plugin_options.advanced_image_ref or
                CONF.neutron_plugin_options.default_image_is_advanced):
            raise cls.skipException(
                "Advanced image is required to run this test.")

    @classmethod
    def resource_setup(cls):
        super().resource_setup()
        test_tap_mirror._serialize_topology_lifetime(cls)
        cls.keypair = cls.create_keypair()
        cls.secgroup = cls.create_security_group(
            name=data_utils.rand_name('secgroup'))
        cls.create_loginable_secgroup_rule(secgroup_id=cls.secgroup['id'])
        cls.create_pingable_secgroup_rule(secgroup_id=cls.secgroup['id'])
        test_tap_mirror._create_shared_topology(cls)

    @classmethod
    def resource_cleanup(cls):
        test_tap_mirror._cleanup_shared_servers(cls)
        super().resource_cleanup()

    @staticmethod
    def _decode_erspan_packets(tcpdump_output):
        """Parse ``tcpdump -vvv -n -XX proto GRE`` text output.

        Returns a list of (src_ip, dst_ip, proto_name, icmp_type_or_None,
        session_id) for every ERSPAN frame containing a decodable inner
        IPv4/IPv6 packet. ``session_id`` is the 10-bit Session ID field
        from the ERSPAN Type II header (bytes 2-3 of that header: low 2
        bits of byte 2 are the high bits of session_id, byte 3 is the
        low 8 bits), or None if the header wasn't ERSPAN Type II. OVN
        writes each mirror's tunnel_id directly into this field, so it
        can be used to attribute a packet to a specific mirror, the same
        way GRE tap mirrors are attributed via their tunnel key.
        """
        def _try_decode(raw):
            try:
                offset = 14 * ((raw[12] << 8 | raw[13]) == 0x0800 and
                               (raw[14] >> 4) == 4)
                if not ((raw[offset] >> 4) == 4 and raw[offset + 9] == 47):
                    return None
                offset += (raw[offset] & 0xf) * 4
                gre_flags = raw[offset] << 8 | raw[offset + 1]
                if not ((raw[offset + 2] << 8 | raw[offset + 3]) == 0x88be):
                    return None
                offset += 4 + 4 * bin(gre_flags & 0xb000).count('1')
                erspan_hdr_offset = offset
                is_erspan_v1 = (raw[offset] >> 4) == 1
                session_id = None
                if is_erspan_v1:
                    session_id = ((raw[erspan_hdr_offset + 2] & 0x03) << 8 |
                                  raw[erspan_hdr_offset + 3])
                offset += 8 * is_erspan_v1
                ethertype = raw[offset + 12] << 8 | raw[offset + 13]
                offset += 14
                if ethertype == 0x0800:
                    if not ((raw[offset] >> 4) == 4):
                        return None
                    proto_num = raw[offset + 9]
                    src = socket.inet_ntoa(raw[offset + 12:offset + 16])
                    dst = socket.inet_ntoa(raw[offset + 16:offset + 20])
                    proto = {1: 'ICMP', 6: 'TCP', 17: 'UDP'}.get(
                        proto_num, str(proto_num))
                    ihl = (raw[offset] & 0xf) * 4
                    icmp_type = raw[offset + ihl] if proto_num == 1 else None
                elif ethertype == 0x86dd:
                    if not ((raw[offset] >> 4) == 6):
                        return None
                    proto_num = raw[offset + 6]
                    src = socket.inet_ntop(
                        socket.AF_INET6, raw[offset + 8:offset + 24])
                    dst = socket.inet_ntop(
                        socket.AF_INET6, raw[offset + 24:offset + 40])
                    proto = {58: 'ICMPv6', 6: 'TCP', 17: 'UDP'}.get(
                        proto_num, str(proto_num))
                    icmp_type = raw[offset + 40] if proto_num == 58 else None
                else:
                    return None
                return (src, dst, proto, icmp_type, session_id)
            except (IndexError, ValueError, OSError):
                # Truncated/malformed frames can slice short of the
                # expected length without raising IndexError (e.g. a
                # 3-byte IP slice), which inet_ntoa/inet_ntop then reject
                # with ValueError/OSError. Skip undecodable packets.
                return None

        packets = []
        current_bytes = []

        for line in tcpdump_output.splitlines():
            if re.match(r'\s+0x[0-9a-f]{4}:', line):
                hex_part = re.split(
                    r'\s{2,}', line.split(':', 1)[1].strip())[0]
                current_bytes += [
                    int(g[i:i + 2], 16) for g in hex_part.split()
                    for i in range(0, len(g) - 1, 2)]
            elif current_bytes:
                packets.append(bytes(current_bytes))
                current_bytes = []

        if current_bytes:
            packets.append(bytes(current_bytes))

        return [r for p in packets if (r := _try_decode(p))]

    def _assert_erspan_sessions(self, output, expected):
        """Decode output and assert every expected (pkt, session_id) is there.

        :param expected: {session_id: [icmp_tuple, ...]}, where icmp_tuple
            is (src_ip, dst_ip, proto_name, icmp_type) as returned by
            _decode_erspan_packets minus the trailing session_id.
        """
        self.assertIn('gre-proto-0x88be', output)
        decoded = self._decode_erspan_packets(output)
        self.assertTrue(
            decoded, "No inner packets decoded from ERSPAN capture")
        for session_id, packets in expected.items():
            for pkt in packets:
                self.assertIn(
                    pkt + (session_id,), decoded,
                    "session %d missing %s" % (session_id, pkt))

    @decorators.idempotent_id('efc8821e-eb3a-4dfc-9fd7-507bb3bfdd57')
    def test_tap_mirror_erspan_connectivity(self):
        """Test that an erspanv1 tap mirror delivers mirrored ICMP traffic.

        .. code-block:: HTML

               +------------+
               | Monitor VM |
               |   FIP      |
               +-----+------+
                     |
               +-----+------+
               |   NetMon   |
               +------------+

               +-------------------+
               |       Net0        |
               +---+----------+----+
                   |          |
               +---+-+      +-+---+
               | VM0 |      | VM1 |
               +-----+      +-----+

        VM1's port is mirrored via ERSPAN v1 (both IN and OUT) to the monitor
        VM's FIP.  VM0 pings VM1, causing ICMP echo requests (IN, type=8) and
        echo replies (OUT, type=0) to cross VM1's mirrored port.
        """
        result = test_tap_mirror._run_tap_mirror_connectivity(
            self, mirror_type='erspanv1')
        vm0_ip = result['vm0_ip']
        vm1_ip = result['vm1_ip']
        directions = result['directions']

        request = (vm0_ip, vm1_ip, 'ICMP', 8)
        reply = (vm1_ip, vm0_ip, 'ICMP', 0)
        expected = {101: [request], 102: [reply]}
        if 'BOTH' in directions:
            expected[103] = [request, reply]
        self._assert_erspan_sessions(result['output'], expected)

    @decorators.idempotent_id('3a0e56b8-805a-46aa-9131-5273ca92b48c')
    def test_tap_mirror_erspan_ipv6_connectivity(self):
        """Test that an erspanv1 tap mirror delivers mirrored ICMPv6 traffic.

        .. code-block:: HTML

               +------------+
               | Monitor VM |
               |   FIP      |
               +-----+------+
                     |
               +-----+------+
               |   NetMon   |
               +------------+

               +-------------------+
               |   Net0 (v4+v6)    |
               +---+----------+----+
                   |          |
               +---+-+      +-+---+
               | VM0 |      | VM1 |
               +-----+      +-----+

        VM1's port is mirrored via ERSPAN v1 (IN, OUT, BOTH) to the monitor
        VM's FIP.  VM0 pings VM1 over IPv6, causing ICMPv6 echo requests
        (IN, type=128) and echo replies (OUT, type=129) across VM1's port.
        """
        result = test_tap_mirror._run_ipv6_connectivity(
            self, mirror_type='erspanv1')
        vm0_ipv6 = result['vm0_ipv6']
        vm1_ipv6 = result['vm1_ipv6']
        directions = result['directions']

        request = (vm0_ipv6, vm1_ipv6, 'ICMPv6', 128)
        reply = (vm1_ipv6, vm0_ipv6, 'ICMPv6', 129)
        expected = {101: [request], 102: [reply]}
        if 'BOTH' in directions:
            expected[103] = [request, reply]
        self._assert_erspan_sessions(result['output'], expected)

    @decorators.idempotent_id('7f6a1e3c-4b2d-4a8e-9c1f-2d3e4f5a6b7c')
    def test_two_source_one_dest_erspan_mirror(self):
        """Test traffic from 2 src VMs mirrored via ERSPAN to 1 dest VM.

        .. code-block:: HTML

               +------------+
               | Monitor VM |
               |   FIP      |
               +-----+------+
                     |
               +-----+------+
               |   NetMon   |
               +------------+
               +-------------------+
               |       Net0        |
               +---+----------+----+
                   |          |
               +---+-+      +-+---+
               | VM0 |      | VM1 |
               +-----+      +-----+

        Both VM0 and VM1 source ports are mirrored via independent erspanv1
        tap mirrors to the same monitor VM remote IP. VM0 pings VM1;
        per-mirror, per-direction delivery is verified via the ERSPAN
        Session ID field (see _decode_erspan_packets docstring).
        """
        if not self.is_driver_ovn:
            raise self.skipException("Test is supported only in OVN")

        result = test_tap_mirror._run_two_source_one_dest_mirror(
            self, mirror_type='erspanv1')
        vm0_ip = result['vm0_ip']
        vm1_ip = result['vm1_ip']
        directions_vm0 = result['directions_vm0']
        directions_vm1 = result['directions_vm1']

        # REQUEST = echo request (vm0->vm1, type 8);
        # REPLY = echo reply (vm1->vm0, type 0).
        request = (vm0_ip, vm1_ip, 'ICMP', 8)
        reply = (vm1_ip, vm0_ip, 'ICMP', 0)
        expected = {
            101: [reply],    # vm0 IN
            102: [request],  # vm0 OUT
            103: [request],  # vm1 IN
            104: [reply],    # vm1 OUT
        }
        if 'BOTH' in directions_vm0:
            expected[105] = [request, reply]
        if 'BOTH' in directions_vm1:
            expected[106] = [request, reply]
        self._assert_erspan_sessions(result['output'], expected)

    @decorators.idempotent_id('9a1c2e4f-6b3d-48a0-9e7f-1c4d5e6f7a8b')
    def test_one_source_two_dest_erspan_mirror(self):
        """Test traffic from 1 src VM mirrored via ERSPAN to 2 dest VMs.

        .. code-block:: HTML

               +-------------+   +-------------+
               | Monitor VM1 |   | Monitor VM2 |
               |   FIP       |   |   FIP       |
               +------+------+   +------+------+
                      |                 |
               +------+------+   +------+------+
               |   NetMon1   |   |   NetMon2   |
               +-------------+   +-------------+
               +-------------------+
               |       Net0        |
               +---+----------+----+
                   |          |
               +---+-+      +-+---+
               | VM0 |      | VM1 |
               +-----+      +-----+

        vm0_port is mirrored via two independent erspanv1 mirrors to two
        different monitor VMs, using disjoint tunnel_id ranges.
        """
        if not self.is_driver_ovn:
            raise self.skipException("Test is supported only in OVN")

        result = test_tap_mirror._run_one_source_two_dest_mirror(
            self, mirror_type='erspanv1')
        vm0_ip = result['vm0_ip']
        vm1_ip = result['vm1_ip']
        directions1 = result['directions1']
        directions2 = result['directions2']

        request = (vm0_ip, vm1_ip, 'ICMP', 8)
        reply = (vm1_ip, vm0_ip, 'ICMP', 0)
        expected1 = {101: [reply], 102: [request]}
        if 'BOTH' in directions1:
            expected1[105] = [request, reply]
        expected2 = {103: [reply], 104: [request]}
        if 'BOTH' in directions2:
            expected2[106] = [request, reply]
        # output -> expected ICMP tuples for that monitor's mirror
        expected_by_output = {
            result['output1']: expected1,
            result['output2']: expected2,
        }
        for output, expected in expected_by_output.items():
            self._assert_erspan_sessions(output, expected)
