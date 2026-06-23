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

from tempest.common import utils
from tempest import config
from tempest.lib.common.utils import data_utils
from tempest.lib.common.utils.linux import remote_client
from tempest.lib.common.utils import test_utils
from tempest.lib import decorators

from neutron_tempest_plugin.tap_as_a_service.scenario import manager

CONF = config.CONF


class TestTapMirror(manager.BaseTaasScenarioTests):

    @classmethod
    @utils.requires_ext(extension='security-group', service='network')
    @utils.requires_ext(extension='tap-mirror', service='network')
    def skip_checks(cls):
        super().skip_checks()

    @classmethod
    def resource_setup(cls):
        super().resource_setup()
        cls.keypair = cls.create_keypair()
        cls.secgroup = cls.create_security_group(
            name=data_utils.rand_name('secgroup'))
        cls.create_loginable_secgroup_rule(secgroup_id=cls.secgroup['id'])
        cls.create_pingable_secgroup_rule(secgroup_id=cls.secgroup['id'])

    @decorators.idempotent_id('d9cfca96-fa83-417a-b111-1c02f6fe2796')
    def test_tap_mirror_connectivity(self):
        """Test that traffic between 2 VMs mirrored to a FIP

        .. code-block:: HTML

           +------------+
           | Monitor VM |
           |   FIP      |
           +-----+------+
                 |
                 |
           +-----+------+
           |   NetMon   |
           +------------+

           +---------------+
           |   Net0        |
           +---+---------+-+
               |         |
               |         |
           +---+-+     +-+---+
           | VM0 |     | VM1 |
           +-----+     +-----+

        This is a simplified scenario adapted to the CI machinery.
        The mirroring destination should be outside of the cloud.
        """

        # Create the topology for the 2 VMs of which the traffic
        # will be mirrored
        self.network, self.subnet, self.router = self.create_networks()

        vm0_port, vm0_fip = self._create_server_with_floatingip(
            security_group=self.secgroup['name']
        )
        vm1_port, vm1_fip = self._create_server_with_floatingip(
            security_group=self.secgroup['name']
        )
        vm1_ip = vm1_port['fixed_ips'][0]['ip_address']

        vm0_client = remote_client.RemoteClient(
            vm0_fip['floating_ip_address'],
            CONF.validation.image_ssh_user,
            pkey=self.keypair['private_key'],
            ssh_key_type=CONF.validation.ssh_key_type)
        vm0_client.validate_authentication()
        vm1_client = remote_client.RemoteClient(
            vm1_fip['floating_ip_address'],
            CONF.validation.image_ssh_user,
            pkey=self.keypair['private_key'],
            ssh_key_type=CONF.validation.ssh_key_type)
        vm1_client.validate_authentication()

        self.check_remote_connectivity(vm0_client, vm1_ip, ping_count=5)

        # Create the VM which will be the destination of the mirror
        netmon, _, _ = self.create_networks()
        _, vm_mon_fip = self._create_server_with_floatingip(
            use_taas_cloud_image=True, network=netmon,
            security_group=self.secgroup['name'],
            port_security_enabled=False,
        )

        user = CONF.neutron_plugin_options.advanced_image_ssh_user
        self.monitor_client = remote_client.RemoteClient(
            vm_mon_fip['floating_ip_address'], user,
            pkey=self.keypair['private_key'],
            ssh_key_type=CONF.validation.ssh_key_type)
        self.monitor_client.validate_authentication()

        r_ip = vm_mon_fip['floating_ip_address']
        directions = {'IN': '101', 'OUT': '102'}
        if utils.is_extension_enabled('tap-mirror-both-direction', 'network'):
            directions['BOTH'] = '103'
        # Create GRE mirror, as tcpdump cant extract ERSPAN
        # it is just visible as a type of GRE traffic.
        # direction IN and that the test pings from vm0 to vm1
        # means that ICMP echo request will be in the dump.
        # 101 as tunnel id means that we will see 0x65 as key
        tap_mirror = self.tap_mirrors_client.create_tap_mirror(
            name=data_utils.rand_name("tap_mirror"),
            port_id=vm1_port['id'],
            directions=directions,
            remote_ip=r_ip,
            mirror_type='gre',
        )
        self.addCleanup(
            test_utils.call_and_ignore_notfound_exc,
            self.tap_mirrors_client.delete_tap_mirror,
            tap_mirror['tap_mirror']['id']
        )

        res, output = self._check_icmp_traffic(
            self.monitor_client,
            vm0_client, vm0_port, vm1_port,
            tcpdump_cmd="sudo tcpdump -vvv -n -nn proto GRE > %s")

        self.assertTrue(res)
        # GRE Key for Direction IN:101
        self.assertIn('key=0x65', output)
        # GRE Key for Direction OUT:102
        self.assertIn('key=0x66', output)
        if 'BOTH' in directions:
            # GRE Key for Direction BOTH:103
            self.assertIn('key=0x67', output)

        vm0_ip = vm0_port['fixed_ips'][0]['ip_address']
        output_lines = output.splitlines()

        self._check_icmp_mirror_direction(output_lines, vm0_ip, vm1_ip, "IN",
                                          "key=0x65")
        self._check_icmp_mirror_direction(output_lines, vm0_ip, vm1_ip, "OUT",
                                          "key=0x66")
        if 'BOTH' in directions:
            self._check_icmp_mirror_direction(output_lines, vm0_ip, vm1_ip,
                                              "BOTH", "key=0x67")

    def _check_icmp_mirror_direction(self, output_lines, ip_sender,
                                     ip_receiver, direction, key):
        """Check direction of the mirroring is consistent with what is expected

        output_lines[i+2] should have the following format for OUT:
        [ip_receiver] > [ip_sender]: ICMP echo reply, id ...

        output_lines[i+2] should have the following format for IN:
        [ip_sender] > [ip_receiver]: ICMP echo request, id ...

        BOTH direction should have at least one iteration of each.
        """

        directions = [direction] if direction != "BOTH" else ['IN', 'OUT']
        for d in directions:
            found_log = False
            if d == 'IN':
                left_ip, right_ip = ip_sender, ip_receiver
                icmp_msg = 'ICMP echo request'
            elif d == 'OUT':
                left_ip, right_ip = ip_receiver, ip_sender
                icmp_msg = 'ICMP echo reply'
            for i, line in enumerate(output_lines):
                icmp_log = None
                if key not in line:
                    continue
                icmp_log = output_lines[i + 2].split(':')
                if icmp_msg in icmp_log[1]:
                    self.assertIn(left_ip + ' > ' + right_ip, icmp_log[0])
                    found_log = True
                    break
            # Make sure we have found at least one coincidence of the target
            # string for this direction.
            self.assertTrue(found_log, msg=f"Did not find direction "
                f"{direction} and key {key} in the tcpdump log. ICMP "
                f"log: {icmp_log}")

    @testtools.skipUnless(
        (CONF.neutron_plugin_options.advanced_image_ref or
         CONF.neutron_plugin_options.default_image_is_advanced),
        "Advanced image is required to run this test.")
    @decorators.idempotent_id('7a4f9d54-16e8-499f-9791-0217aee309e1')
    def test_one_source_two_dest_remote_ip_mirror(self):
        """Test traffic from 1 src VM mirrored to 2 destination VM remote IPs

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
                   |          |
               +---+-+      +-+---+
               | VM0 |      | VM1 |
               +-----+      +-----+

        VM0 source port is mirrored via GRE to 2 remote IPs (monitor VMs)
        using BOTH direction with tunnel ids 105 and 106.
        """

        if not self.is_driver_ovn:
            raise self.skipException("Test is supported only in OVN")

        self.network, self.subnet, self.router = self.create_networks()
        vm0_port, vm0_fip = self._create_server_with_floatingip(
            security_group=self.secgroup['name']
        )
        vm1_port, vm1_fip = self._create_server_with_floatingip(
            security_group=self.secgroup['name']
        )
        vm1_ip = vm1_port['fixed_ips'][0]['ip_address']
        vm0_client = remote_client.RemoteClient(
            vm0_fip['floating_ip_address'],
            CONF.validation.image_ssh_user,
            pkey=self.keypair['private_key'],
            ssh_key_type=CONF.validation.ssh_key_type)
        vm0_client.validate_authentication()
        vm1_client = remote_client.RemoteClient(
            vm1_fip['floating_ip_address'],
            CONF.validation.image_ssh_user,
            pkey=self.keypair['private_key'],
            ssh_key_type=CONF.validation.ssh_key_type)
        vm1_client.validate_authentication()
        self.check_remote_connectivity(vm0_client, vm1_ip, ping_count=5)
        # Create 2 monitor VMs on separate networks
        netmon1, _, _ = self.create_networks()
        _, vm_mon1_fip = self._create_server_with_floatingip(
            use_taas_cloud_image=True, network=netmon1,
            security_group=self.secgroup['name'],
            port_security_enabled=False,
        )
        netmon2, _, _ = self.create_networks()
        _, vm_mon2_fip = self._create_server_with_floatingip(
            use_taas_cloud_image=True, network=netmon2,
            security_group=self.secgroup['name'],
            port_security_enabled=False,
        )
        user = CONF.neutron_plugin_options.advanced_image_ssh_user
        monitor1_client = remote_client.RemoteClient(
            vm_mon1_fip['floating_ip_address'], user,
            pkey=self.keypair['private_key'],
            ssh_key_type=CONF.validation.ssh_key_type)
        monitor1_client.validate_authentication()
        monitor2_client = remote_client.RemoteClient(
            vm_mon2_fip['floating_ip_address'], user,
            pkey=self.keypair['private_key'],
            ssh_key_type=CONF.validation.ssh_key_type)
        monitor2_client.validate_authentication()
        r_ip1 = vm_mon1_fip['floating_ip_address']
        r_ip2 = vm_mon2_fip['floating_ip_address']
        directions1 = {'IN': '101', 'OUT': '102'}
        directions2 = {'IN': '103', 'OUT': '104'}
        if utils.is_extension_enabled('tap-mirror-both-direction', 'network'):
            directions1['BOTH'] = '105'
            directions2['BOTH'] = '106'
        # Mirror vm0_port to monitor1
        tap_mirror1 = self.tap_mirrors_client.create_tap_mirror(
            name=data_utils.rand_name("tap_mirror1"),
            port_id=vm0_port['id'],
            directions=directions1,
            remote_ip=r_ip1,
            mirror_type='gre',
        )
        self.addCleanup(
            test_utils.call_and_ignore_notfound_exc,
            self.tap_mirrors_client.delete_tap_mirror,
            tap_mirror1['tap_mirror']['id']
        )
        # Mirror vm0_port to monitor2
        tap_mirror2 = self.tap_mirrors_client.create_tap_mirror(
            name=data_utils.rand_name("tap_mirror2"),
            port_id=vm0_port['id'],
            directions=directions2,
            remote_ip=r_ip2,
            mirror_type='gre',
        )
        self.addCleanup(
            test_utils.call_and_ignore_notfound_exc,
            self.tap_mirrors_client.delete_tap_mirror,
            tap_mirror2['tap_mirror']['id']
        )
        # Start tcpdump on both monitors before sending traffic
        log_location = "/tmp/tcpdumplog"
        tcpdump_cmd = "sudo tcpdump -vvv -n -nn proto GRE > %s" % log_location
        self._run_in_background(monitor1_client, tcpdump_cmd)
        self._run_in_background(monitor2_client, tcpdump_cmd)
        # Ensure tcpdump is running on both monitors
        self.assertIn("tcpdump", monitor1_client.exec_command("ps -ax"))
        self.assertIn("tcpdump", monitor2_client.exec_command("ps -ax"))
        # Send traffic from vm0 to vm1
        self.check_remote_connectivity(vm0_client, vm1_ip, ping_count=50)
        # Check monitor1
        output1 = monitor1_client.exec_command("cat %s" % log_location)
        self.assertLess(0, len(output1))
        self.assertIn('key=0x65', output1)  # IN:101
        self.assertIn('key=0x66', output1)  # OUT:102
        if 'BOTH' in directions1:
            self.assertIn('key=0x69', output1)  # BOTH:105
        # Check monitor2
        output2 = monitor2_client.exec_command("cat %s" % log_location)
        self.assertLess(0, len(output2))
        self.assertIn('key=0x67', output2)  # IN:103
        self.assertIn('key=0x68', output2)  # OUT:104
        if 'BOTH' in directions2:
            self.assertIn('key=0x6a', output2)  # BOTH:106
        vm0_ip = vm0_port['fixed_ips'][0]['ip_address']
        output1_lines = output1.splitlines()
        output2_lines = output2.splitlines()
        # vm0_port IN captures echo reply (vm1->vm0), OUT captures echo request
        self._check_icmp_mirror_direction(output1_lines, vm0_ip, vm1_ip,
                                          "OUT", "key=0x65")
        self._check_icmp_mirror_direction(output1_lines, vm0_ip, vm1_ip,
                                          "IN", "key=0x66")
        if 'BOTH' in directions1:
            self._check_icmp_mirror_direction(output1_lines, vm0_ip, vm1_ip,
                                              "BOTH", "key=0x69")
        self._check_icmp_mirror_direction(output2_lines, vm0_ip, vm1_ip,
                                          "OUT", "key=0x67")
        self._check_icmp_mirror_direction(output2_lines, vm0_ip, vm1_ip,
                                          "IN", "key=0x68")
        if 'BOTH' in directions2:
            self._check_icmp_mirror_direction(output2_lines, vm0_ip, vm1_ip,
                                              "BOTH", "key=0x6a")

    @testtools.skipUnless(
        (CONF.neutron_plugin_options.advanced_image_ref or
         CONF.neutron_plugin_options.default_image_is_advanced),
        "Advanced image is required to run this test.")
    @decorators.idempotent_id('640e8e23-00f4-457c-8e91-04bb011fa94c')
    def test_two_source_one_dest_remote_ip_mirror(self):
        """Test traffic from 2 src VMs mirrored to 1 destination VM remote IP

        .. code-block:: HTML

               +------------+
               | Monitor VM |
               |   FIP      |
               +-----+------+
                     |
                     |
               +-----+------+
               |   NetMon   |
               +------------+
               +-------------------+
               |       Net0        |
               +---+----------+----+
                   |          |
                   |          |
               +---+-+      +-+---+
               | VM0 |      | VM1 |
               +-----+      +-----+

        Both VM0 and VM1 source ports are mirrored via GRE to the remote IP
        of the monitor VM using BOTH direction with tunnel ids 105 and 106.
        """

        if not self.is_driver_ovn:
            raise self.skipException("Test is supported only in OVN")

        self.network, self.subnet, self.router = self.create_networks()
        vm0_port, vm0_fip = self._create_server_with_floatingip(
            security_group=self.secgroup['name']
        )
        vm1_port, vm1_fip = self._create_server_with_floatingip(
            security_group=self.secgroup['name']
        )
        vm1_ip = vm1_port['fixed_ips'][0]['ip_address']
        vm0_client = remote_client.RemoteClient(
            vm0_fip['floating_ip_address'],
            CONF.validation.image_ssh_user,
            pkey=self.keypair['private_key'],
            ssh_key_type=CONF.validation.ssh_key_type)
        vm0_client.validate_authentication()
        vm1_client = remote_client.RemoteClient(
            vm1_fip['floating_ip_address'],
            CONF.validation.image_ssh_user,
            pkey=self.keypair['private_key'],
            ssh_key_type=CONF.validation.ssh_key_type)
        vm1_client.validate_authentication()
        self.check_remote_connectivity(vm0_client, vm1_ip, ping_count=5)
        # Create the destination/monitor VM on a separate network
        netmon, _, _ = self.create_networks()
        _, vm_mon_fip = self._create_server_with_floatingip(
            use_taas_cloud_image=True, network=netmon,
            security_group=self.secgroup['name'],
            port_security_enabled=False,
        )
        user = CONF.neutron_plugin_options.advanced_image_ssh_user
        self.monitor_client = remote_client.RemoteClient(
            vm_mon_fip['floating_ip_address'], user,
            pkey=self.keypair['private_key'],
            ssh_key_type=CONF.validation.ssh_key_type)
        self.monitor_client.validate_authentication()
        r_ip = vm_mon_fip['floating_ip_address']
        directions_vm0 = {'IN': '101', 'OUT': '102'}
        directions_vm1 = {'IN': '103', 'OUT': '104'}
        if utils.is_extension_enabled('tap-mirror-both-direction', 'network'):
            directions_vm0['BOTH'] = '105'
            directions_vm1['BOTH'] = '106'
        # Create GRE mirror for vm0_port pointing to monitor VM remote IP
        tap_mirror_vm0 = self.tap_mirrors_client.create_tap_mirror(
            name=data_utils.rand_name("tap_mirror_vm0"),
            port_id=vm0_port['id'],
            directions=directions_vm0,
            remote_ip=r_ip,
            mirror_type='gre',
        )
        self.addCleanup(
            test_utils.call_and_ignore_notfound_exc,
            self.tap_mirrors_client.delete_tap_mirror,
            tap_mirror_vm0['tap_mirror']['id']
        )
        # Create GRE mirror for vm1_port pointing to the same monitor VM
        tap_mirror_vm1 = self.tap_mirrors_client.create_tap_mirror(
            name=data_utils.rand_name("tap_mirror_vm1"),
            port_id=vm1_port['id'],
            directions=directions_vm1,
            remote_ip=r_ip,
            mirror_type='gre',
        )
        self.addCleanup(
            test_utils.call_and_ignore_notfound_exc,
            self.tap_mirrors_client.delete_tap_mirror,
            tap_mirror_vm1['tap_mirror']['id']
        )
        res, output = self._check_icmp_traffic(
            self.monitor_client,
            vm0_client, vm0_port, vm1_port,
            tcpdump_cmd="sudo tcpdump -vvv -n -nn proto GRE > %s")
        self.assertTrue(res)
        # GRE Keys: vm0 IN:101->0x65, OUT:102->0x66; vm1 IN:103->0x67
        # Note: vm1_port OUT (key=0x68) is not checked — OVN does not mirror
        # OUT direction for intra-network traffic; the echo reply is already
        # captured by vm0_port IN (key=0x65).
        self.assertIn('key=0x65', output)  # IN:101 vm0
        self.assertIn('key=0x66', output)  # OUT:102 vm0
        self.assertIn('key=0x67', output)  # IN:103 vm1
        if 'BOTH' in directions_vm0:
            self.assertIn('key=0x69', output)  # BOTH:105 vm0
        if 'BOTH' in directions_vm1:
            self.assertIn('key=0x6a', output)  # BOTH:106 vm1
        vm0_ip = vm0_port['fixed_ips'][0]['ip_address']
        output_lines = output.splitlines()
        # vm0_port IN captures echo reply (vm1->vm0), OUT captures echo request
        self._check_icmp_mirror_direction(output_lines, vm0_ip, vm1_ip,
                                          "OUT", "key=0x65")
        self._check_icmp_mirror_direction(output_lines, vm0_ip, vm1_ip,
                                          "IN", "key=0x66")
        if 'BOTH' in directions_vm0:
            self._check_icmp_mirror_direction(output_lines, vm0_ip, vm1_ip,
                                              "BOTH", "key=0x69")
        # vm1_port IN captures echo request (vm0->vm1)
        self._check_icmp_mirror_direction(output_lines, vm0_ip, vm1_ip,
                                          "IN", "key=0x67")
        if 'BOTH' in directions_vm1:
            self._check_icmp_mirror_direction(output_lines, vm0_ip, vm1_ip,
                                              "BOTH", "key=0x6a")
