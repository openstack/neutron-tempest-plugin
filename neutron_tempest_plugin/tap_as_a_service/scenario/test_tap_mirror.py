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
        # Create GRE mirror, as tcpdump cant extract ERSPAN
        # it is just visible as a type of GRE traffic.
        # direction IN and that the test pings from vm0 to vm1
        # means that ICMP echo request will be in the dump.
        # 101 as tunnel id means that we will see 0x65 as key
        tap_mirror = self.tap_mirrors_client.create_tap_mirror(
            name=data_utils.rand_name("tap_mirror"),
            port_id=vm1_port['id'],
            directions={'IN': '101', 'OUT': '102'},
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
