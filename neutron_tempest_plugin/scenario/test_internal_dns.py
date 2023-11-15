# Copyright 2018 Red Hat, Inc.
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

from oslo_log import log
from tempest.common import utils
from tempest.lib.common.utils import data_utils
from tempest.lib import decorators

from neutron_tempest_plugin.common import ssh
from neutron_tempest_plugin import config
from neutron_tempest_plugin.scenario import base

CONF = config.CONF
LOG = log.getLogger(__name__)


class InternalDNSBase(base.BaseTempestTestCase):
    """Base class of useful resources and functionalities for test class."""

    port_error_msg = ('Openstack command returned incorrect '
                      'hostname value in port.')
    ssh_error_msg = ('Remote shell command returned incorrect hostname value '
                     "(command: 'hostname' OR 'cat /etc/hostname').")

    @staticmethod
    def _rand_name(name):
        """'data_utils.rand_name' wrapper, show name related to test suite."""
        return data_utils.rand_name(f'internal-dns-test-{name}')

    @classmethod
    def resource_setup(cls):
        super(InternalDNSBase, cls).resource_setup()
        cls.router = cls.create_router_by_client()
        cls.keypair = cls.create_keypair(
            name=cls._rand_name('shared-keypair'))
        cls.secgroup = cls.create_security_group(
            name=cls._rand_name('shared-secgroup'))
        cls.security_groups.append(cls.secgroup)
        cls.create_loginable_secgroup_rule(
            secgroup_id=cls.secgroup['id'])
        cls.vm_kwargs = {
            'flavor_ref': CONF.compute.flavor_ref,
            'image_ref': CONF.compute.image_ref,
            'key_name': cls.keypair['name'],
            'security_groups': [{'name': cls.secgroup['name']}]
        }

    def _create_ssh_client(self, ip_addr):
        return ssh.Client(ip_addr,
                          CONF.validation.image_ssh_user,
                          pkey=self.keypair['private_key'])

    def _validate_port_dns_details(self, checked_hostname, checked_port):
        """Validates reused objects for correct dns values in tests."""
        dns_details = checked_port['dns_assignment'][0]
        self.assertEqual(checked_hostname, checked_port['dns_name'],
                         self.port_error_msg)
        self.assertEqual(checked_hostname, dns_details['hostname'],
                         self.port_error_msg)
        self.assertIn(checked_hostname, dns_details['fqdn'],
                      self.port_error_msg)

    def _validate_ssh_dns_details(self, checked_hostname, ssh_client):
        """Validates correct dns values returned from ssh command in tests."""
        ssh_output = ssh_client.get_hostname()
        self.assertIn(checked_hostname, ssh_output, self.ssh_error_msg)


class InternalDNSTest(InternalDNSBase):
    """Tests internal DNS capabilities."""
    credentials = ['primary', 'admin']

    @utils.requires_ext(extension="dns-integration", service="network")
    @decorators.idempotent_id('988347de-07af-471a-abfa-65aea9f452a6')
    def test_dns_domain_and_name(self):
        """Test the ability to ping a VM's hostname from another VM.

        1) Create two VMs on the same network, giving each a name
        2) SSH in to the first VM:
            - ping the other VM's internal IP
            - ping the other VM's hostname
        """
        network = self.create_network(dns_domain='starwars.')
        self.setup_network_and_server(network=network, server_name='luke')
        self.create_pingable_secgroup_rule(
            secgroup_id=self.security_groups[-1]['id'])
        self.check_connectivity(self.fip['floating_ip_address'],
                                CONF.validation.image_ssh_user,
                                self.keypair['private_key'])

        leia = self.create_server(
            flavor_ref=CONF.compute.flavor_ref,
            image_ref=CONF.compute.image_ref,
            key_name=self.keypair['name'],
            networks=[{'uuid': self.network['id']}],
            security_groups=[
                {'name': self.security_groups[-1]['name']}],
            name='leia')

        ssh_client = ssh.Client(
            self.fip['floating_ip_address'],
            CONF.validation.image_ssh_user,
            pkey=self.keypair['private_key'])

        self.assertIn('luke', ssh_client.get_hostname())

        leia_port = self.client.list_ports(
            network_id=self.network['id'],
            device_id=leia['server']['id'])['ports'][0]

        # Ping with a higher timeout because spawning 2 VMs in some
        # environment can put significant load on the deployment, resulting
        # in very long boot times.
        self.check_remote_connectivity(
            ssh_client, leia_port['fixed_ips'][0]['ip_address'],
            timeout=CONF.validation.ping_timeout * 10,
            servers=[self.server, leia])

        resolv_conf = ssh_client.exec_command('cat /etc/resolv.conf')
        dns_domain = CONF.neutron_plugin_options.dns_domain
        self.assertIn(dns_domain, resolv_conf)
        self.assertNotIn('starwars', resolv_conf)

        self.check_remote_connectivity(ssh_client, 'leia',
                                       servers=[self.server, leia])
        self.check_remote_connectivity(ssh_client, 'leia.' + dns_domain,
                                       servers=[self.server, leia])

    @utils.requires_ext(extension="dns-integration", service="network")
    @decorators.idempotent_id('db5e612f-f17f-4974-b5f1-9fe89f4a6fc9')
    def test_create_and_update_port_with_dns_name(self):
        """Test creation of port with correct internal dns-name (hostname)."""

        # 1) Create resources: network, subnet, etc.
        # 2) Create a port with wrong dns-name (not as VM name).
        # 3) Verify that wrong port initial dns-name.
        #    was queried from openstack API.
        # 4) Update the port with correct dns-name (as VM name).
        # 5) Boot a VM with corrected predefined port.
        # 6) Verify that correct port dns-name
        #    was queried from openstack API.
        # 7) Validate hostname configured on VM is same as VM's name.

        # NOTE: VM's hostname has to be the same as VM's name
        #       when a VM is created, it is a known limitation.
        #       Therefore VM's dns-name/hostname is checked to be as VM's name.

        vm_correct_name = self._rand_name('vm')
        vm_wrong_name = self._rand_name('bazinga')
        # create resources
        network = self.create_network(name=self._rand_name('network'))
        subnet = self.create_subnet(network, name=self._rand_name('subnet'))
        self.create_router_interface(self.router['id'], subnet['id'])
        # create port with wrong dns-name (not as VM name)
        dns_port = self.create_port(network,
                                    dns_name=vm_wrong_name,
                                    security_groups=[self.secgroup['id']],
                                    name=self._rand_name('port'))
        # validate dns port with wrong initial hostname from API
        self._validate_port_dns_details(vm_wrong_name, dns_port)
        # update port with correct dns-name (as VM name)
        dns_port = self.update_port(dns_port, dns_name=vm_correct_name)
        # create VM with correct predefined dns-name on port
        vm_1 = self.create_server(name=vm_correct_name,
                                  networks=[{'port': dns_port['id']}],
                                  **self.vm_kwargs)
        # validate dns port with correct changed hostname using API
        self._validate_port_dns_details(vm_correct_name, dns_port)
        # validate hostname configured on VM is same as VM's name.
        vm_1['fip'] = self.create_floatingip(port=dns_port)
        vm_1['ssh_client'] = self._create_ssh_client(
            vm_1['fip']['floating_ip_address'])
        self._validate_ssh_dns_details(vm_correct_name, vm_1['ssh_client'])
