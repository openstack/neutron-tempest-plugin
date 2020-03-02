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

from tempest.common import utils
from tempest.lib import decorators

from neutron_tempest_plugin.common import ssh
from neutron_tempest_plugin import config
from neutron_tempest_plugin.scenario import base

CONF = config.CONF


class InternalDNSTest(base.BaseTempestTestCase):

    @utils.requires_ext(extension="dns-integration", service="network")
    @decorators.idempotent_id('988347de-07af-471a-abfa-65aea9f452a6')
    def test_dns_domain_and_name(self):
        """Test the ability to ping a VM's hostname from another VM.

        1) Create two VMs on the same network, giving each a name
        2) SSH in to the first VM:
          2.1) ping the other VM's internal IP
          2.2) ping the other VM's hostname
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
        self.wait_for_server_active(leia['server'])

        ssh_client = ssh.Client(
            self.fip['floating_ip_address'],
            CONF.validation.image_ssh_user,
            pkey=self.keypair['private_key'])

        self.assertIn('luke', ssh_client.exec_command('hostname'))

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
        self.assertIn('openstackgate.local', resolv_conf)
        self.assertNotIn('starwars', resolv_conf)

        self.check_remote_connectivity(ssh_client, 'leia',
                                       servers=[self.server, leia])
        self.check_remote_connectivity(ssh_client, 'leia.openstackgate.local',
                                       servers=[self.server, leia])
