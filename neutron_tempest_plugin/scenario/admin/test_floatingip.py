# Copyright 2017 Red Hat, Inc.
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
from tempest.common import waiters
from tempest.lib import decorators

from neutron_tempest_plugin.common import ssh
from neutron_tempest_plugin import config
from neutron_tempest_plugin.scenario import base
from neutron_tempest_plugin.scenario import constants as const

CONF = config.CONF


class FloatingIpTestCasesAdmin(base.BaseTempestTestCase):
    credentials = ['primary', 'admin']

    @classmethod
    @utils.requires_ext(extension="router", service="network")
    def resource_setup(cls):
        super(FloatingIpTestCasesAdmin, cls).resource_setup()
        cls.network = cls.create_network()
        cls.create_subnet(cls.network)
        router = cls.create_router_by_client()
        cls.create_router_interface(router['id'], cls.subnets[0]['id'])
        # Create keypair with admin privileges
        cls.keypair = cls.create_keypair(client=cls.os_admin.keypairs_client)

        # Create security group with admin privileges
        network_client = cls.os_admin.network_client
        cls.secgroup = cls.create_security_group(
            client=cls.os_admin.network_client)
        cls.create_loginable_secgroup_rule(
            secgroup_id=cls.secgroup['id'],
            client=network_client)
        cls.create_pingable_secgroup_rule(
            secgroup_id=cls.secgroup['id'],
            client=network_client),

    def _list_hypervisors(self):
        # List of hypervisors
        return self.os_admin.hv_client.list_hypervisors()['hypervisors']

    def _list_availability_zones(self):
        # List of availability zones
        func = self.os_admin.az_client.list_availability_zones
        return func()['availabilityZoneInfo']

    def _create_vms(self, hyper, avail_zone, num_servers=2):
        servers, fips, server_ssh_clients = ([], [], [])
        # Create the availability zone with default zone and
        # a specific mentioned hypervisor.
        az = avail_zone + ':' + hyper
        for i in range(num_servers):
            servers.append(self.create_server(
                flavor_ref=CONF.compute.flavor_ref,
                image_ref=CONF.compute.image_ref,
                key_name=self.keypair['name'],
                networks=[{'uuid': self.network['id']}],
                security_groups=[{'name': self.secgroup['name']}],
                availability_zone=az))
        for i, server in enumerate(servers):
            waiters.wait_for_server_status(
                self.os_admin.servers_client, server['server']['id'],
                const.SERVER_STATUS_ACTIVE)
            port = self.client.list_ports(
                network_id=self.network['id'],
                device_id=server['server']['id']
            )['ports'][0]
            fip = self.create_floatingip(port=port,
                                         client=self.os_admin.network_client)
            fips.append(fip)
            server_ssh_clients.append(ssh.Client(
                fips[i]['floating_ip_address'], CONF.validation.image_ssh_user,
                pkey=self.keypair['private_key']))
        return servers, server_ssh_clients, fips

    @decorators.idempotent_id('6bba729b-3fb6-494b-9e1e-82bbd89a1045')
    def test_two_vms_fips(self):
        """Test two VMs floating IPs

        This test verifies the ability of two instances
        that were created in the same compute node and same availability zone
        to reach each other.
        """
        # Get hypervisor list to pass it for vm creation
        hyper = self._list_hypervisors()[0]['hypervisor_hostname']
        # Get availability zone list to pass it for vm creation
        avail_zone = self._list_availability_zones()[0]['zoneName']
        servers, server_ssh_clients, fips = self._create_vms(hyper, avail_zone)
        self.check_remote_connectivity(
            server_ssh_clients[0], fips[1]['floating_ip_address'],
            servers=servers)
