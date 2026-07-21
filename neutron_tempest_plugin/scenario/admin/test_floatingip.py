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
from tempest.common import compute
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
    def setup_clients(cls):
        super().setup_clients()
        # admin_client set in BaseAdminNetworkTest but here we inherit from
        # BaseNetworkTest
        if not cls.admin_client:
            cls.admin_client = cls.os_admin.network_client

    @classmethod
    @utils.requires_ext(extension="router", service="network")
    def resource_setup(cls):
        super().resource_setup()
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

    def _choose_az_and_node(self):
        az_list = self.os_admin.az_client.list_availability_zones(
            detail=True)['availabilityZoneInfo']
        hv_list = self.os_admin.hv_client.list_hypervisors()['hypervisors']
        for az in az_list:
            if not az['zoneState']['available']:
                continue
            for host, services in az['hosts'].items():
                for service, info in services.items():
                    if (
                        service == 'nova-compute' and
                        info['active'] and info['available']
                    ):
                        hv = [
                            h for h in hv_list
                            if (
                                h['hypervisor_hostname'].startswith(host) and
                                h["state"] == "up" and
                                h["status"] == "enabled"
                            )
                        ]
                        if not hv:
                            continue
                        return az['zoneName'], hv[0]['hypervisor_hostname']
        return None, None

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
            port = self.admin_client.list_ports(
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

    @decorators.idempotent_id('3fc4a2e0-71c9-4587-ab9e-9b06e14a14df')
    def test_fip_from_vm_on_external_network(self):
        """Test connectivity from a VM on the external network to a FIP.

        Boot one VM directly on the external network and another on a
        tenant network with a floating IP.  Ping the FIP from the
        external-network VM.

        Regression test for OSPRH-32287.
        """
        ext_subnets = self.admin_client.list_subnets(
            network_id=CONF.network.public_network_id)['subnets']
        if not any(s['enable_dhcp'] for s in ext_subnets):
            self.skipTest("DHCP is disabled on the external subnet")

        # Boot a VM directly on the external network
        ext_port = self.admin_client.create_port(
            network_id=CONF.network.public_network_id,
            security_groups=[self.secgroup['id']])['port']
        self.addCleanup(
            self.admin_client.delete_port, ext_port['id'])
        ext_server = self.create_server(
            flavor_ref=CONF.compute.flavor_ref,
            image_ref=CONF.compute.image_ref,
            key_name=self.keypair['name'],
            networks=[{'port': ext_port['id']}],
            client=self.os_admin.servers_client)

        # Boot a VM on the tenant network and assign a FIP
        tenant_kwargs = dict(
            flavor_ref=CONF.compute.flavor_ref,
            image_ref=CONF.compute.image_ref,
            key_name=self.keypair['name'],
            networks=[{'uuid': self.network['id']}],
            security_groups=[{'name': self.secgroup['name']}],
            client=self.os_admin.servers_client)
        if (CONF.compute.min_compute_nodes > 1 and
                compute.is_scheduler_filter_enabled("DifferentHostFilter")):
            tenant_kwargs['scheduler_hints'] = {
                'different_host': [ext_server['server']['id']]}
        tenant_server = self.create_server(**tenant_kwargs)
        tenant_port = self.admin_client.list_ports(
            network_id=self.network['id'],
            device_id=tenant_server['server']['id'])['ports'][0]
        fip = self.create_floatingip(
            port=tenant_port, client=self.os_admin.network_client)

        # Ping the FIP from the external-network VM
        ext_ssh = ssh.Client(
            ext_port['fixed_ips'][0]['ip_address'],
            CONF.validation.image_ssh_user,
            pkey=self.keypair['private_key'])
        self.check_remote_connectivity(
            ext_ssh, fip['floating_ip_address'],
            servers=[ext_server, tenant_server])

        # Ping the external-network VM from the FIP VM
        fip_ssh = ssh.Client(
            fip['floating_ip_address'],
            CONF.validation.image_ssh_user,
            pkey=self.keypair['private_key'])
        self.check_remote_connectivity(
            fip_ssh, ext_port['fixed_ips'][0]['ip_address'],
            servers=[ext_server, tenant_server])

    @decorators.idempotent_id('6bba729b-3fb6-494b-9e1e-82bbd89a1045')
    def test_two_vms_fips(self):
        """Test two VMs floating IPs

        This test verifies the ability of two instances
        that were created in the same compute node and same availability zone
        to reach each other.
        """
        avail_zone, hyper = self._choose_az_and_node()
        if not (avail_zone and hyper):
            self.fail("No compute host is available")
        servers, server_ssh_clients, fips = self._create_vms(hyper, avail_zone)
        self.check_remote_connectivity(
            server_ssh_clients[0], fips[1]['floating_ip_address'],
            servers=servers)
