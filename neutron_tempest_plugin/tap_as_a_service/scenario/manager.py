# Copyright 2012 OpenStack Foundation
# Copyright 2013 IBM Corp.
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

import netaddr
from oslo_log import log
from oslo_utils import netutils

from tempest import config
from tempest.lib.common.utils import data_utils
from tempest.lib.common.utils import test_utils
from tempest.lib import exceptions as lib_exc

from neutron_tempest_plugin.scenario import base
from neutron_tempest_plugin.tap_as_a_service.services import taas_client

CONF = config.CONF

LOG = log.getLogger(__name__)


class BaseTaasScenarioTests(base.BaseTempestTestCase):

    credentials = ['primary', 'admin']

    @classmethod
    def setup_clients(cls):
        super(BaseTaasScenarioTests, cls).setup_clients()

        cls.client = cls.os_primary.network_client
        cls.admin_network_client = cls.os_admin.network_client

        # Setup taas clients
        cls.tap_services_client = taas_client.TapServicesClient(
            cls.os_primary.auth_provider,
            CONF.network.catalog_type,
            CONF.network.region or CONF.identity.region,
            endpoint_type=CONF.network.endpoint_type,
            build_interval=CONF.network.build_interval,
            build_timeout=CONF.network.build_timeout,
            **cls.os_primary.default_params)
        cls.tap_flows_client = taas_client.TapFlowsClient(
            cls.os_primary.auth_provider,
            CONF.network.catalog_type,
            CONF.network.region or CONF.identity.region,
            endpoint_type=CONF.network.endpoint_type,
            build_interval=CONF.network.build_interval,
            build_timeout=CONF.network.build_timeout,
            **cls.os_primary.default_params)

    def _create_subnet(self, network, subnets_client=None,
                       namestart='subnet-smoke', **kwargs):
        """Create a subnet for the given network

        within the cidr block configured for tenant networks.
        """
        if not subnets_client:
            subnets_client = self.client

        def cidr_in_use(cidr, tenant_id):
            """Check cidr existence

            :returns: True if subnet with cidr already exist in tenant
                  False else
            """
            cidr_in_use = self.os_admin.network_client.list_subnets(
                tenant_id=tenant_id, cidr=cidr)['subnets']
            return len(cidr_in_use) != 0

        ip_version = kwargs.pop('ip_version', 4)

        if ip_version == 6:
            tenant_cidr = netaddr.IPNetwork(
                CONF.network.project_network_v6_cidr)
            num_bits = CONF.network.project_network_v6_mask_bits
        else:
            tenant_cidr = netaddr.IPNetwork(CONF.network.project_network_cidr)
            num_bits = CONF.network.project_network_mask_bits

        result = None
        str_cidr = None
        # Repeatedly attempt subnet creation with sequential cidr
        # blocks until an unallocated block is found.
        for subnet_cidr in tenant_cidr.subnet(num_bits):
            str_cidr = str(subnet_cidr)
            if cidr_in_use(str_cidr, tenant_id=network['tenant_id']):
                continue

            subnet = dict(
                name=data_utils.rand_name(namestart),
                network_id=network['id'],
                tenant_id=network['tenant_id'],
                cidr=str_cidr,
                ip_version=ip_version,
                **kwargs
            )
            try:
                result = subnets_client.create_subnet(**subnet)
                break
            except lib_exc.Conflict as e:
                is_overlapping_cidr = 'overlaps with another subnet' in str(e)
                if not is_overlapping_cidr:
                    raise
        assert result is not None, 'Unable to allocate tenant network'

        subnet = result['subnet']
        assert subnet['cidr'] == str_cidr

        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                       subnets_client.delete_subnet, subnet['id'])

        return subnet

    def _get_server_port_id_and_ip4(self, server, ip_addr=None):
        ports = self.os_admin.network_client.list_ports(
            device_id=server['id'], fixed_ip=ip_addr)['ports']
        # A port can have more than one IP address in some cases.
        # If the network is dual-stack (IPv4 + IPv6), this port is associated
        # with 2 subnets
        p_status = ['ACTIVE']
        # NOTE(vsaienko) With Ironic, instances live on separate hardware
        # servers. Neutron does not bind ports for Ironic instances, as a
        # result the port remains in the DOWN state.
        # TODO(vsaienko) remove once bug: #1599836 is resolved.
        if getattr(CONF.service_available, 'ironic', False):
            p_status.append('DOWN')
        port_map = [(p["id"], fxip["ip_address"])
                    for p in ports
                    for fxip in p["fixed_ips"]
                    if netutils.is_valid_ipv4(fxip["ip_address"]) and
                    p['status'] in p_status]
        inactive = [p for p in ports if p['status'] != 'ACTIVE']
        if inactive:
            LOG.warning("Instance has ports that are not ACTIVE: %s", inactive)

        self.assertNotEqual(0, len(port_map),
                            "No IPv4 addresses found in: %s" % ports)
        self.assertEqual(len(port_map), 1,
                         "Found multiple IPv4 addresses: %s. "
                         "Unable to determine which port to target."
                         % port_map)
        return port_map[0]

    def _get_network_by_name(self, network_name):
        net = self.os_admin.network_client.list_networks(
            name=network_name)['networks']
        self.assertNotEqual(len(net), 0,
                            "Unable to get network by name: %s" % network_name)
        return net[0]

    def _run_in_background(self, sshclient, cmd):
        runInBg = "nohup %s 2>&1 &" % cmd
        sshclient.exec_command(runInBg)

    def create_networks(self, networks_client=None,
                        routers_client=None, subnets_client=None,
                        dns_nameservers=None, port_security_enabled=True):
        """Create a network with a subnet connected to a router.

        The baremetal driver is a special case since all nodes are
        on the same shared network.

        :param dns_nameservers: list of dns servers to send to subnet.
        :returns: network, subnet, router
        """
        if CONF.network.shared_physical_network:
            # NOTE(Shrews): This exception is for environments where tenant
            # credential isolation is available, but network separation is
            # not (the current baremetal case). Likely can be removed when
            # test account mgmt is reworked:
            # https://blueprints.launchpad.net/tempest/+spec/test-accounts
            if not CONF.compute.fixed_network_name:
                m = 'fixed_network_name must be specified in config'
                raise lib_exc.InvalidConfiguration(m)
            network = self._get_network_by_name(
                CONF.compute.fixed_network_name)
            router = None
            subnet = None
        else:
            network = self.create_network(
                client=networks_client,
                port_security_enabled=port_security_enabled)
            router = self._ensure_public_router(client=routers_client)
            subnet_kwargs = dict(network=network,
                                 subnets_client=subnets_client)
            # use explicit check because empty list is a valid option
            if dns_nameservers is not None:
                subnet_kwargs['dns_nameservers'] = dns_nameservers
            subnet = self._create_subnet(**subnet_kwargs)
            if not routers_client:
                routers_client = self.client
            router_id = router['id']
            routers_client.add_router_interface_with_subnet_id(
                router_id=router_id, subnet_id=subnet['id'])

            # save a cleanup job to remove this association between
            # router and subnet
            self.addCleanup(
                test_utils.call_and_ignore_notfound_exc,
                routers_client.remove_router_interface_with_subnet_id,
                router_id=router_id, subnet_id=subnet['id'])
        return network, subnet, router

    def _create_server_with_floatingip(self, use_taas_cloud_image=False,
                                       provider_net=False, **kwargs):
        network = self.network
        if use_taas_cloud_image:
            image = CONF.neutron_plugin_options.advanced_image_ref
            flavor = CONF.neutron_plugin_options.advanced_image_flavor_ref
        else:
            flavor = CONF.compute.flavor_ref
            image = CONF.compute.image_ref

        if provider_net:
            network = self.provider_network

        port = self.create_port(
            network=network, security_groups=[self.secgroup['id']], **kwargs)
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        self.client.delete_port, port['id'])

        params = {
            'flavor_ref': flavor,
            'image_ref': image,
            'key_name': self.keypair['name']
        }
        vm = self.create_server(networks=[{'port': port['id']}], **params)
        self.wait_for_server_active(vm['server'])
        self.wait_for_guest_os_ready(vm['server'])

        fip = self.create_and_associate_floatingip(
            port_id=port['id'])

        return port, fip

    def _setup_provider_network(self):
        net = self._create_provider_network()
        self._create_provider_subnet(net["id"])
        return net

    def _create_provider_network(self):
        network_kwargs = {
            "admin_state_up": True,
            "shared": True,
            "provider:network_type": "vlan",
            "provider:physical_network":
                CONF.taas.provider_physical_network,
        }

        segmentation_id = CONF.taas.provider_segmentation_id
        if segmentation_id and segmentation_id == "0":
            network_kwargs['provider:network_type'] = 'flat'
        elif segmentation_id:
            network_kwargs['provider:segmentation_id'] = segmentation_id

        network = self.admin_network_client.create_network(
            **network_kwargs)['network']
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        self.admin_network_client.delete_network,
                        network['id'])

        return network

    def _create_provider_subnet(self, net_id):
        subnet = dict(
            network_id=net_id,
            cidr="172.25.100.0/24",
            ip_version=4,
        )
        result = self.admin_network_client.create_subnet(**subnet)
        self.addCleanup(
            test_utils.call_and_ignore_notfound_exc,
            self.admin_network_client.delete_subnet, result['subnet']['id'])

        self.admin_network_client.add_router_interface_with_subnet_id(
            self.router['id'], subnet_id=result['subnet']['id'])

        self.addCleanup(
            test_utils.call_and_ignore_notfound_exc,
            self.admin_network_client.remove_router_interface_with_subnet_id,
            self.router['id'], subnet_id=result['subnet']['id'])
