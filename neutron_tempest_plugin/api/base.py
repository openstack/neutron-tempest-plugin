# Copyright 2012 OpenStack Foundation
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

import functools
import math
import time

import netaddr
from neutron_lib import constants as const
from oslo_log import log
from tempest.common import utils as tutils
from tempest.lib.common.utils import data_utils
from tempest.lib import exceptions as lib_exc
from tempest import test

from neutron_tempest_plugin.api import clients
from neutron_tempest_plugin.common import constants
from neutron_tempest_plugin.common import utils
from neutron_tempest_plugin import config
from neutron_tempest_plugin import exceptions

CONF = config.CONF

LOG = log.getLogger(__name__)


class BaseNetworkTest(test.BaseTestCase):

    """Base class for Neutron tests that use the Tempest Neutron REST client

    Per the Neutron API Guide, API v1.x was removed from the source code tree
    (docs.openstack.org/api/openstack-network/2.0/content/Overview-d1e71.html)
    Therefore, v2.x of the Neutron API is assumed. It is also assumed that the
    following options are defined in the [network] section of etc/tempest.conf:

        project_network_cidr with a block of cidr's from which smaller blocks
        can be allocated for tenant networks

        project_network_mask_bits with the mask bits to be used to partition
        the block defined by tenant-network_cidr

    Finally, it is assumed that the following option is defined in the
    [service_available] section of etc/tempest.conf

        neutron as True
    """

    force_tenant_isolation = False
    credentials = ['primary']

    # Default to ipv4.
    _ip_version = const.IP_VERSION_4

    # Derive from BaseAdminNetworkTest class to have this initialized
    admin_client = None

    external_network_id = CONF.network.public_network_id

    @classmethod
    def get_client_manager(cls, credential_type=None, roles=None,
                           force_new=None):
        manager = super(BaseNetworkTest, cls).get_client_manager(
            credential_type=credential_type,
            roles=roles,
            force_new=force_new
        )
        # Neutron uses a different clients manager than the one in the Tempest
        # save the original in case mixed tests need it
        if credential_type == 'primary':
            cls.os_tempest = manager
        return clients.Manager(manager.credentials)

    @classmethod
    def skip_checks(cls):
        super(BaseNetworkTest, cls).skip_checks()
        if not CONF.service_available.neutron:
            raise cls.skipException("Neutron support is required")
        if (cls._ip_version == const.IP_VERSION_6 and
                not CONF.network_feature_enabled.ipv6):
            raise cls.skipException("IPv6 Tests are disabled.")
        for req_ext in getattr(cls, 'required_extensions', []):
            if not tutils.is_extension_enabled(req_ext, 'network'):
                msg = "%s extension not enabled." % req_ext
                raise cls.skipException(msg)

    @classmethod
    def setup_credentials(cls):
        # Create no network resources for these test.
        cls.set_network_resources()
        super(BaseNetworkTest, cls).setup_credentials()

    @classmethod
    def setup_clients(cls):
        super(BaseNetworkTest, cls).setup_clients()
        cls.client = cls.os_primary.network_client

    @classmethod
    def resource_setup(cls):
        super(BaseNetworkTest, cls).resource_setup()

        cls.networks = []
        cls.admin_networks = []
        cls.subnets = []
        cls.admin_subnets = []
        cls.ports = []
        cls.routers = []
        cls.floating_ips = []
        cls.port_forwardings = []
        cls.metering_labels = []
        cls.service_profiles = []
        cls.flavors = []
        cls.metering_label_rules = []
        cls.qos_rules = []
        cls.qos_policies = []
        cls.ethertype = "IPv" + str(cls._ip_version)
        cls.address_scopes = []
        cls.admin_address_scopes = []
        cls.subnetpools = []
        cls.admin_subnetpools = []
        cls.security_groups = []
        cls.admin_security_groups = []
        cls.projects = []
        cls.log_objects = []
        cls.reserved_subnet_cidrs = set()
        cls.keypairs = []
        cls.trunks = []
        cls.network_segment_ranges = []
        cls.conntrack_helpers = []

    @classmethod
    def resource_cleanup(cls):
        if CONF.service_available.neutron:
            # Clean up trunks
            for trunk in cls.trunks:
                cls._try_delete_resource(cls.delete_trunk, trunk)

            # Clean up port forwardings
            for pf in cls.port_forwardings:
                cls._try_delete_resource(cls.delete_port_forwarding, pf)

            # Clean up floating IPs
            for floating_ip in cls.floating_ips:
                cls._try_delete_resource(cls.delete_floatingip, floating_ip)

            # Clean up conntrack helpers
            for cth in cls.conntrack_helpers:
                cls._try_delete_resource(cls.delete_conntrack_helper, cth)

            # Clean up routers
            for router in cls.routers:
                cls._try_delete_resource(cls.delete_router,
                                         router)
            # Clean up metering label rules
            for metering_label_rule in cls.metering_label_rules:
                cls._try_delete_resource(
                    cls.admin_client.delete_metering_label_rule,
                    metering_label_rule['id'])
            # Clean up metering labels
            for metering_label in cls.metering_labels:
                cls._try_delete_resource(
                    cls.admin_client.delete_metering_label,
                    metering_label['id'])
            # Clean up flavors
            for flavor in cls.flavors:
                cls._try_delete_resource(
                    cls.admin_client.delete_flavor,
                    flavor['id'])
            # Clean up service profiles
            for service_profile in cls.service_profiles:
                cls._try_delete_resource(
                    cls.admin_client.delete_service_profile,
                    service_profile['id'])
            # Clean up ports
            for port in cls.ports:
                cls._try_delete_resource(cls.client.delete_port,
                                         port['id'])
            # Clean up subnets
            for subnet in cls.subnets:
                cls._try_delete_resource(cls.client.delete_subnet,
                                         subnet['id'])
            # Clean up admin subnets
            for subnet in cls.admin_subnets:
                cls._try_delete_resource(cls.admin_client.delete_subnet,
                                         subnet['id'])
            # Clean up networks
            for network in cls.networks:
                cls._try_delete_resource(cls.delete_network, network)

            # Clean up admin networks
            for network in cls.admin_networks:
                cls._try_delete_resource(cls.admin_client.delete_network,
                                         network['id'])

            # Clean up security groups
            for security_group in cls.security_groups:
                cls._try_delete_resource(cls.delete_security_group,
                                         security_group)

            # Clean up admin security groups
            for security_group in cls.admin_security_groups:
                cls._try_delete_resource(cls.delete_security_group,
                                         security_group,
                                         client=cls.admin_client)

            for subnetpool in cls.subnetpools:
                cls._try_delete_resource(cls.client.delete_subnetpool,
                                         subnetpool['id'])

            for subnetpool in cls.admin_subnetpools:
                cls._try_delete_resource(cls.admin_client.delete_subnetpool,
                                         subnetpool['id'])

            for address_scope in cls.address_scopes:
                cls._try_delete_resource(cls.client.delete_address_scope,
                                         address_scope['id'])

            for address_scope in cls.admin_address_scopes:
                cls._try_delete_resource(
                    cls.admin_client.delete_address_scope,
                    address_scope['id'])

            for project in cls.projects:
                cls._try_delete_resource(
                    cls.identity_admin_client.delete_project,
                    project['id'])

            # Clean up QoS rules
            for qos_rule in cls.qos_rules:
                cls._try_delete_resource(cls.admin_client.delete_qos_rule,
                                         qos_rule['id'])
            # Clean up QoS policies
            # as all networks and ports are already removed, QoS policies
            # shouldn't be "in use"
            for qos_policy in cls.qos_policies:
                cls._try_delete_resource(cls.admin_client.delete_qos_policy,
                                         qos_policy['id'])

            # Clean up log_objects
            for log_object in cls.log_objects:
                cls._try_delete_resource(cls.admin_client.delete_log,
                                         log_object['id'])

            for keypair in cls.keypairs:
                cls._try_delete_resource(cls.delete_keypair, keypair)

            # Clean up network_segment_ranges
            for network_segment_range in cls.network_segment_ranges:
                cls._try_delete_resource(
                    cls.admin_client.delete_network_segment_range,
                    network_segment_range['id'])

        super(BaseNetworkTest, cls).resource_cleanup()

    @classmethod
    def _try_delete_resource(cls, delete_callable, *args, **kwargs):
        """Cleanup resources in case of test-failure

        Some resources are explicitly deleted by the test.
        If the test failed to delete a resource, this method will execute
        the appropriate delete methods. Otherwise, the method ignores NotFound
        exceptions thrown for resources that were correctly deleted by the
        test.

        :param delete_callable: delete method
        :param args: arguments for delete method
        :param kwargs: keyword arguments for delete method
        """
        try:
            delete_callable(*args, **kwargs)
        # if resource is not found, this means it was deleted in the test
        except lib_exc.NotFound:
            pass

    @classmethod
    def create_network(cls, network_name=None, client=None, external=None,
                       shared=None, provider_network_type=None,
                       provider_physical_network=None,
                       provider_segmentation_id=None, **kwargs):
        """Create a network.

        When client is not provider and admin_client is attribute is not None
        (for example when using BaseAdminNetworkTest base class) and using any
        of the convenience parameters (external, shared, provider_network_type,
        provider_physical_network and provider_segmentation_id) it silently
        uses admin_client. If the network is not shared then it uses the same
        project_id as regular client.

        :param network_name: Human-readable name of the network

        :param client: client to be used for connecting to network service

        :param external: indicates whether the network has an external routing
        facility that's not managed by the networking service.

        :param shared: indicates whether this resource is shared across all
        projects. By default, only administrative users can change this value.
        If True and admin_client attribute is not None, then the network is
        created under administrative project.

        :param provider_network_type: the type of physical network that this
        network should be mapped to. For example, 'flat', 'vlan', 'vxlan', or
        'gre'. Valid values depend on a networking back-end.

        :param provider_physical_network: the physical network where this
        network should be implemented. The Networking API v2.0 does not provide
        a way to list available physical networks. For example, the Open
        vSwitch plug-in configuration file defines a symbolic name that maps to
        specific bridges on each compute host.

        :param provider_segmentation_id: The ID of the isolated segment on the
        physical network. The network_type attribute defines the segmentation
        model. For example, if the network_type value is 'vlan', this ID is a
        vlan identifier. If the network_type value is 'gre', this ID is a gre
        key.

        :param **kwargs: extra parameters to be forwarded to network service
        """

        name = (network_name or kwargs.pop('name', None) or
                data_utils.rand_name('test-network-'))

        # translate convenience parameters
        admin_client_required = False
        if provider_network_type:
            admin_client_required = True
            kwargs['provider:network_type'] = provider_network_type
        if provider_physical_network:
            admin_client_required = True
            kwargs['provider:physical_network'] = provider_physical_network
        if provider_segmentation_id:
            admin_client_required = True
            kwargs['provider:segmentation_id'] = provider_segmentation_id
        if external is not None:
            admin_client_required = True
            kwargs['router:external'] = bool(external)
        if shared is not None:
            admin_client_required = True
            kwargs['shared'] = bool(shared)

        if not client:
            if admin_client_required and cls.admin_client:
                # For convenience silently switch to admin client
                client = cls.admin_client
                if not shared:
                    # Keep this network visible from current project
                    project_id = (kwargs.get('project_id') or
                                  kwargs.get('tenant_id') or
                                  cls.client.tenant_id)
                    kwargs.update(project_id=project_id, tenant_id=project_id)
            else:
                # Use default client
                client = cls.client

        network = client.create_network(name=name, **kwargs)['network']
        network['client'] = client
        cls.networks.append(network)
        return network

    @classmethod
    def delete_network(cls, network, client=None):
        client = client or network.get('client') or cls.client
        client.delete_network(network['id'])

    @classmethod
    def create_shared_network(cls, network_name=None, **kwargs):
        return cls.create_network(name=network_name, shared=True, **kwargs)

    @classmethod
    def create_subnet(cls, network, gateway='', cidr=None, mask_bits=None,
                      ip_version=None, client=None, reserve_cidr=True,
                      **kwargs):
        """Wrapper utility that returns a test subnet.

        Convenient wrapper for client.create_subnet method. It reserves and
        allocates CIDRs to avoid creating overlapping subnets.

        :param network: network where to create the subnet
        network['id'] must contain the ID of the network

        :param gateway: gateway IP address
        It can be a str or a netaddr.IPAddress
        If gateway is not given, then it will use default address for
        given subnet CIDR, like "192.168.0.1" for "192.168.0.0/24" CIDR
        if gateway is given as None then no gateway will be assigned

        :param cidr: CIDR of the subnet to create
        It can be either None, a str or a netaddr.IPNetwork instance

        :param mask_bits: CIDR prefix length
        It can be either None or a numeric value.
        If cidr parameter is given then mask_bits is used to determinate a
        sequence of valid CIDR to use as generated.
        Please see netaddr.IPNetwork.subnet method documentation[1]

        :param ip_version: ip version of generated subnet CIDRs
        It can be None, IP_VERSION_4 or IP_VERSION_6
        It has to match given either given CIDR and gateway

        :param ip_version: numeric value (either IP_VERSION_4 or IP_VERSION_6)
        this value must match CIDR and gateway IP versions if any of them is
        given

        :param client: client to be used to connect to network service

        :param reserve_cidr: if True then it reserves assigned CIDR to avoid
        using the same CIDR for further subnets in the scope of the same
        test case class

        :param **kwargs: optional parameters to be forwarded to wrapped method

        [1] http://netaddr.readthedocs.io/en/latest/tutorial_01.html#supernets-and-subnets  # noqa
        """

        # allow tests to use admin client
        if not client:
            client = cls.client

        if gateway:
            gateway_ip = netaddr.IPAddress(gateway)
            if ip_version:
                if ip_version != gateway_ip.version:
                    raise ValueError(
                        "Gateway IP version doesn't match IP version")
            else:
                ip_version = gateway_ip.version
        else:
            ip_version = ip_version or cls._ip_version

        for subnet_cidr in cls.get_subnet_cidrs(
                ip_version=ip_version, cidr=cidr, mask_bits=mask_bits):
            if gateway is not None:
                kwargs['gateway_ip'] = str(gateway or (subnet_cidr.ip + 1))
            else:
                kwargs['gateway_ip'] = None
            try:
                body = client.create_subnet(
                    network_id=network['id'],
                    cidr=str(subnet_cidr),
                    ip_version=subnet_cidr.version,
                    **kwargs)
                break
            except lib_exc.BadRequest as e:
                if 'overlaps with another subnet' not in str(e):
                    raise
        else:
            message = 'Available CIDR for subnet creation could not be found'
            raise ValueError(message)
        subnet = body['subnet']
        if client is cls.client:
            cls.subnets.append(subnet)
        else:
            cls.admin_subnets.append(subnet)
        if reserve_cidr:
            cls.reserve_subnet_cidr(subnet_cidr)
        return subnet

    @classmethod
    def reserve_subnet_cidr(cls, addr, **ipnetwork_kwargs):
        """Reserve given subnet CIDR making sure it is not used by create_subnet

        :param addr: the CIDR address to be reserved
        It can be a str or netaddr.IPNetwork instance

        :param **ipnetwork_kwargs: optional netaddr.IPNetwork constructor
        parameters
        """

        if not cls.try_reserve_subnet_cidr(addr, **ipnetwork_kwargs):
            raise ValueError('Subnet CIDR already reserved: %r'.format(
                addr))

    @classmethod
    def try_reserve_subnet_cidr(cls, addr, **ipnetwork_kwargs):
        """Reserve given subnet CIDR if it hasn't been reserved before

        :param addr: the CIDR address to be reserved
        It can be a str or netaddr.IPNetwork instance

        :param **ipnetwork_kwargs: optional netaddr.IPNetwork constructor
        parameters

        :return: True if it wasn't reserved before, False elsewhere.
        """

        subnet_cidr = netaddr.IPNetwork(addr, **ipnetwork_kwargs)
        if subnet_cidr in cls.reserved_subnet_cidrs:
            return False
        else:
            cls.reserved_subnet_cidrs.add(subnet_cidr)
            return True

    @classmethod
    def get_subnet_cidrs(
            cls, cidr=None, mask_bits=None, ip_version=None):
        """Iterate over a sequence of unused subnet CIDR for IP version

        :param cidr: CIDR of the subnet to create
        It can be either None, a str or a netaddr.IPNetwork instance

        :param mask_bits: CIDR prefix length
        It can be either None or a numeric value.
        If cidr parameter is given then mask_bits is used to determinate a
        sequence of valid CIDR to use as generated.
        Please see netaddr.IPNetwork.subnet method documentation[1]

        :param ip_version: ip version of generated subnet CIDRs
        It can be None, IP_VERSION_4 or IP_VERSION_6
        It has to match given CIDR if given

        :return: iterator over reserved CIDRs of type netaddr.IPNetwork

        [1] http://netaddr.readthedocs.io/en/latest/tutorial_01.html#supernets-and-subnets  # noqa
        """

        if cidr:
            # Generate subnet CIDRs starting from given CIDR
            # checking it is of requested IP version
            cidr = netaddr.IPNetwork(cidr, version=ip_version)
        else:
            # Generate subnet CIDRs starting from configured values
            ip_version = ip_version or cls._ip_version
            if ip_version == const.IP_VERSION_4:
                mask_bits = mask_bits or config.safe_get_config_value(
                    'network', 'project_network_mask_bits')
                cidr = netaddr.IPNetwork(config.safe_get_config_value(
                    'network', 'project_network_cidr'))
            elif ip_version == const.IP_VERSION_6:
                mask_bits = config.safe_get_config_value(
                    'network', 'project_network_v6_mask_bits')
                cidr = netaddr.IPNetwork(config.safe_get_config_value(
                    'network', 'project_network_v6_cidr'))
            else:
                raise ValueError('Invalid IP version: {!r}'.format(ip_version))

        if mask_bits:
            subnet_cidrs = cidr.subnet(mask_bits)
        else:
            subnet_cidrs = iter([cidr])

        for subnet_cidr in subnet_cidrs:
            if subnet_cidr not in cls.reserved_subnet_cidrs:
                yield subnet_cidr

    @classmethod
    def create_port(cls, network, **kwargs):
        """Wrapper utility that returns a test port."""
        if CONF.network.port_vnic_type and 'binding:vnic_type' not in kwargs:
            kwargs['binding:vnic_type'] = CONF.network.port_vnic_type
        body = cls.client.create_port(network_id=network['id'],
                                      **kwargs)
        port = body['port']
        cls.ports.append(port)
        return port

    @classmethod
    def update_port(cls, port, **kwargs):
        """Wrapper utility that updates a test port."""
        body = cls.client.update_port(port['id'],
                                      **kwargs)
        return body['port']

    @classmethod
    def _create_router_with_client(
        cls, client, router_name=None, admin_state_up=False,
        external_network_id=None, enable_snat=None, **kwargs
    ):
        ext_gw_info = {}
        if external_network_id:
            ext_gw_info['network_id'] = external_network_id
        if enable_snat is not None:
            ext_gw_info['enable_snat'] = enable_snat
        body = client.create_router(
            router_name, external_gateway_info=ext_gw_info,
            admin_state_up=admin_state_up, **kwargs)
        router = body['router']
        cls.routers.append(router)
        return router

    @classmethod
    def create_router(cls, *args, **kwargs):
        return cls._create_router_with_client(cls.client, *args, **kwargs)

    @classmethod
    def create_admin_router(cls, *args, **kwargs):
        return cls._create_router_with_client(cls.os_admin.network_client,
                                              *args, **kwargs)

    @classmethod
    def create_floatingip(cls, external_network_id=None, port=None,
                          client=None, **kwargs):
        """Creates a floating IP.

        Create a floating IP and schedule it for later deletion.
        If a client is passed, then it is used for deleting the IP too.

        :param external_network_id: network ID where to create
        By default this is 'CONF.network.public_network_id'.

        :param port: port to bind floating IP to
        This is translated to 'port_id=port['id']'
        By default it is None.

        :param client: network client to be used for creating and cleaning up
        the floating IP.

        :param **kwargs: additional creation parameters to be forwarded to
        networking server.
        """

        client = client or cls.client
        external_network_id = (external_network_id or
                               cls.external_network_id)

        if port:
            port_id = kwargs.setdefault('port_id', port['id'])
            if port_id != port['id']:
                message = "Port ID specified twice: {!s} != {!s}".format(
                    port_id, port['id'])
                raise ValueError(message)

        fip = client.create_floatingip(external_network_id,
                                       **kwargs)['floatingip']

        # save client to be used later in cls.delete_floatingip
        # for final cleanup
        fip['client'] = client
        cls.floating_ips.append(fip)
        return fip

    @classmethod
    def delete_floatingip(cls, floating_ip, client=None):
        """Delete floating IP

        :param client: Client to be used
        If client is not given it will use the client used to create
        the floating IP, or cls.client if unknown.
        """

        client = client or floating_ip.get('client') or cls.client
        client.delete_floatingip(floating_ip['id'])

    @classmethod
    def create_port_forwarding(cls, fip_id, internal_port_id,
                               internal_port, external_port,
                               internal_ip_address=None, protocol="tcp",
                               client=None):
        """Creates a port forwarding.

        Create a port forwarding and schedule it for later deletion.
        If a client is passed, then it is used for deleting the PF too.

        :param fip_id: The ID of the floating IP address.

        :param internal_port_id: The ID of the Neutron port associated to
        the floating IP port forwarding.

        :param internal_port: The TCP/UDP/other protocol port number of the
        Neutron port fixed IP address associated to the floating ip
        port forwarding.

        :param external_port: The TCP/UDP/other protocol port number of
        the port forwarding floating IP address.

        :param internal_ip_address: The fixed IPv4 address of the Neutron
        port associated to the floating IP port forwarding.

        :param protocol: The IP protocol used in the floating IP port
        forwarding.

        :param client: network client to be used for creating and cleaning up
        the floating IP port forwarding.
        """

        client = client or cls.client

        pf = client.create_port_forwarding(
            fip_id, internal_port_id, internal_port, external_port,
            internal_ip_address, protocol)['port_forwarding']

        # save ID of floating IP associated with port forwarding for final
        # cleanup
        pf['floatingip_id'] = fip_id

        # save client to be used later in cls.delete_port_forwarding
        # for final cleanup
        pf['client'] = client
        cls.port_forwardings.append(pf)
        return pf

    @classmethod
    def delete_port_forwarding(cls, pf, client=None):
        """Delete port forwarding

        :param client: Client to be used
        If client is not given it will use the client used to create
        the port forwarding, or cls.client if unknown.
        """

        client = client or pf.get('client') or cls.client
        client.delete_port_forwarding(pf['floatingip_id'], pf['id'])

    @classmethod
    def create_router_interface(cls, router_id, subnet_id):
        """Wrapper utility that returns a router interface."""
        interface = cls.client.add_router_interface_with_subnet_id(
            router_id, subnet_id)
        return interface

    @classmethod
    def add_extra_routes_atomic(cls, *args, **kwargs):
        return cls.client.add_extra_routes_atomic(*args, **kwargs)

    @classmethod
    def remove_extra_routes_atomic(cls, *args, **kwargs):
        return cls.client.remove_extra_routes_atomic(*args, **kwargs)

    @classmethod
    def get_supported_qos_rule_types(cls):
        body = cls.client.list_qos_rule_types()
        return [rule_type['type'] for rule_type in body['rule_types']]

    @classmethod
    def create_qos_policy(cls, name, description=None, shared=False,
                          project_id=None, is_default=False):
        """Wrapper utility that returns a test QoS policy."""
        body = cls.admin_client.create_qos_policy(
            name, description, shared, project_id, is_default)
        qos_policy = body['policy']
        cls.qos_policies.append(qos_policy)
        return qos_policy

    @classmethod
    def create_qos_bandwidth_limit_rule(cls, policy_id, max_kbps,
                                        max_burst_kbps,
                                        direction=const.EGRESS_DIRECTION):
        """Wrapper utility that returns a test QoS bandwidth limit rule."""
        body = cls.admin_client.create_bandwidth_limit_rule(
            policy_id, max_kbps, max_burst_kbps, direction)
        qos_rule = body['bandwidth_limit_rule']
        cls.qos_rules.append(qos_rule)
        return qos_rule

    @classmethod
    def create_qos_minimum_bandwidth_rule(cls, policy_id, min_kbps,
                                          direction=const.EGRESS_DIRECTION):
        """Wrapper utility that creates and returns a QoS min bw rule."""
        body = cls.admin_client.create_minimum_bandwidth_rule(
            policy_id, direction, min_kbps)
        qos_rule = body['minimum_bandwidth_rule']
        cls.qos_rules.append(qos_rule)
        return qos_rule

    @classmethod
    def delete_router(cls, router, client=None):
        client = client or cls.client
        if 'routes' in router:
            client.remove_router_extra_routes(router['id'])
        body = client.list_router_interfaces(router['id'])
        interfaces = [port for port in body['ports']
                      if port['device_owner'] in const.ROUTER_INTERFACE_OWNERS]
        for i in interfaces:
            try:
                client.remove_router_interface_with_subnet_id(
                    router['id'], i['fixed_ips'][0]['subnet_id'])
            except lib_exc.NotFound:
                pass
        client.delete_router(router['id'])

    @classmethod
    def create_address_scope(cls, name, is_admin=False, **kwargs):
        if is_admin:
            body = cls.admin_client.create_address_scope(name=name, **kwargs)
            cls.admin_address_scopes.append(body['address_scope'])
        else:
            body = cls.client.create_address_scope(name=name, **kwargs)
            cls.address_scopes.append(body['address_scope'])
        return body['address_scope']

    @classmethod
    def create_subnetpool(cls, name, is_admin=False, **kwargs):
        if is_admin:
            body = cls.admin_client.create_subnetpool(name, **kwargs)
            cls.admin_subnetpools.append(body['subnetpool'])
        else:
            body = cls.client.create_subnetpool(name, **kwargs)
            cls.subnetpools.append(body['subnetpool'])
        return body['subnetpool']

    @classmethod
    def create_project(cls, name=None, description=None):
        test_project = name or data_utils.rand_name('test_project_')
        test_description = description or data_utils.rand_name('desc_')
        project = cls.identity_admin_client.create_project(
            name=test_project,
            description=test_description)['project']
        cls.projects.append(project)
        # Create a project will create a default security group.
        sgs_list = cls.admin_client.list_security_groups(
            tenant_id=project['id'])['security_groups']
        for security_group in sgs_list:
            # Make sure delete_security_group method will use
            # the admin client for this group
            security_group['client'] = cls.admin_client
            cls.security_groups.append(security_group)
        return project

    @classmethod
    def create_security_group(cls, name=None, project=None, client=None,
                              **kwargs):
        if project:
            client = client or cls.admin_client
            project_id = kwargs.setdefault('project_id', project['id'])
            tenant_id = kwargs.setdefault('tenant_id', project['id'])
            if project_id != project['id'] or tenant_id != project['id']:
                raise ValueError('Project ID specified multiple times')
        else:
            client = client or cls.client

        name = name or data_utils.rand_name(cls.__name__)
        security_group = client.create_security_group(name=name, **kwargs)[
            'security_group']
        security_group['client'] = client
        cls.security_groups.append(security_group)
        return security_group

    @classmethod
    def delete_security_group(cls, security_group, client=None):
        client = client or security_group.get('client') or cls.client
        client.delete_security_group(security_group['id'])

    @classmethod
    def create_security_group_rule(cls, security_group=None, project=None,
                                   client=None, ip_version=None, **kwargs):
        if project:
            client = client or cls.admin_client
            project_id = kwargs.setdefault('project_id', project['id'])
            tenant_id = kwargs.setdefault('tenant_id', project['id'])
            if project_id != project['id'] or tenant_id != project['id']:
                raise ValueError('Project ID specified multiple times')

        if 'security_group_id' not in kwargs:
            security_group = (security_group or
                              cls.get_security_group(client=client))

        if security_group:
            client = client or security_group.get('client')
            security_group_id = kwargs.setdefault('security_group_id',
                                                  security_group['id'])
            if security_group_id != security_group['id']:
                raise ValueError('Security group ID specified multiple times.')

        ip_version = ip_version or cls._ip_version
        default_params = (
            constants.DEFAULT_SECURITY_GROUP_RULE_PARAMS[ip_version])
        for key, value in default_params.items():
            kwargs.setdefault(key, value)

        client = client or cls.client
        return client.create_security_group_rule(**kwargs)[
            'security_group_rule']

    @classmethod
    def get_security_group(cls, name='default', client=None):
        client = client or cls.client
        security_groups = client.list_security_groups()['security_groups']
        for security_group in security_groups:
            if security_group['name'] == name:
                return security_group
        raise ValueError("No such security group named {!r}".format(name))

    @classmethod
    def create_keypair(cls, client=None, name=None, **kwargs):
        client = client or cls.os_primary.keypairs_client
        name = name or data_utils.rand_name('keypair-test')
        keypair = client.create_keypair(name=name, **kwargs)['keypair']

        # save client for later cleanup
        keypair['client'] = client
        cls.keypairs.append(keypair)
        return keypair

    @classmethod
    def delete_keypair(cls, keypair, client=None):
        client = (client or keypair.get('client') or
                  cls.os_primary.keypairs_client)
        client.delete_keypair(keypair_name=keypair['name'])

    @classmethod
    def create_trunk(cls, port=None, subports=None, client=None, **kwargs):
        """Create network trunk

        :param port: dictionary containing parent port ID (port['id'])
        :param client: client to be used for connecting to networking service
        :param **kwargs: extra parameters to be forwarded to network service

        :returns: dictionary containing created trunk details
        """
        client = client or cls.client

        if port:
            kwargs['port_id'] = port['id']

        trunk = client.create_trunk(subports=subports, **kwargs)['trunk']
        # Save client reference for later deletion
        trunk['client'] = client
        cls.trunks.append(trunk)
        return trunk

    @classmethod
    def delete_trunk(cls, trunk, client=None, detach_parent_port=True):
        """Delete network trunk

        :param trunk: dictionary containing trunk ID (trunk['id'])

        :param client: client to be used for connecting to networking service
        """
        client = client or trunk.get('client') or cls.client
        trunk.update(client.show_trunk(trunk['id'])['trunk'])

        if not trunk['admin_state_up']:
            # Cannot touch trunk before admin_state_up is True
            client.update_trunk(trunk['id'], admin_state_up=True)
        if trunk['sub_ports']:
            # Removes trunk ports before deleting it
            cls._try_delete_resource(client.remove_subports, trunk['id'],
                                     trunk['sub_ports'])

        # we have to detach the interface from the server before
        # the trunk can be deleted.
        parent_port = {'id': trunk['port_id']}

        def is_parent_port_detached():
            parent_port.update(client.show_port(parent_port['id'])['port'])
            return not parent_port['device_id']

        if detach_parent_port and not is_parent_port_detached():
            # this could probably happen when trunk is deleted and parent port
            # has been assigned to a VM that is still running. Here we are
            # assuming that device_id points to such VM.
            cls.os_primary.compute.InterfacesClient().delete_interface(
                parent_port['device_id'], parent_port['id'])
            utils.wait_until_true(is_parent_port_detached)

        client.delete_trunk(trunk['id'])

    @classmethod
    def create_conntrack_helper(cls, router_id, helper, protocol, port,
                                client=None):
        """Create a conntrack helper

        Create a conntrack helper and schedule it for later deletion. If a
        client is passed, then it is used for deleteing the CTH too.

        :param router_id: The ID of the Neutron router associated to the
        conntrack helper.

        :param helper: The conntrack helper module alias

        :param protocol: The conntrack helper IP protocol used in the conntrack
        helper.

        :param port: The conntrack helper IP protocol port number for the
        conntrack helper.

        :param client: network client to be used for creating and cleaning up
        the conntrack helper.
        """

        client = client or cls.client

        cth = client.create_conntrack_helper(router_id, helper, protocol,
                                             port)['conntrack_helper']

        # save ID of router associated with conntrack helper for final cleanup
        cth['router_id'] = router_id

        # save client to be used later in cls.delete_conntrack_helper for final
        # cleanup
        cth['client'] = client
        cls.conntrack_helpers.append(cth)
        return cth

    @classmethod
    def delete_conntrack_helper(cls, cth, client=None):
        """Delete conntrack helper

        :param client: Client to be used
        If client is not given it will use the client used to create the
        conntrack helper, or cls.client if unknown.
        """

        client = client or cth.get('client') or cls.client
        client.delete_conntrack_helper(cth['router_id'], cth['id'])


class BaseAdminNetworkTest(BaseNetworkTest):

    credentials = ['primary', 'admin']

    @classmethod
    def setup_clients(cls):
        super(BaseAdminNetworkTest, cls).setup_clients()
        cls.admin_client = cls.os_admin.network_client
        cls.identity_admin_client = cls.os_admin.projects_client

    @classmethod
    def create_metering_label(cls, name, description):
        """Wrapper utility that returns a test metering label."""
        body = cls.admin_client.create_metering_label(
            description=description,
            name=data_utils.rand_name("metering-label"))
        metering_label = body['metering_label']
        cls.metering_labels.append(metering_label)
        return metering_label

    @classmethod
    def create_metering_label_rule(cls, remote_ip_prefix, direction,
                                   metering_label_id):
        """Wrapper utility that returns a test metering label rule."""
        body = cls.admin_client.create_metering_label_rule(
            remote_ip_prefix=remote_ip_prefix, direction=direction,
            metering_label_id=metering_label_id)
        metering_label_rule = body['metering_label_rule']
        cls.metering_label_rules.append(metering_label_rule)
        return metering_label_rule

    @classmethod
    def create_network_segment_range(cls, name, shared,
                                     project_id, network_type,
                                     physical_network, minimum,
                                     maximum):
        """Wrapper utility that returns a test network segment range."""
        network_segment_range_args = {'name': name,
                                      'shared': shared,
                                      'project_id': project_id,
                                      'network_type': network_type,
                                      'physical_network': physical_network,
                                      'minimum': minimum,
                                      'maximum': maximum}
        body = cls.admin_client.create_network_segment_range(
            **network_segment_range_args)
        network_segment_range = body['network_segment_range']
        cls.network_segment_ranges.append(network_segment_range)
        return network_segment_range

    @classmethod
    def create_flavor(cls, name, description, service_type):
        """Wrapper utility that returns a test flavor."""
        body = cls.admin_client.create_flavor(
            description=description, service_type=service_type,
            name=name)
        flavor = body['flavor']
        cls.flavors.append(flavor)
        return flavor

    @classmethod
    def create_service_profile(cls, description, metainfo, driver):
        """Wrapper utility that returns a test service profile."""
        body = cls.admin_client.create_service_profile(
            driver=driver, metainfo=metainfo, description=description)
        service_profile = body['service_profile']
        cls.service_profiles.append(service_profile)
        return service_profile

    @classmethod
    def create_log(cls, name, description=None,
                   resource_type='security_group', resource_id=None,
                   target_id=None, event='ALL', enabled=True):
        """Wrapper utility that returns a test log object."""
        log_args = {'name': name,
                    'description': description,
                    'resource_type': resource_type,
                    'resource_id': resource_id,
                    'target_id': target_id,
                    'event': event,
                    'enabled': enabled}
        body = cls.admin_client.create_log(**log_args)
        log_object = body['log']
        cls.log_objects.append(log_object)
        return log_object

    @classmethod
    def get_unused_ip(cls, net_id, ip_version=None):
        """Get an unused ip address in a allocation pool of net"""
        body = cls.admin_client.list_ports(network_id=net_id)
        ports = body['ports']
        used_ips = []
        for port in ports:
            used_ips.extend(
                [fixed_ip['ip_address'] for fixed_ip in port['fixed_ips']])
        body = cls.admin_client.list_subnets(network_id=net_id)
        subnets = body['subnets']

        for subnet in subnets:
            if ip_version and subnet['ip_version'] != ip_version:
                continue
            cidr = subnet['cidr']
            allocation_pools = subnet['allocation_pools']
            iterators = []
            if allocation_pools:
                for allocation_pool in allocation_pools:
                    iterators.append(netaddr.iter_iprange(
                        allocation_pool['start'], allocation_pool['end']))
            else:
                net = netaddr.IPNetwork(cidr)

                def _iterip():
                    for ip in net:
                        if ip not in (net.network, net.broadcast):
                            yield ip
                iterators.append(iter(_iterip()))

            for iterator in iterators:
                for ip in iterator:
                    if str(ip) not in used_ips:
                        return str(ip)

        message = (
            "net(%s) has no usable IP address in allocation pools" % net_id)
        raise exceptions.InvalidConfiguration(message)

    @classmethod
    def create_provider_network(cls, physnet_name, start_segmentation_id,
                                max_attempts=30):
        segmentation_id = start_segmentation_id
        for attempts in range(max_attempts):
            try:
                return cls.create_network(
                    name=data_utils.rand_name('test_net'),
                    shared=True,
                    provider_network_type='vlan',
                    provider_physical_network=physnet_name,
                    provider_segmentation_id=segmentation_id)
            except lib_exc.Conflict:
                segmentation_id += 1
                if segmentation_id > 4095:
                    raise lib_exc.TempestException(
                        "No free segmentation id was found for provider "
                        "network creation!")
                time.sleep(CONF.network.build_interval)
        LOG.exception("Failed to create provider network after "
                      "%d attempts", max_attempts)
        raise lib_exc.TimeoutException


def require_qos_rule_type(rule_type):
    def decorator(f):
        @functools.wraps(f)
        def wrapper(self, *func_args, **func_kwargs):
            if rule_type not in self.get_supported_qos_rule_types():
                raise self.skipException(
                    "%s rule type is required." % rule_type)
            return f(self, *func_args, **func_kwargs)
        return wrapper
    return decorator


def _require_sorting(f):
    @functools.wraps(f)
    def inner(self, *args, **kwargs):
        if not tutils.is_extension_enabled("sorting", "network"):
            self.skipTest('Sorting feature is required')
        return f(self, *args, **kwargs)
    return inner


def _require_pagination(f):
    @functools.wraps(f)
    def inner(self, *args, **kwargs):
        if not tutils.is_extension_enabled("pagination", "network"):
            self.skipTest('Pagination feature is required')
        return f(self, *args, **kwargs)
    return inner


class BaseSearchCriteriaTest(BaseNetworkTest):

    # This should be defined by subclasses to reflect resource name to test
    resource = None

    field = 'name'

    # NOTE(ihrachys): some names, like those starting with an underscore (_)
    # are sorted differently depending on whether the plugin implements native
    # sorting support, or not. So we avoid any such cases here, sticking to
    # alphanumeric. Also test a case when there are multiple resources with the
    # same name
    resource_names = ('test1', 'abc1', 'test10', '123test') + ('test1',)

    force_tenant_isolation = True

    list_kwargs = {}

    list_as_admin = False

    def assertSameOrder(self, original, actual):
        # gracefully handle iterators passed
        original = list(original)
        actual = list(actual)
        self.assertEqual(len(original), len(actual))
        for expected, res in zip(original, actual):
            self.assertEqual(expected[self.field], res[self.field])

    @utils.classproperty
    def plural_name(self):
        return '%ss' % self.resource

    @property
    def list_client(self):
        return self.admin_client if self.list_as_admin else self.client

    def list_method(self, *args, **kwargs):
        method = getattr(self.list_client, 'list_%s' % self.plural_name)
        kwargs.update(self.list_kwargs)
        return method(*args, **kwargs)

    def get_bare_url(self, url):
        base_url = self.client.base_url
        base_url_normalized = utils.normalize_url(base_url)
        url_normalized = utils.normalize_url(url)
        self.assertTrue(url_normalized.startswith(base_url_normalized))
        return url_normalized[len(base_url_normalized):]

    @classmethod
    def _extract_resources(cls, body):
        return body[cls.plural_name]

    def _test_list_sorts(self, direction):
        sort_args = {
            'sort_dir': direction,
            'sort_key': self.field
        }
        body = self.list_method(**sort_args)
        resources = self._extract_resources(body)
        self.assertNotEmpty(
            resources, "%s list returned is empty" % self.resource)
        retrieved_names = [res[self.field] for res in resources]
        expected = sorted(retrieved_names)
        if direction == constants.SORT_DIRECTION_DESC:
            expected = list(reversed(expected))
        self.assertEqual(expected, retrieved_names)

    @_require_sorting
    def _test_list_sorts_asc(self):
        self._test_list_sorts(constants.SORT_DIRECTION_ASC)

    @_require_sorting
    def _test_list_sorts_desc(self):
        self._test_list_sorts(constants.SORT_DIRECTION_DESC)

    @_require_pagination
    def _test_list_pagination(self):
        for limit in range(1, len(self.resource_names) + 1):
            pagination_args = {
                'limit': limit,
            }
            body = self.list_method(**pagination_args)
            resources = self._extract_resources(body)
            self.assertEqual(limit, len(resources))

    @_require_pagination
    def _test_list_no_pagination_limit_0(self):
        pagination_args = {
            'limit': 0,
        }
        body = self.list_method(**pagination_args)
        resources = self._extract_resources(body)
        self.assertGreaterEqual(len(resources), len(self.resource_names))

    def _test_list_pagination_iteratively(self, lister):
        # first, collect all resources for later comparison
        sort_args = {
            'sort_dir': constants.SORT_DIRECTION_ASC,
            'sort_key': self.field
        }
        body = self.list_method(**sort_args)
        expected_resources = self._extract_resources(body)
        self.assertNotEmpty(expected_resources)

        resources = lister(
            len(expected_resources), sort_args
        )

        # finally, compare that the list retrieved in one go is identical to
        # the one containing pagination results
        self.assertSameOrder(expected_resources, resources)

    def _list_all_with_marker(self, niterations, sort_args):
        # paginate resources one by one, using last fetched resource as a
        # marker
        resources = []
        for i in range(niterations):
            pagination_args = sort_args.copy()
            pagination_args['limit'] = 1
            if resources:
                pagination_args['marker'] = resources[-1]['id']
            body = self.list_method(**pagination_args)
            resources_ = self._extract_resources(body)
            self.assertEqual(1, len(resources_))
            resources.extend(resources_)
        return resources

    @_require_pagination
    @_require_sorting
    def _test_list_pagination_with_marker(self):
        self._test_list_pagination_iteratively(self._list_all_with_marker)

    def _list_all_with_hrefs(self, niterations, sort_args):
        # paginate resources one by one, using next href links
        resources = []
        prev_links = {}

        for i in range(niterations):
            if prev_links:
                uri = self.get_bare_url(prev_links['next'])
            else:
                sort_args.update(self.list_kwargs)
                uri = self.list_client.build_uri(
                    self.plural_name, limit=1, **sort_args)
            prev_links, body = self.list_client.get_uri_with_links(
                self.plural_name, uri
            )
            resources_ = self._extract_resources(body)
            self.assertEqual(1, len(resources_))
            resources.extend(resources_)

        # The last element is empty and does not contain 'next' link
        uri = self.get_bare_url(prev_links['next'])
        prev_links, body = self.client.get_uri_with_links(
            self.plural_name, uri
        )
        self.assertNotIn('next', prev_links)

        # Now walk backwards and compare results
        resources2 = []
        for i in range(niterations):
            uri = self.get_bare_url(prev_links['previous'])
            prev_links, body = self.list_client.get_uri_with_links(
                self.plural_name, uri
            )
            resources_ = self._extract_resources(body)
            self.assertEqual(1, len(resources_))
            resources2.extend(resources_)

        self.assertSameOrder(resources, reversed(resources2))

        return resources

    @_require_pagination
    @_require_sorting
    def _test_list_pagination_with_href_links(self):
        self._test_list_pagination_iteratively(self._list_all_with_hrefs)

    @_require_pagination
    @_require_sorting
    def _test_list_pagination_page_reverse_with_href_links(
            self, direction=constants.SORT_DIRECTION_ASC):
        pagination_args = {
            'sort_dir': direction,
            'sort_key': self.field,
        }
        body = self.list_method(**pagination_args)
        expected_resources = self._extract_resources(body)

        page_size = 2
        pagination_args['limit'] = page_size

        prev_links = {}
        resources = []
        num_resources = len(expected_resources)
        niterations = int(math.ceil(float(num_resources) / page_size))
        for i in range(niterations):
            if prev_links:
                uri = self.get_bare_url(prev_links['previous'])
            else:
                pagination_args.update(self.list_kwargs)
                uri = self.list_client.build_uri(
                    self.plural_name, page_reverse=True, **pagination_args)
            prev_links, body = self.list_client.get_uri_with_links(
                self.plural_name, uri
            )
            resources_ = self._extract_resources(body)
            self.assertGreaterEqual(page_size, len(resources_))
            resources.extend(reversed(resources_))

        self.assertSameOrder(expected_resources, reversed(resources))

    @_require_pagination
    @_require_sorting
    def _test_list_pagination_page_reverse_asc(self):
        self._test_list_pagination_page_reverse(
            direction=constants.SORT_DIRECTION_ASC)

    @_require_pagination
    @_require_sorting
    def _test_list_pagination_page_reverse_desc(self):
        self._test_list_pagination_page_reverse(
            direction=constants.SORT_DIRECTION_DESC)

    def _test_list_pagination_page_reverse(self, direction):
        pagination_args = {
            'sort_dir': direction,
            'sort_key': self.field,
            'limit': 3,
        }
        body = self.list_method(**pagination_args)
        expected_resources = self._extract_resources(body)

        pagination_args['limit'] -= 1
        pagination_args['marker'] = expected_resources[-1]['id']
        pagination_args['page_reverse'] = True
        body = self.list_method(**pagination_args)

        self.assertSameOrder(
            # the last entry is not included in 2nd result when used as a
            # marker
            expected_resources[:-1],
            self._extract_resources(body))

    @tutils.requires_ext(extension="filter-validation", service="network")
    def _test_list_validation_filters(
            self, validation_args, filter_is_valid=True):
        if not filter_is_valid:
            self.assertRaises(lib_exc.BadRequest, self.list_method,
                              **validation_args)
        else:
            body = self.list_method(**validation_args)
            resources = self._extract_resources(body)
            for resource in resources:
                self.assertIn(resource['name'], self.resource_names)
