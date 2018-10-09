# Copyright 2016 OpenStack Foundation
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

from tempest.common import utils
from tempest.lib.common.utils import data_utils
from tempest.lib.common.utils import test_utils
from tempest.lib import decorators
from tempest.lib import exceptions

from neutron_tempest_plugin.api import base

from neutron_lib import constants as lib_constants

# 3 IP addresses are taken from every total for IPv4 these are reserved
DEFAULT_IP4_RESERVED = 3
# 2 IP addresses are taken from every total for IPv6 these are reserved
# I assume the reason for having one less than IPv4 is it does not have
# broadcast address
DEFAULT_IP6_RESERVED = 2

DELETE_TIMEOUT = 10
DELETE_SLEEP = 2


class NetworksIpAvailabilityTest(base.BaseAdminNetworkTest):
    """Tests Networks IP Availability

    Tests the following operations in the Neutron API using the REST client for
    Neutron:

        test total and used ips for net create
        test total and ips for net after subnet create
        test total and used ips for net after subnet and port create

    """

    @classmethod
    @utils.requires_ext(extension="network-ip-availability", service="network")
    def skip_checks(cls):
        super(NetworksIpAvailabilityTest, cls).skip_checks()

    @staticmethod
    def _get_availability(network, net_availability):
        if 'network_ip_availabilities' in net_availability:
            for availability in net_availability['network_ip_availabilities']:
                if availability['network_id'] == network['id']:
                    return availability
            raise exceptions.TempestException('Network IP Availability not '
                                              'found')
        else:
            return net_availability['network_ip_availability']

    def _get_used_ips(self, network, net_availability):
        availability = self._get_availability(network, net_availability)
        return availability and availability['used_ips']

    def _assert_total_and_used_ips(self, expected_used, expected_total,
                                   network, net_availability):
        availability = self._get_availability(network, net_availability)
        self.assertEqual(expected_total, availability['total_ips'])
        self.assertEqual(expected_used, availability['used_ips'])


def calc_total_ips(prefix, ip_version):
    # will calculate total ips after removing reserved.
    if ip_version == lib_constants.IP_VERSION_4:
        total_ips = 2 ** (lib_constants.IPv4_BITS -
                          prefix) - DEFAULT_IP4_RESERVED
    elif ip_version == lib_constants.IP_VERSION_6:
        total_ips = 2 ** (lib_constants.IPv6_BITS -
                          prefix) - DEFAULT_IP6_RESERVED
    return total_ips


class NetworksIpAvailabilityIPv4Test(NetworksIpAvailabilityTest):

    def setUp(self):
        super(NetworksIpAvailabilityIPv4Test, self).setUp()
        net_name = data_utils.rand_name('network')
        self.network = self.create_network(network_name=net_name)

    @decorators.idempotent_id('0f33cc8c-1bf6-47d1-9ce1-010618240599')
    def test_list_ip_availability_before_subnet(self):
        net_availability = self.admin_client.list_network_ip_availabilities()
        self._assert_total_and_used_ips(0, 0, self.network, net_availability)

    @decorators.idempotent_id('3aecd3b2-16ed-4b87-a54a-91d7b3c2986b')
    def test_list_ip_availability_after_subnet_and_ports(self):
        subnet = self.create_subnet(self.network, enable_dhcp=False)
        prefix = netaddr.IPNetwork(subnet['cidr']).prefixlen
        body = self.admin_client.list_network_ip_availabilities()
        used_ips_before_port_create = self._get_used_ips(self.network, body)
        self.create_port(self.network)
        net_availability = self.admin_client.list_network_ip_availabilities()
        self._assert_total_and_used_ips(
            used_ips_before_port_create + 1,
            calc_total_ips(prefix, self._ip_version),
            self.network, net_availability)

    @decorators.idempotent_id('9f11254d-757b-492e-b14b-f52144e4ee7b')
    def test_list_ip_availability_after_port_delete(self):
        self.create_subnet(self.network, enable_dhcp=False)
        port = self.create_port(self.network)
        net_availability = self.admin_client.list_network_ip_availabilities()
        used_ips = self._get_used_ips(self.network, net_availability)
        self.client.delete_port(port['id'])

        def is_count_ip_availability_valid():
            availabilities = self.admin_client.list_network_ip_availabilities()
            used_ips_after_port_delete = self._get_used_ips(self.network,
                                                            availabilities)
            return used_ips - 1 == used_ips_after_port_delete

        self.assertTrue(
            test_utils.call_until_true(
                is_count_ip_availability_valid, DELETE_TIMEOUT, DELETE_SLEEP),
            msg="IP address did not become available after port delete")

    @decorators.idempotent_id('da1fbed5-b4a9-45b3-bdcb-b1660710d565')
    def test_show_ip_availability_after_subnet_and_ports_create(self):
        net_availability = self.admin_client.show_network_ip_availability(
            self.network['id'])
        self._assert_total_and_used_ips(0, 0, self.network, net_availability)
        subnet = self.create_subnet(self.network, enable_dhcp=False)
        prefix = netaddr.IPNetwork(subnet['cidr']).prefixlen
        net_availability = self.admin_client.show_network_ip_availability(
            self.network['id'])
        used_ips_before_port_create = self._get_used_ips(self.network,
                                                         net_availability)
        self.create_port(self.network)
        net_availability = self.admin_client.show_network_ip_availability(
            self.network['id'])
        self._assert_total_and_used_ips(
            used_ips_before_port_create + 1,
            calc_total_ips(prefix, self._ip_version),
            self.network,
            net_availability)

    @decorators.idempotent_id('a4d1e291-c152-4d62-9316-8c9bf1c6aee2')
    def test_show_ip_availability_after_port_delete(self):
        self.create_subnet(self.network, enable_dhcp=False)
        port = self.create_port(self.network)
        net_availability = self.admin_client.show_network_ip_availability(
            self.network['id'])
        used_ips = self._get_used_ips(self.network, net_availability)
        self.client.delete_port(port['id'])

        def is_count_ip_availability_valid():
            availabilities = self.admin_client.show_network_ip_availability(
                self.network['id'])
            used_ips_after_port_delete = self._get_used_ips(self.network,
                                                            availabilities)
            return used_ips - 1 == used_ips_after_port_delete

        self.assertTrue(
            test_utils.call_until_true(
                is_count_ip_availability_valid, DELETE_TIMEOUT, DELETE_SLEEP),
            msg="IP address did not become available after port delete")


class NetworksIpAvailabilityIPv6Test(NetworksIpAvailabilityIPv4Test):

    _ip_version = lib_constants.IP_VERSION_6
