# Copyright (c) 2017 x-ion GmbH
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

import ipaddress

import testtools

from tempest.common import utils
from tempest.common import waiters
from tempest.lib.common.utils import data_utils
from tempest.lib import decorators
from tempest.lib import exceptions as lib_exc

from neutron_tempest_plugin.api import base as base_api
from neutron_tempest_plugin import config
from neutron_tempest_plugin.scenario import base
from neutron_tempest_plugin.scenario import constants


CONF = config.CONF

# Note(jh): Need to do a bit of juggling here in order to avoid failures
# when designate_tempest_plugin is not available
dns_base = testtools.try_import('designate_tempest_plugin.tests.base')
dns_waiters = testtools.try_import('designate_tempest_plugin.common.waiters')
if dns_base:
    DNSMixin = dns_base.BaseDnsV2Test
else:
    DNSMixin = object


class BaseDNSIntegrationTests(base.BaseTempestTestCase, DNSMixin):
    credentials = ['primary']

    @classmethod
    def setup_clients(cls):
        super(BaseDNSIntegrationTests, cls).setup_clients()
        cls.dns_client = cls.os_tempest.zones_client
        cls.query_client = cls.os_tempest.query_client
        cls.query_client.build_timeout = 30

    @classmethod
    def skip_checks(cls):
        super(BaseDNSIntegrationTests, cls).skip_checks()
        if not ('designate' in CONF.service_available and
                CONF.service_available.designate):
            raise cls.skipException("Designate support is required")
        if not (dns_base and dns_waiters):
            raise cls.skipException("Designate tempest plugin is missing")

    @classmethod
    @utils.requires_ext(extension="dns-integration", service="network")
    def resource_setup(cls):
        super(BaseDNSIntegrationTests, cls).resource_setup()
        _, cls.zone = cls.dns_client.create_zone()
        cls.addClassResourceCleanup(cls.dns_client.delete_zone,
            cls.zone['id'], ignore_errors=lib_exc.NotFound)
        dns_waiters.wait_for_zone_status(
            cls.dns_client, cls.zone['id'], 'ACTIVE')

        cls.network = cls.create_network(dns_domain=cls.zone['name'])
        cls.subnet = cls.create_subnet(cls.network)
        cls.subnet_v6 = cls.create_subnet(cls.network, ip_version=6)
        cls.router = cls.create_router_by_client()
        cls.create_router_interface(cls.router['id'], cls.subnet['id'])
        cls.keypair = cls.create_keypair()

    def _create_floatingip_with_dns(self, dns_name):
        return self.create_floatingip(client=self.os_primary.network_client,
                                      dns_name=dns_name,
                                      dns_domain=self.zone['name'])

    def _create_server(self, name=None):
        port = self.create_port(self.network)
        server = self.create_server(
            flavor_ref=CONF.compute.flavor_ref,
            image_ref=CONF.compute.image_ref,
            key_name=self.keypair['name'], name=name,
            networks=[{'port': port['id']}])['server']
        waiters.wait_for_server_status(self.os_primary.servers_client,
                                       server['id'],
                                       constants.SERVER_STATUS_ACTIVE)
        fip = self.create_floatingip(port=port)
        return {'port': port, 'fip': fip, 'server': server}

    def _verify_dns_records(self, address, name, found=True, record_type='A'):
        client = self.query_client
        forward = name + '.' + self.zone['name']
        reverse = ipaddress.ip_address(address).reverse_pointer
        dns_waiters.wait_for_query(client, forward, record_type, found)
        dns_waiters.wait_for_query(client, reverse, 'PTR', found)
        if not found:
            return
        fwd_response = client.query(forward, record_type)
        rev_response = client.query(reverse, 'PTR')
        for r in fwd_response:
            for rr in r.answer:
                self.assertIn(address, rr.to_text())
        for r in rev_response:
            for rr in r.answer:
                self.assertIn(forward, rr.to_text())


class DNSIntegrationTests(BaseDNSIntegrationTests):
    @decorators.idempotent_id('850ee378-4b5a-4f71-960e-0e7b12e03a34')
    def test_server_with_fip(self):
        name = data_utils.rand_name('server-test')
        server = self._create_server(name=name)
        server_ip = server['fip']['floating_ip_address']
        self._verify_dns_records(server_ip, name)
        self.delete_floatingip(server['fip'])
        self._verify_dns_records(server_ip, name, found=False)

    @decorators.idempotent_id('a8f2fade-8d5c-40f9-80f0-3de4b8d91985')
    def test_fip(self):
        name = data_utils.rand_name('fip-test')
        fip = self._create_floatingip_with_dns(name)
        addr = fip['floating_ip_address']
        self._verify_dns_records(addr, name)
        self.delete_floatingip(fip)
        self._verify_dns_records(addr, name, found=False)


class DNSIntegrationAdminTests(BaseDNSIntegrationTests,
                               base_api.BaseAdminNetworkTest):

    credentials = ['primary', 'admin']

    @classmethod
    def resource_setup(cls):
        super(DNSIntegrationAdminTests, cls).resource_setup()
        # TODO(jh): We should add the segmentation_id as tempest option
        # so that it can be changed to match the deployment if needed
        cls.network2 = cls.create_network(dns_domain=cls.zone['name'],
                provider_network_type='vxlan',
                provider_segmentation_id=12345)
        cls.subnet2 = cls.create_subnet(cls.network2)

    @decorators.idempotent_id('fa6477ce-a12b-41da-b671-5a3bbdafab07')
    def test_port_on_special_network(self):
        name = data_utils.rand_name('port-test')
        port = self.create_port(self.network2,
                                dns_name=name)
        addr = port['fixed_ips'][0]['ip_address']
        self._verify_dns_records(addr, name)
        self.client.delete_port(port['id'])
        self._verify_dns_records(addr, name, found=False)


class DNSIntegrationExtraTests(BaseDNSIntegrationTests):

    required_extensions = ["subnet-dns-publish-fixed-ip"]

    @classmethod
    def resource_setup(cls):
        super(DNSIntegrationExtraTests, cls).resource_setup()
        cls.network2 = cls.create_network()
        cls.subnet2 = cls.create_subnet(cls.network2)
        cls.subnet2_v6 = cls.create_subnet(cls.network2,
                                           ip_version=6,
                                           dns_publish_fixed_ip=True)

    @decorators.idempotent_id('e10e0e5d-69ac-4172-b39f-27ab344b7f99')
    def test_port_with_publishing_subnet(self):
        name = data_utils.rand_name('port-test')
        port = self.create_port(self.network2,
                                dns_domain=self.zone['name'],
                                dns_name=name)
        fixed_ips = port['fixed_ips']
        if fixed_ips[1]['subnet_id'] == self.subnet2_v6['id']:
            v6_index = 1
        else:
            v6_index = 0
        addr_v4 = port['fixed_ips'][1 - v6_index]['ip_address']
        addr_v6 = port['fixed_ips'][v6_index]['ip_address']
        self._verify_dns_records(addr_v6, name, record_type='AAAA')
        self._verify_dns_records(addr_v4, name, found=False)
        self.client.delete_port(port['id'])
        self._verify_dns_records(addr_v6, name, record_type='AAAA',
                                 found=False)
