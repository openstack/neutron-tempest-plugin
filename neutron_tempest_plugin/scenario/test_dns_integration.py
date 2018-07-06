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


class DNSIntegrationTests(base.BaseTempestTestCase, DNSMixin):
    credentials = ['primary']

    @classmethod
    def setup_clients(cls):
        super(DNSIntegrationTests, cls).setup_clients()
        cls.dns_client = cls.os_tempest.zones_client
        cls.query_client = cls.os_tempest.query_client
        cls.query_client.build_timeout = 30

    @classmethod
    def skip_checks(cls):
        super(DNSIntegrationTests, cls).skip_checks()
        if not ('designate' in CONF.service_available and
                CONF.service_available.designate):
            raise cls.skipException("Designate support is required")
        if not (dns_base and dns_waiters):
            raise cls.skipException("Designate tempest plugin is missing")

    @classmethod
    @utils.requires_ext(extension="dns-integration", service="network")
    def resource_setup(cls):
        super(DNSIntegrationTests, cls).resource_setup()
        _, cls.zone = cls.dns_client.create_zone()
        cls.addClassResourceCleanup(cls.dns_client.delete_zone,
            cls.zone['id'], ignore_errors=lib_exc.NotFound)
        dns_waiters.wait_for_zone_status(
            cls.dns_client, cls.zone['id'], 'ACTIVE')

        cls.network = cls.create_network(dns_domain=cls.zone['name'])
        cls.subnet = cls.create_subnet(cls.network)
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

    def _verify_dns_records(self, address, name):
        forward = name + '.' + self.zone['name']
        reverse = ipaddress.ip_address(address).reverse_pointer
        dns_waiters.wait_for_query(self.query_client, forward, 'A')
        dns_waiters.wait_for_query(self.query_client, reverse, 'PTR')
        fwd_response = self.query_client.query(forward, 'A')
        rev_response = self.query_client.query(reverse, 'PTR')
        for r in fwd_response:
            for rr in r.answer:
                self.assertIn(address, rr.to_text())
        for r in rev_response:
            for rr in r.answer:
                self.assertIn(forward, rr.to_text())

    @decorators.idempotent_id('850ee378-4b5a-4f71-960e-0e7b12e03a34')
    def test_server_with_fip(self):
        name = data_utils.rand_name('server-test')
        server = self._create_server(name=name)
        server_ip = server['fip']['floating_ip_address']
        self._verify_dns_records(server_ip, name)

    @decorators.idempotent_id('a8f2fade-8d5c-40f9-80f0-3de4b8d91985')
    def test_fip(self):
        name = data_utils.rand_name('fip-test')
        fip = self._create_floatingip_with_dns(name)
        self._verify_dns_records(fip['floating_ip_address'], name)
