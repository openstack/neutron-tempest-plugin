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

from oslo_log import log
from tempest.common import utils
from tempest.common import waiters
from tempest.lib.common.utils import data_utils
from tempest.lib.common.utils import test_utils
from tempest.lib import decorators
from tempest.lib import exceptions as lib_exc

from neutron_tempest_plugin.api import base as base_api
from neutron_tempest_plugin import config
from neutron_tempest_plugin.scenario import base
from neutron_tempest_plugin.scenario import constants


CONF = config.CONF
LOG = log.getLogger(__name__)


# Note(jh): Need to do a bit of juggling here in order to avoid failures
# when designate_tempest_plugin is not available
dns_base = testtools.try_import('designate_tempest_plugin.tests.base')
dns_waiters = testtools.try_import('designate_tempest_plugin.common.waiters')
if dns_base:
    DNSMixin = dns_base.BaseDnsV2Test
else:
    DNSMixin = object


class BaseDNSIntegrationTests(base.BaseTempestTestCase, DNSMixin):
    credentials = ['primary', 'admin']

    @classmethod
    def setup_clients(cls):
        super(BaseDNSIntegrationTests, cls).setup_clients()
        cls.zone_client = cls.os_tempest.dns_v2.ZonesClient()
        cls.recordset_client = cls.os_tempest.dns_v2.RecordsetClient()
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
        cls.zone = cls.zone_client.create_zone()[1]
        cls.addClassResourceCleanup(cls.zone_client.delete_zone,
            cls.zone['id'], ignore_errors=lib_exc.NotFound)
        dns_waiters.wait_for_zone_status(
            cls.zone_client, cls.zone['id'], 'ACTIVE')

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

    def _check_type_in_recordsets(self, zone_id, rec_type):
        types = [rec['type'] for rec in self.recordset_client.list_recordset(
            zone_id)[1]['recordsets']]
        if rec_type in types:
            return True
        return False

    def _wait_for_type_in_recordsets(self, zone_id, type):
        test_utils.call_until_true(
            func=self._check_type_in_recordsets, zone_id=zone_id,
            rec_type=type, duration=self.query_client.build_timeout,
            sleep_for=5)

    def _check_recordset_deleted(
            self, recordset_client, zone_id, recordset_id):
        return test_utils.call_and_ignore_notfound_exc(
            recordset_client.show_recordset, zone_id, recordset_id) is None

    def _verify_designate_recordset(
            self, address, found=True, record_type='A'):
        if found:
            self._wait_for_type_in_recordsets(self.zone['id'], record_type)
            recordsets = self.recordset_client.list_recordset(
                self.zone['id'])[1]['recordsets']
            relevant_type = [rec for rec in recordsets if
                             rec['type'] == record_type]
            self.assertTrue(
                relevant_type,
                'Failed no {} type recordset has been detected in the '
                'Designate DNS DB'.format(record_type))
            rec_id = [rec['id'] for rec in relevant_type if address in
                      str(rec['records'])][0]
            self.assertTrue(
                rec_id, 'Record of type:{} with IP:{} was not detected in '
                        'the Designate DNS DB'.format(record_type, address))
            dns_waiters.wait_for_recordset_status(
                self.recordset_client, self.zone['id'], rec_id, 'ACTIVE')
        else:
            rec_id = None
            recordsets = self.recordset_client.list_recordset(
                self.zone['id'])[1]['recordsets']
            relevant_type = [rec for rec in recordsets if
                             rec['type'] == record_type]
            if relevant_type:
                rec_id = [rec['id'] for rec in relevant_type if
                          address in str(rec['records'])][0]
            if rec_id:
                recordset_exists = test_utils.call_until_true(
                    func=self._check_recordset_deleted,
                    recordset_client=self.recordset_client,
                    zone_id=self.zone['id'], recordset_id=rec_id,
                    duration=self.query_client.build_timeout, sleep_for=5)
                self.assertTrue(
                    recordset_exists,
                    'Failed, recordset type:{} and ID:{} is still exist in '
                    'the Designate DNS DB'.format(record_type, rec_id))

    def _verify_dns_records(self, address, name, found=True, record_type='A'):
        client = self.query_client
        forward = name + '.' + self.zone['name']
        reverse = ipaddress.ip_address(address).reverse_pointer
        record_types_to_check = [record_type, 'PTR']
        for rec_type in record_types_to_check:
            try:
                if rec_type == 'PTR':
                    dns_waiters.wait_for_query(
                        client, reverse, rec_type, found)
                else:
                    dns_waiters.wait_for_query(
                        client, forward, rec_type, found)
            except Exception as e:
                LOG.error(e)
                self._verify_designate_recordset(address, found, rec_type)
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
        segmentation_id = CONF.designate_feature_enabled.segmentation_id
        cls.network2 = cls.create_network(
            dns_domain=cls.zone['name'], provider_network_type='vxlan',
            provider_segmentation_id=segmentation_id)
        cls.subnet2 = cls.create_subnet(cls.network2)

    def _verify_dns_assignment(self, port):
        expected_fqdn = '%s.%s' % (port['dns_name'], self.zone['name'])
        self.assertEqual(expected_fqdn, port['dns_assignment'][0]['fqdn'])

    @decorators.idempotent_id('fa6477ce-a12b-41da-b671-5a3bbdafab07')
    def test_port_on_special_network(self):
        name = data_utils.rand_name('port-test')
        port = self.create_port(self.network2,
                                dns_name=name)
        self._verify_dns_assignment(port)
        addr = port['fixed_ips'][0]['ip_address']
        self._verify_dns_records(addr, name)
        self.client.delete_port(port['id'])
        self._verify_dns_records(addr, name, found=False)

    @decorators.idempotent_id('d44cd5b8-ac67-4965-96ff-cb77ab6aea8b')
    def test_fip_admin_delete(self):
        name = data_utils.rand_name('fip-test')
        fip = self._create_floatingip_with_dns(name)
        addr = fip['floating_ip_address']
        self._verify_dns_records(addr, name)
        self.delete_floatingip(fip, client=self.admin_client)
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


class DNSIntegrationDomainPerProjectTests(BaseDNSIntegrationTests):

    credentials = ['primary', 'admin']

    required_extensions = ['subnet-dns-publish-fixed-ip',
                           'dns-integration-domain-keywords']

    @classmethod
    def resource_setup(cls):
        super(BaseDNSIntegrationTests, cls).resource_setup()

        name = data_utils.rand_name('test-domain')
        zone_name = "%s.%s.%s.zone." % (cls.client.user_id,
                                        cls.client.project_id,
                                        name)
        dns_domain_template = "<user_id>.<project_id>.%s.zone." % name

        cls.zone = cls.zone_client.create_zone(name=zone_name)[1]
        cls.addClassResourceCleanup(cls.zone_client.delete_zone,
            cls.zone['id'], ignore_errors=lib_exc.NotFound)
        dns_waiters.wait_for_zone_status(
            cls.zone_client, cls.zone['id'], 'ACTIVE')

        cls.network = cls.create_network(dns_domain=dns_domain_template)
        cls.subnet = cls.create_subnet(cls.network,
                                       dns_publish_fixed_ip=True)
        cls.subnet_v6 = cls.create_subnet(cls.network,
                                          ip_version=6,
                                          dns_publish_fixed_ip=True)
        cls.router = cls.create_router_by_client()
        cls.create_router_interface(cls.router['id'], cls.subnet['id'])
        cls.keypair = cls.create_keypair()

    @decorators.idempotent_id('43a67509-3161-4125-8f2c-0d4a67599721')
    def test_port_with_dns_name(self):
        name = data_utils.rand_name('port-test')
        port = self.create_port(self.network,
                                dns_name=name)
        addr = port['fixed_ips'][0]['ip_address']
        self._verify_dns_records(addr, name)
        self.client.delete_port(port['id'])
        self._verify_dns_records(addr, name, found=False)

    @decorators.idempotent_id('ac89db9b-5ca4-43bd-85ba-40fbeb47e208')
    def test_fip_admin_delete(self):
        name = data_utils.rand_name('fip-test')
        fip = self._create_floatingip_with_dns(name)
        addr = fip['floating_ip_address']
        self._verify_dns_records(addr, name)
        self.delete_floatingip(fip, client=self.admin_client)
        self._verify_dns_records(addr, name, found=False)
