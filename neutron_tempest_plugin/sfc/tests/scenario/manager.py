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

from oslo_log import log

from tempest import config
from tempest.lib.common.utils import data_utils
from tempest.lib.common.utils import test_utils
from tempest.lib import exceptions as lib_exc
from tempest.scenario import manager

CONF = config.CONF

LOG = log.getLogger(__name__)


class ScenarioTest(manager.NetworkScenarioTest):
    """Base class for scenario tests. Uses tempest own clients. """

    credentials = ['primary']

    @classmethod
    def setup_clients(cls):
        super(ScenarioTest, cls).setup_clients()
        # Clients (in alphabetical order)
        cls.keypairs_client = cls.os_primary.keypairs_client
        cls.servers_client = cls.os_primary.servers_client
        # Neutron network client
        cls.networks_client = cls.os_primary.networks_client
        cls.ports_client = cls.os_primary.ports_client
        cls.routers_client = cls.os_primary.routers_client
        cls.subnets_client = cls.os_primary.subnets_client
        cls.floating_ips_client = cls.os_primary.floating_ips_client
        cls.security_groups_client = cls.os_primary.security_groups_client
        cls.security_group_rules_client = (
            cls.os_primary.security_group_rules_client)

    # ## Test functions library
    #
    # The create_[resource] functions only return body and discard the
    # resp part which is not used in scenario tests

    def _log_net_info(self, exc):
        # network debug is called as part of ssh init
        if not isinstance(exc, lib_exc.SSHTimeout):
            LOG.debug('Network information on a devstack host')

    def check_public_network_connectivity(self, ip_address, username,
                                          private_key, should_connect=True,
                                          msg=None, servers=None, mtu=None):
        # The target login is assumed to have been configured for
        # key-based authentication by cloud-init.
        LOG.debug('checking network connections to IP %s with user: %s',
                  ip_address, username)
        try:
            self.check_vm_connectivity(ip_address,
                                       username,
                                       private_key,
                                       should_connect=should_connect,
                                       mtu=mtu)
        except Exception:
            ex_msg = 'Public network connectivity check failed'
            if msg:
                ex_msg += ": " + msg
            LOG.exception(ex_msg)
            self.log_console_output(servers)
            raise


class NetworkScenarioTest(ScenarioTest):
    """Base class for network scenario tests.

    This class provide helpers for network scenario tests, using the neutron
    API. Helpers from ancestor which use the nova network API are overridden
    with the neutron API.

    This Class also enforces using Neutron instead of novanetwork.
    Subclassed tests will be skipped if Neutron is not enabled

    """

    credentials = ['primary', 'admin']

    @classmethod
    def skip_checks(cls):
        super(NetworkScenarioTest, cls).skip_checks()
        if not CONF.service_available.neutron:
            raise cls.skipException('Neutron not available')

    def _create_router(self, client=None, tenant_id=None,
                       namestart='router-smoke'):
        if not client:
            client = self.routers_client
        if not tenant_id:
            tenant_id = client.tenant_id
        name = data_utils.rand_name(namestart)
        result = client.create_router(name=name,
                                      admin_state_up=True,
                                      tenant_id=tenant_id)
        router = result['router']
        self.assertEqual(router['name'], name)
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        client.delete_router,
                        router['id'])
        return router
