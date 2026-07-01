# Copyright (c) 2015 Midokura SARL
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

from oslo_log import log as logging
from tempest import config

from tempest.lib import exceptions as lib_exc

from neutron_tempest_plugin.common import ssh
from neutron_tempest_plugin.fwaas.common import fwaas_v2_client
from neutron_tempest_plugin.scenario import base as scenario_base

CONF = config.CONF
LOG = logging.getLogger(__name__)

DEFAULT_FWG = 'default'


class FWaaSScenarioTestBase:

    def check_ssh_connectivity(self, ip_address, username=None,
                               private_key=None, should_connect=True):
        """Check SSH reachability, including expected negative checks."""
        connect_timeout = CONF.validation.connect_timeout
        kwargs = {}
        if not should_connect:
            # Use a shorter timeout for negative cases.
            kwargs['timeout'] = 1
        try:
            client = ssh.Client(ip_address, username, pkey=private_key,
                                channel_timeout=connect_timeout,
                                **kwargs)
            client.test_connection_auth()
        except lib_exc.SSHTimeout:
            if should_connect:
                raise
        else:
            self.assertTrue(should_connect, "Unexpectedly reachable")

    def _create_server(self, network, security_group=None):
        keys = self.create_keypair()
        port_kwargs = {}
        if security_group is not None:
            port_kwargs['security_groups'] = [security_group['id']]
        port = self.create_port(network, **port_kwargs)
        server_kwargs = {
            'flavor_ref': CONF.compute.flavor_ref,
            'image_ref': CONF.compute.image_ref,
            'key_name': keys['name'],
            'networks': [{'port': port['id']}]}
        if security_group is not None:
            server_kwargs['security_groups'] = [
                {'name': security_group['name']}]
        server = self.create_server(**server_kwargs)
        return server['server'], keys, port

    def _check_server_connectivity(self, floating_ip, keys1, address_list,
                                   should_connect=True, ssh_source=None,
                                   servers=None):
        if ssh_source is None:
            ssh_source = ssh.Client(
                floating_ip['floating_ip_address'],
                CONF.validation.image_ssh_user,
                pkey=keys1)

        for remote_ip in address_list:
            self.check_remote_connectivity(
                ssh_source, remote_ip, ping_count=1,
                should_succeed=should_connect,
                servers=servers)

    def _create_network_subnet(self, prefix="smoke-",
                               port_security_enabled=True):
        network = self.create_network(
            network_name="network-%s" % prefix,
            port_security_enabled=port_security_enabled)
        subnet = self.create_subnet(
            network=network, name="subnet-%s" % prefix)
        return network, subnet

    def _create_router_with_external_gateway(self, namestart, subnet_id=None):
        router = self.create_router(
            router_name=namestart,
            admin_state_up=True,
            external_network_id=CONF.network.public_network_id)
        if subnet_id:
            self.create_router_interface(router['id'], subnet_id=subnet_id)
        return router

    def _create_fip_access_policies(self):
        fw_allow_icmp_rule = self.create_firewall_rule(
            action="allow", protocol="icmp")
        fw_allow_ssh_rule = self.create_firewall_rule(
            action="allow", protocol="tcp", destination_port=22)
        fw_allow_egress_ssh_rule = self.create_firewall_rule(
            action="allow", protocol="tcp", source_port=22)
        fw_ingress_policy = self.create_firewall_policy(
            firewall_rules=[fw_allow_icmp_rule['id'], fw_allow_ssh_rule['id']])
        fw_egress_policy = self.create_firewall_policy(
            firewall_rules=[fw_allow_icmp_rule['id'],
                            fw_allow_egress_ssh_rule['id']])
        return (fw_allow_icmp_rule, fw_allow_ssh_rule,
                fw_allow_egress_ssh_rule, fw_ingress_policy, fw_egress_policy)

    def _get_default_firewall_group(self):
        fw_groups = self.firewall_groups_client.list_firewall_groups()[
            'firewall_groups']
        default_fwgs = [fwg for fwg in fw_groups if fwg['name'] == DEFAULT_FWG]
        return default_fwgs[0] if default_fwgs else None

    def _dissociate_ports_from_default_firewall_group(self, port_ids):
        default_fwg = self._get_default_firewall_group()
        if default_fwg is None:
            return
        remaining_ports = [port_id for port_id in default_fwg.get('ports', [])
                           if port_id not in port_ids]
        self.update_firewall_group_and_wait(default_fwg['id'],
                                            ports=remaining_ports)


class FWaaSScenarioTest_V2(fwaas_v2_client.FWaaSClientMixin,
                           FWaaSScenarioTestBase,
                           scenario_base.BaseTempestTestCase):
    credentials = ['primary', 'admin']
    required_extensions = ['fwaas_v2', 'router']
