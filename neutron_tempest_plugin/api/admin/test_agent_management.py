# Copyright 2013 IBM Corp.
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

from neutron_tempest_plugin.common import tempest_fixtures
from tempest.lib.common.utils import data_utils
from tempest.lib import decorators
from tempest.lib import exceptions as lib_exc

from neutron_tempest_plugin.api import base


class AgentManagementTestJSON(base.BaseAdminNetworkTest):

    required_extensions = ['agent']

    @classmethod
    def resource_setup(cls):
        super(AgentManagementTestJSON, cls).resource_setup()
        body = cls.admin_client.list_agents()
        agents = body['agents']
        cls.agent = agents[0]  # don't modify this agent

    @decorators.idempotent_id('9c80f04d-11f3-44a4-8738-ed2f879b0ff4')
    def test_list_agent(self):
        body = self.admin_client.list_agents()
        agents = body['agents']
        # Heartbeats must be excluded from comparison
        self.agent.pop('heartbeat_timestamp', None)
        self.agent.pop('configurations', None)
        # Exclude alive as it can happen that when testclass'
        # resource_setup executed the selected agent is not up
        self.agent.pop('alive', None)
        for agent in agents:
            agent.pop('heartbeat_timestamp', None)
            agent.pop('configurations', None)
            agent.pop('alive', None)
        self.assertIn(self.agent, agents)

    @decorators.idempotent_id('e335be47-b9a1-46fd-be30-0874c0b751e6')
    def test_list_agents_non_admin(self):
        body = self.client.list_agents()
        self.assertEqual(len(body["agents"]), 0)

    @decorators.idempotent_id('869bc8e8-0fda-4a30-9b71-f8a7cf58ca9f')
    def test_show_agent(self):
        body = self.admin_client.show_agent(self.agent['id'])
        agent = body['agent']
        self.assertEqual(agent['id'], self.agent['id'])

    @decorators.idempotent_id('371dfc5b-55b9-4cb5-ac82-c40eadaac941')
    def test_update_agent_status(self):
        origin_status = self.agent['admin_state_up']
        # Try to update the 'admin_state_up' to the original
        # one to avoid the negative effect.
        agent_status = {'admin_state_up': origin_status}
        body = self.admin_client.update_agent(agent_id=self.agent['id'],
                                              agent_info=agent_status)
        updated_status = body['agent']['admin_state_up']
        self.assertEqual(origin_status, updated_status)

    @decorators.idempotent_id('68a94a14-1243-46e6-83bf-157627e31556')
    def test_update_agent_description(self):
        agents = self.admin_client.list_agents()['agents']
        dyn_agent = self._select_one_agent_for_update(agents)

        self.useFixture(tempest_fixtures.LockFixture('agent_description'))
        description = 'description for update agent.'
        agent_description = {'description': description}
        body = self.admin_client.update_agent(agent_id=dyn_agent['id'],
                                              agent_info=agent_description)
        self.addCleanup(self._restore_agent, dyn_agent)
        updated_description = body['agent']['description']
        self.assertEqual(updated_description, description)

    def _restore_agent(self, dyn_agent):
        """Restore the agent description after update test."""
        description = dyn_agent['description']
        origin_agent = {'description': description}
        self.admin_client.update_agent(agent_id=dyn_agent['id'],
                                       agent_info=origin_agent)

    def _select_one_agent_for_update(self, agents):
        """Return one agent that is not the one selected at resource_setup"""
        for agent in agents:
            if self.agent['id'] != agent['id']:
                return agent
        raise self.skipException("This test requires at least two agents.")

    @decorators.idempotent_id('b33af888-b6ac-4e68-a0ca-0444c2696cf9')
    def test_delete_agent_negative(self):
        non_existent_id = data_utils.rand_uuid()
        self.assertRaises(
            lib_exc.NotFound,
            self.admin_client.delete_agent, non_existent_id)
