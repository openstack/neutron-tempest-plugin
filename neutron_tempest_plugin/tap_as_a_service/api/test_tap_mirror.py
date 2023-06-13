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

from oslo_utils import uuidutils

from tempest.common import utils
from tempest.lib import decorators
from tempest.lib import exceptions as lib_exc

from neutron_tempest_plugin.tap_as_a_service import base


class TapMirrorTestJSON(base.BaseTaasTest):

    @classmethod
    @utils.requires_ext(extension='tap-mirror', service='network')
    def skip_checks(cls):
        super().skip_checks()

    @classmethod
    def resource_setup(cls):
        super().resource_setup()
        cls.network = cls.create_network()
        cls.tap_mirror_port = cls.create_port(cls.network)
        cls.in_direction = {'IN': 101}
        cls.out_direction = {'OUT': 102}
        cls.both_direction = cls.in_direction | cls.out_direction
        cls.remote_ip = '192.101.0.42'
        cls.remote_ip2 = '192.101.3.43'
        cls.gre = 'gre'
        cls.erspan = 'erspanv1'

    @decorators.idempotent_id('628f202c-ed0a-4eb1-8547-4954f67a84b7')
    def test_create_tap_mirror(self):
        tap_mirror = self.create_tap_mirror(
            port_id=self.tap_mirror_port['id'],
            directions=self.in_direction,
            remote_ip=self.remote_ip,
            mirror_type=self.gre
        )
        self.assertEqual(self.tap_mirror_port['id'], tap_mirror['port_id'])
        self.assertEqual('gre', tap_mirror['mirror_type'])
        self.assertEqual(self.in_direction, tap_mirror['directions'])
        self.tap_mirrors_client.delete_tap_mirror(tap_mirror['id'])

        tap_mirror = self.create_tap_mirror(
            port_id=self.tap_mirror_port['id'],
            directions=self.both_direction,
            remote_ip=self.remote_ip,
            mirror_type=self.erspan
        )
        self.assertEqual(self.tap_mirror_port['id'], tap_mirror['port_id'])
        self.assertEqual(self.erspan, tap_mirror['mirror_type'])
        self.assertEqual(self.both_direction, tap_mirror['directions'])

    @decorators.idempotent_id('299c251b-e0bc-4449-98db-959a5d8038c2')
    def test_list_show_tap_mirror(self):
        tap_mirror = self.create_tap_mirror(
            port_id=self.tap_mirror_port['id'],
            directions=self.out_direction,
            remote_ip=self.remote_ip,
            mirror_type=self.gre
        )
        tap_mirrors = self.tap_mirrors_client.list_tap_mirrors()
        is_t_m_found = False
        for t_m in tap_mirrors['tap_mirrors']:
            if t_m['id'] == tap_mirror['id']:
                is_t_m_found = True
                break
        self.assertTrue(is_t_m_found)
        tap_mirror_show_res = self.tap_mirrors_client.show_tap_mirror(
            tap_mirror['id'])['tap_mirror']
        self.assertEqual(tap_mirror['id'], tap_mirror_show_res['id'])
        self.assertEqual(self.gre, tap_mirror_show_res['mirror_type'])
        self.assertEqual(self.remote_ip,
                         tap_mirror_show_res['remote_ip'])
        self.assertEqual(self.out_direction,
                         tap_mirror_show_res['directions'])

    @decorators.idempotent_id('19c40379-bda5-48c9-8873-fc990739d1b5')
    def test_update_tap_mirror(self):
        tap_mirror = self.create_tap_mirror(
            port_id=self.tap_mirror_port['id'],
            directions=self.in_direction,
            remote_ip=self.remote_ip,
            mirror_type=self.gre
        )
        self.tap_mirrors_client.update_tap_mirror(
            tap_mirror_id=tap_mirror['id'],
            name='new_name',
            description='My fancy Tap Mirror'
        )
        tap_mirror_show_res = self.tap_mirrors_client.show_tap_mirror(
            tap_mirror['id'])['tap_mirror']
        self.assertEqual('new_name', tap_mirror_show_res['name'])
        self.assertEqual('My fancy Tap Mirror',
                         tap_mirror_show_res['description'])

    @decorators.idempotent_id('9ed165af-7c54-43ac-b14f-077e8f9601f6')
    def test_delete_mirror_port_deletes_tap_mirror(self):
        port1 = self.create_port(self.network)
        tap_mirror = self.create_tap_mirror(
            port_id=port1['id'],
            directions=self.out_direction,
            remote_ip=self.remote_ip,
            mirror_type=self.gre
        )
        # Delete port will result in deteltion of the tap_mirror
        self.ports_client.delete_port(port1['id'])
        self.assertRaises(lib_exc.NotFound,
                          self.tap_mirrors_client.show_tap_mirror,
                          tap_mirror['id'])

    @decorators.idempotent_id('abdd4451-bd9d-4f1e-ab7f-e949b9246714')
    def test_delete_tap_mirror_port_remains(self):
        port1 = self.create_port(self.network)
        tap_mirror = self.create_tap_mirror(
            port_id=port1['id'],
            directions=self.out_direction,
            remote_ip=self.remote_ip,
            mirror_type=self.gre
        )
        # Delete tap_mirror will keep the port
        self.tap_mirrors_client.delete_tap_mirror(tap_mirror['id'])
        port_res = self.ports_client.show_port(port1['id'])['port']
        self.assertEqual(port1['name'], port_res['name'])

    @decorators.idempotent_id('1d8b68fc-a600-4b9e-bd17-9469c3a6c95b')
    def test_create_tap_mirror_negative(self):
        # directions keys' valid values are IN and OUT
        self.assertRaises(lib_exc.BadRequest,
                          self.create_tap_mirror,
                          port_id=self.tap_mirror_port['id'],
                          directions={'something': 101},
                          remote_ip=self.remote_ip,
                          mirror_type=self.gre)
        # mirror_type valid values are erspanv1 and gre
        self.assertRaises(lib_exc.BadRequest,
                          self.create_tap_mirror,
                          port_id=self.tap_mirror_port['id'],
                          directions=self.out_direction,
                          remote_ip=self.remote_ip,
                          mirror_type='erspanv2')
        # remote_ip must be a valid IP
        self.assertRaises(lib_exc.BadRequest,
                          self.create_tap_mirror,
                          port_id=self.tap_mirror_port['id'],
                          directions=self.in_direction,
                          remote_ip='192.101.0.420',
                          mirror_type=self.gre)

    @decorators.idempotent_id('2b7850b3-3920-4f16-96b7-05e2efd96877')
    def test_create_tap_service_tunnel_id_conflict(self):
        self.create_tap_mirror(
            port_id=self.tap_mirror_port['id'],
            directions=self.in_direction,
            remote_ip=self.remote_ip,
            mirror_type=self.gre
        )

        port2 = self.create_port(self.network)
        self.addCleanup(self.ports_client.delete_port, port2['id'])
        self.assertRaises(lib_exc.Conflict,
                          self.create_tap_mirror,
                          port_id=port2['id'],
                          directions=self.in_direction,
                          remote_ip='192.101.0.4',
                          mirror_type=self.gre)

    @decorators.idempotent_id('95ef1cc1-cd57-4193-a88e-716795e39ebf')
    def test_create_tap_mirror_non_existing_port(self):
        not_exists = uuidutils.generate_uuid()
        self.assertRaises(lib_exc.NotFound,
                          self.create_tap_mirror,
                          port_id=not_exists,
                          directions=self.out_direction,
                          remote_ip=self.remote_ip,
                          mirror_type=self.gre)

    @decorators.idempotent_id('123202cd-d810-4c15-bae7-26d69b24a1a4')
    def test_multiple_mirrors_for_port(self):
        port1 = self.create_port(self.network)
        tap_mirror = self.create_tap_mirror(
            port_id=port1['id'],
            directions=self.out_direction,
            remote_ip=self.remote_ip,
            mirror_type=self.gre
        )
        self.addCleanup(self.tap_mirrors_client.delete_tap_mirror,
                        tap_mirror['id'])

        # Creation of the 2nd mirror in case the direction: tunnel_id dict
        # is different.
        tap_mirror2 = self.create_tap_mirror(
            port_id=port1['id'],
            directions={'OUT': 103},
            remote_ip=self.remote_ip2,
            mirror_type=self.gre
        )

        # We have a conflict if the direction: tunnel_id dict is the
        # same
        self.tap_mirrors_client.delete_tap_mirror(tap_mirror2['id'])
        self.assertRaises(lib_exc.Conflict,
                          self.create_tap_mirror,
                          port_id=port1['id'],
                          directions=self.out_direction,
                          remote_ip='192.101.0.4',
                          mirror_type=self.gre)
