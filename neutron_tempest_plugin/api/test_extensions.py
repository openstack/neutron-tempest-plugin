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

from tempest.common import utils
from tempest import config
from tempest.lib import decorators

from neutron_tempest_plugin.api import base


CONF = config.CONF


class ExtensionsTest(base.BaseNetworkTest):

    def _test_list_extensions_includes(self, exts):
        body = self.client.list_extensions()
        extensions = {ext_['alias'] for ext_ in body['extensions']}
        self.assertNotEmpty(extensions, "Extension list returned is empty")
        for ext in exts:
            ext_enabled = utils.is_extension_enabled(ext, "network")
            if ext_enabled:
                self.assertIn(ext, extensions)
            else:
                self.assertNotIn(ext, extensions)

    @decorators.idempotent_id('262420b7-a4bb-4a3e-b4b5-e73bad18df8c')
    def test_list_extensions_sorting(self):
        self._test_list_extensions_includes(['sorting'])

    @decorators.idempotent_id('19db409e-a23f-445d-8bc8-ca3d64c84706')
    def test_list_extensions_pagination(self):
        self._test_list_extensions_includes(['pagination'])

    @decorators.idempotent_id('155b7bc2-e358-4dd8-bf3e-1774c084567f')
    def test_list_extensions_project_id(self):
        self._test_list_extensions_includes(['project-id'])

    @decorators.idempotent_id('c7597fac-2404-45b1-beb4-523c8b1d4604')
    def test_list_extensions_includes_all(self):
        extensions = CONF.network_feature_enabled.api_extensions
        if not extensions:
            raise self.skipException("Extension list is empty")
        if extensions[0] == 'all':
            raise self.skipException("No lists of enabled extensions provided")

        self._test_list_extensions_includes(extensions)
