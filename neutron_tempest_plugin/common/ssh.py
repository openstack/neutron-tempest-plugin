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

import os

from oslo_log import log
from tempest.lib.common import ssh

from neutron_tempest_plugin import config


CONF = config.CONF
LOG = log.getLogger(__name__)


class Client(ssh.Client):

    timeout = CONF.validation.ssh_timeout

    proxy_jump_host = CONF.neutron_plugin_options.ssh_proxy_jump_host
    proxy_jump_username = CONF.neutron_plugin_options.ssh_proxy_jump_username
    proxy_jump_password = CONF.neutron_plugin_options.ssh_proxy_jump_password
    proxy_jump_keyfile = CONF.neutron_plugin_options.ssh_proxy_jump_keyfile
    proxy_jump_port = CONF.neutron_plugin_options.ssh_proxy_jump_port

    def __init__(self, host, username, password=None, timeout=None, pkey=None,
                 channel_timeout=10, look_for_keys=False, key_filename=None,
                 port=22, proxy_client=None):

        timeout = timeout or self.timeout

        if self.proxy_jump_host:
            # Perform all SSH connections passing through configured SSH server
            proxy_client = proxy_client or self.create_proxy_client(
                timeout=timeout, channel_timeout=channel_timeout)

        super(Client, self).__init__(
            host=host, username=username, password=password, timeout=timeout,
            pkey=pkey, channel_timeout=channel_timeout,
            look_for_keys=look_for_keys, key_filename=key_filename, port=port,
            proxy_client=proxy_client)

    @classmethod
    def create_proxy_client(cls, look_for_keys=True, **kwargs):
        host = cls.proxy_jump_host
        if not host:
            # proxy_jump_host string cannot be empty or None
            raise ValueError(
                "'proxy_jump_host' configuration option is empty.")

        # Let accept an empty string as a synonymous of default value on below
        # options
        password = cls.proxy_jump_password or None
        key_file = cls.proxy_jump_keyfile or None
        username = cls.proxy_jump_username

        # Port must be a positive integer
        port = cls.proxy_jump_port
        if port <= 0 or port > 65535:
            raise ValueError(
                "Invalid value for 'proxy_jump_port' configuration option: "
                "{!r}".format(port))

        login = "{username}@{host}:{port}".format(username=username, host=host,
                                                  port=port)

        if key_file:
            # expand ~ character with user HOME directory
            key_file = os.path.expanduser(key_file)
            if os.path.isfile(key_file):
                LOG.debug("Going to create SSH connection to %r using key "
                          "file: %s", login, key_file)

            else:
                # This message could help the user to identify a
                # mis-configuration in tempest.conf
                raise ValueError(
                    "Cannot find file specified as 'proxy_jump_keyfile' "
                    "option: {!r}".format(key_file))

        elif password:
            LOG.debug("Going to create SSH connection to %r using password.",
                      login)

        elif look_for_keys:
            # This message could help the user to identify a mis-configuration
            # in tempest.conf
            LOG.info("Both 'proxy_jump_password' and 'proxy_jump_keyfile' "
                     "options are empty. Going to create SSH connection to %r "
                     "looking for key file location into %r directory.",
                     login, os.path.expanduser('~/.ssh'))
        else:
            # An user that forces look_for_keys=False should really know what
            # he really wants
            LOG.warning("No authentication method provided to create an SSH "
                        "connection to %r. If it fails, then please "
                        "set 'proxy_jump_keyfile' to provide a valid SSH key "
                        "file.", login)

        return ssh.Client(
            host=host, username=username, password=password,
            look_for_keys=look_for_keys, key_filename=key_file,
            port=port, proxy_client=None, **kwargs)
