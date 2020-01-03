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

import locale
import os
import socket
import time

from oslo_log import log
import paramiko
import six
from tempest.lib.common import ssh
from tempest.lib import exceptions
import tenacity

from neutron_tempest_plugin import config
from neutron_tempest_plugin import exceptions as exc


CONF = config.CONF
LOG = log.getLogger(__name__)


RETRY_EXCEPTIONS = (exceptions.TimeoutException, paramiko.SSHException,
                    socket.error)
if six.PY2:
    # NOTE(ralonsoh): TimeoutError was added in 3.3 and corresponds to
    # OSError(errno.ETIMEDOUT)
    RETRY_EXCEPTIONS += (OSError, )
else:
    RETRY_EXCEPTIONS += (TimeoutError, )


class Client(ssh.Client):

    default_ssh_lang = 'en_US.UTF-8'

    timeout = CONF.validation.ssh_timeout

    proxy_jump_host = CONF.neutron_plugin_options.ssh_proxy_jump_host
    proxy_jump_username = CONF.neutron_plugin_options.ssh_proxy_jump_username
    proxy_jump_password = CONF.neutron_plugin_options.ssh_proxy_jump_password
    proxy_jump_keyfile = CONF.neutron_plugin_options.ssh_proxy_jump_keyfile
    proxy_jump_port = CONF.neutron_plugin_options.ssh_proxy_jump_port

    def __init__(self, host, username, password=None, timeout=None, pkey=None,
                 channel_timeout=10, look_for_keys=False, key_filename=None,
                 port=22, proxy_client=None, create_proxy_client=True):

        timeout = timeout or self.timeout

        if not proxy_client and create_proxy_client and self.proxy_jump_host:
            # Perform all SSH connections passing through configured SSH server
            proxy_client = self.create_proxy_client(
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

        return Client(
            host=host, username=username, password=password,
            look_for_keys=look_for_keys, key_filename=key_file,
            port=port, create_proxy_client=False, **kwargs)

    def connect(self, *args, **kwargs):
        """Creates paramiko.SSHClient and connect it to remote SSH server

        :returns: paramiko.Client connected to remote server.

        :raises tempest.lib.exceptions.SSHTimeout: in case it fails to connect
        to remote server.
        """
        return super(Client, self)._get_ssh_connection(*args, **kwargs)

    # This overrides superclass test_connection_auth method forbidding it to
    # close connection
    test_connection_auth = connect

    def open_session(self):
        """Gets connection to SSH server and open a new paramiko.Channel

        :returns: new paramiko.Channel
        """

        client = self.connect()

        try:
            return client.get_transport().open_session()
        except paramiko.SSHException:
            # the request is rejected, the session ends prematurely or
            # there is a timeout opening a channel
            LOG.exception("Unable to open SSH session")
            raise exceptions.SSHTimeout(host=self.host,
                                        user=self.username,
                                        password=self.password)

    @tenacity.retry(
        stop=tenacity.stop_after_attempt(10),
        wait=tenacity.wait_fixed(1),
        retry=tenacity.retry_if_exception_type(RETRY_EXCEPTIONS),
        reraise=True)
    def exec_command(self, cmd, encoding="utf-8", timeout=None):
        if timeout:
            original_timeout = self.timeout
            self.timeout = timeout
        try:
            return super(Client, self).exec_command(cmd=cmd, encoding=encoding)
        finally:
            if timeout:
                self.timeout = original_timeout

    def execute_script(self, script, become_root=False, combine_stderr=False,
                       shell='sh -eux', timeout=None, **params):
        """Connect to remote machine and executes script.

        Implementation note: it passes script lines to shell interpreter via
        STDIN. Therefore script line number could be not available to some
        script interpreters for debugging porposes.

        :param script: script lines to be executed.

        :param become_root: executes interpreter as root with sudo.

        :param combine_stderr (bool): whenever to redirect STDERR to STDOUT so
        that output from both streams are returned together. True by default.

        :param shell: command line used to launch script interpreter. By
        default it executes Bash with -eux options enabled. This means that
        any command returning non-zero exist status or any any undefined
        variable would interrupt script execution with an error and every
        command executed by the script is going to be traced to STDERR.

        :param timeout: time in seconds to wait before brutally aborting
        script execution.

        :param **params: script parameter values to be assigned at the
        beginning of the script.

        :returns output written by script to STDOUT.

        :raises tempest.lib.exceptions.SSHTimeout: in case it fails to connect
        to remote server or it fails to open a channel.

        :raises tempest.lib.exceptions.SSHExecCommandFailed: in case command
        script exits with non zero exit status or times out.
        """

        if params:
            # Append script parameters at the beginning of the script
            header = ''.join(sorted(["{!s}={!s}\n".format(k, v)
                                     for k, v in params.items()]))
            script = header + '\n' + script

        timeout = timeout or self.timeout
        end_of_time = time.time() + timeout
        output_data = b''
        error_data = b''
        exit_status = None

        channel = self.open_session()
        with channel:

            # Combine STOUT and STDERR to have to handle with only one stream
            channel.set_combine_stderr(combine_stderr)

            # Update local environment
            lang, encoding = locale.getlocale()
            if not lang:
                lang, encoding = locale.getdefaultlocale()
            _locale = '.'.join([lang, encoding])
            channel.update_environment({'LC_ALL': _locale,
                                        'LANG': _locale})

            if become_root:
                shell = 'sudo ' + shell
            # Spawn a Bash
            channel.exec_command(shell)

            end_of_script = False
            lines_iterator = iter(script.splitlines())
            while (not channel.exit_status_ready() and
                   time.time() < end_of_time):
                # Drain incoming data buffers
                while channel.recv_ready():
                    output_data += channel.recv(self.buf_size)
                while channel.recv_stderr_ready():
                    error_data += channel.recv_stderr(self.buf_size)

                if not end_of_script and channel.send_ready():
                    try:
                        line = next(lines_iterator)
                    except StopIteration:
                        # Finalize Bash script execution
                        channel.shutdown_write()
                        end_of_script = True
                    else:
                        # Send script to Bash STDIN line by line
                        channel.send((line + '\n').encode(encoding))
                        continue

                time.sleep(.1)

            # Get exit status and drain incoming data buffers
            if channel.exit_status_ready():
                exit_status = channel.recv_exit_status()
            while channel.recv_ready():
                output_data += channel.recv(self.buf_size)
            while channel.recv_stderr_ready():
                error_data += channel.recv_stderr(self.buf_size)

        stdout = _buffer_to_string(output_data, encoding)
        if exit_status == 0:
            return stdout

        stderr = _buffer_to_string(error_data, encoding)
        if exit_status is None:
            raise exc.SSHScriptTimeoutExpired(
                command=shell, host=self.host, script=script, stderr=stderr,
                stdout=stdout, timeout=timeout)
        else:
            raise exc.SSHScriptFailed(
                command=shell, host=self.host, script=script, stderr=stderr,
                stdout=stdout, exit_status=exit_status)


def _buffer_to_string(data_buffer, encoding):
    return data_buffer.decode(encoding).replace("\r\n", "\n").replace(
        "\r", "\n")
