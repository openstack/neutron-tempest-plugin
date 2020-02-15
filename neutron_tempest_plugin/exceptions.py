# Copyright 2012 OpenStack Foundation
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

from tempest.lib import exceptions

from neutron_tempest_plugin.common import utils


class NeutronTempestPluginException(exceptions.TempestException):

    def __init__(self, **kwargs):
        super(NeutronTempestPluginException, self).__init__(**kwargs)
        self._properties = kwargs

    def __getattr__(self, name):
        try:
            return self._properties[name]
        except KeyError:
            pass

        msg = ("AttributeError: {!r} object has no attribute {!r}").format(
            self, name)
        raise AttributeError(msg)


class InvalidConfiguration(NeutronTempestPluginException):
    message = "Invalid Configuration"


class InvalidCredentials(NeutronTempestPluginException):
    message = "Invalid Credentials"


class InvalidServiceTag(NeutronTempestPluginException):
    message = "Invalid service tag"


class SSHScriptException(exceptions.TempestException):
    """Base class for SSH client execute_script() exceptions"""


class ShellError(NeutronTempestPluginException):
    pass


class ShellCommandFailed(ShellError):
    """Raised when shell command exited with non-zero status

    """
    message = ("Command %(command)r failed, exit status: %(exit_status)d, "
               "stderr:\n%(stderr)s\n"
               "stdout:\n%(stdout)s")


class SSHScriptFailed(ShellCommandFailed):
    message = ("Command %(command)r failed, exit status: %(exit_status)d, "
               "host: %(host)r\n"
               "script:\n%(script)s\n"
               "stderr:\n%(stderr)s\n"
               "stdout:\n%(stdout)s")


class ShellTimeoutExpired(ShellError):
    """Raised when shell command timeouts and has been killed before exiting

    """
    message = ("Command '%(command)s' timed out: %(timeout)d, "
               "stderr:\n%(stderr)s\n"
               "stdout:\n%(stdout)s")


class SSHScriptTimeoutExpired(ShellTimeoutExpired):
    message = ("Command '%(command)s', timed out: %(timeout)d "
               "host: %(host)r\n"
               "script:\n%(script)s\n"
               "stderr:\n%(stderr)s\n"
               "stdout:\n%(stdout)s")


# Patch SSHExecCommandFailed exception to make sure we can access to fields
# command, exit_status, STDOUT and STDERR when SSH client reports command
# failure
exceptions.SSHExecCommandFailed = utils.override_class(
    exceptions.SSHExecCommandFailed, ShellCommandFailed)

# Above code created a new SSHExecCommandFailed class based on top
# of ShellCommandFailed
assert issubclass(exceptions.SSHExecCommandFailed, ShellCommandFailed)
