# Copyright 2016 Red Hat, Inc.
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


class QoSLimitReached(exceptions.TempestException):
    message = "Limit reached, limit = %(limit)d"


class SocketConnectionRefused(exceptions.TempestException):
    message = "Unable to connect to %(host)s port %(port)d:Connection Refused"


class ConnectionTimeoutException(exceptions.TempestException):
    message = "Timeout connecting to %(host)s port %(port)d"


class FileCreationFailedException(exceptions.TempestException):
    message = "File %(file)s has not been created or has the wrong size"
