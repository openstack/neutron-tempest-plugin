# Copyright 2018 Red Hat, Inc.
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


COMMAND = 'socat'


class SocatAddress(object):

    def __init__(self, address, args=None, options=None):
        self.address = address
        self.args = args
        self.options = options

    @classmethod
    def udp_datagram(cls, host, port, options=None, ip_version=None):
        address = 'UDP{}-DATAGRAM'.format(ip_version or '')
        return cls(address, (host, int(port)), options)

    @classmethod
    def udp_recvfrom(cls, port, options=None, ip_version=None):
        address = 'UDP{}-RECVFROM'.format(ip_version or '')
        return cls(address, (int(port),), options)

    @classmethod
    def stdio(cls):
        return cls('STDIO')

    def __str__(self):
        address = self.address
        if self.args:
            address += ':' + ':'.join(str(a) for a in self.args)
        if self.options:
            address += ',' + ','.join(str(o) for o in self.options)
        return address

    def format(self, *args, **kwargs):
        return str(self).format(*args, **kwargs)


STDIO = SocatAddress.stdio()


class SocatOption(object):

    def __init__(self, name, *args):
        self.name = name
        self.args = args

    @classmethod
    def bind(cls, host):
        return cls('bind', host)

    @classmethod
    def fork(cls):
        return cls('fork')

    @classmethod
    def ip_multicast_ttl(cls, ttl):
        return cls('ip-multicast-ttl', int(ttl))

    @classmethod
    def ip_multicast_if(cls, interface_address):
        return cls('ip-multicast-if', interface_address)

    @classmethod
    def ip_add_membership(cls, multicast_address, interface_address):
        return cls('ip-add-membership', multicast_address, interface_address)

    def __str__(self):
        result = self.name
        args = self.args
        if args:
            result += '=' + ':'.join(str(a) for a in args)
        return result


class SocatCommand(object):

    def __init__(self, source=STDIO, destination=STDIO, command=COMMAND):
        self.source = source
        self.destination = destination
        self.command = command

    def __str__(self):
        words = [self.command, self.source, self.destination]
        return ' '.join(str(obj) for obj in words)


def socat_command(source=STDIO, destination=STDIO, command=COMMAND):
    command = SocatCommand(source=source, destination=destination,
                           command=command)
    return str(command)
