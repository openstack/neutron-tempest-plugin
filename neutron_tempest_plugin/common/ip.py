# Copyright (c) 2018 Red Hat, Inc.
#
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

import collections
import re
import subprocess

import netaddr
from neutron_lib import constants
from oslo_log import log
from oslo_utils import excutils

from neutron_tempest_plugin.common import shell


LOG = log.getLogger(__name__)


class IPCommand(object):

    sudo = 'sudo'
    ip_path = '/sbin/ip'

    def __init__(self, ssh_client=None, timeout=None):
        self.ssh_client = ssh_client
        self.timeout = timeout

    def get_command(self, obj, *command):
        command_line = '{sudo!s} {ip_path!r} {object!s} {command!s}'.format(
            sudo=self.sudo, ip_path=self.ip_path, object=obj,
            command=subprocess.list2cmdline([str(c) for c in command]))
        return command_line

    def execute(self, obj, *command):
        command_line = self.get_command(obj, *command)
        return shell.execute(command_line, ssh_client=self.ssh_client,
                             timeout=self.timeout).stdout

    def configure_vlan_subport(self, port, subport, vlan_tag, subnets):
        addresses = self.list_addresses()
        try:
            subport_device = get_port_device_name(addresses=addresses,
                                                  port=subport)
        except ValueError:
            pass
        else:
            LOG.debug('Interface %r already configured.', subport_device)
            return subport_device

        subport_ips = [
            "{!s}/{!s}".format(ip, prefix_len)
            for ip, prefix_len in _get_ip_address_prefix_len_pairs(
                port=subport, subnets=subnets)]
        if not subport_ips:
            raise ValueError(
                "Unable to get IP address and subnet prefix lengths for "
                "subport")

        port_device = get_port_device_name(addresses=addresses, port=port)
        subport_device = '{!s}.{!s}'.format(port_device, vlan_tag)
        LOG.debug('Configuring VLAN subport interface %r on top of interface '
                  '%r with IPs: %s', subport_device, port_device,
                  ', '.join(subport_ips))

        self.add_link(link=port_device, name=subport_device, link_type='vlan',
                      segmentation_id=vlan_tag)
        self.set_link(device=subport_device, state='up')
        for subport_ip in subport_ips:
            self.add_address(address=subport_ip, device=subport_device)
        return subport_device

    def list_addresses(self, device=None, ip_addresses=None, port=None,
                       subnets=None):
        command = ['list']
        if device:
            command += ['dev', device]
        output = self.execute('address', *command)
        addresses = list(parse_addresses(output))

        return list_ip_addresses(addresses=addresses,
                                 ip_addresses=ip_addresses, port=port,
                                 subnets=subnets)

    def add_link(self, name, link_type, link=None, segmentation_id=None):
        command = ['add']
        if link:
            command += ['link', link]
        command += ['name', name, 'type', link_type]
        if id:
            command += ['id', segmentation_id]
        return self.execute('link', *command)

    def set_link(self, device, state=None):
        command = ['set', 'dev', device]
        if state:
            command.append(state)
        return self.execute('link', *command)

    def add_address(self, address, device):
        # ip addr add 192.168.1.1/24 dev em1
        return self.execute('address', 'add', address, 'dev', device)

    def list_routes(self, *args):
        output = self.execute('route', 'show', *args)
        return list(parse_routes(output))


def parse_addresses(command_output):
    address = device = None
    addresses = []
    for i, line in enumerate(command_output.split('\n')):
        try:
            line_number = i + 1
            fields = line.strip().split()
            if not fields:
                continue
            indent = line.index(fields[0] + ' ')
            if indent == 0:
                # example of line
                # 2: enp0s25: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP qlen 1000  # noqa
                address = None
                name = fields[1]
                if name.endswith(':'):
                    name = name[:-1]
                if '@' in name:
                    name, parent = name.split('@', 1)
                else:
                    parent = None

                if len(fields) > 2:
                    # flags example: <LOOPBACK,UP,LOWER_UP>
                    flags = fields[2]
                    if flags.startswith('<'):
                        flags = flags[1:]
                    if flags.startswith('>'):
                        flags = flags[:-1]
                    flags = flags.split(',')

                device = Device(name=name, parent=parent, flags=flags,
                                properties=dict(parse_properties(fields[3:])))
                LOG.debug("Device parsed: %r", device)

            elif indent == 4:
                address = Address.create(
                    family=fields[0], address=fields[1], device=device,
                    properties=dict(parse_properties(fields[2:])))
                addresses.append(address)
                LOG.debug("Address parsed: %r", address)

            elif indent == 7:
                address.properties.update(parse_properties(fields))
                LOG.debug("Address properties parsed: %r", address.properties)

            else:
                assert False, "Invalid line indentation: {!r}".format(indent)

        except Exception:
            with excutils.save_and_reraise_exception():
                LOG.exception("Error parsing ip command output at line %d:\n"
                              "%r\n",
                              line_number, line)
            raise

    return addresses


def parse_properties(fields):
    for i, field in enumerate(fields):
        if i % 2 == 0:
            key = field
        else:
            yield key, field


class HasProperties(object):

    def __getattr__(self, name):
        try:
            return self.properties[name]
        except KeyError:
            pass
        # This should raise AttributeError
        return getattr(super(HasProperties, self), name)


class Address(HasProperties,
              collections.namedtuple('Address',
                                     ['family', 'address', 'device',
                                      'properties'])):

    _subclasses = {}

    @classmethod
    def create(cls, family, address, device, properties):
        cls = cls._subclasses.get(family, cls)
        return cls(family=family, address=address, device=device,
                   properties=properties)

    @classmethod
    def register_subclass(cls, family, subclass=None):
        if not issubclass(subclass, cls):
            msg = "{!r} is not sub-class of {!r}".format(cls, Address)
            raise TypeError(msg)
        cls._subclasses[family] = subclass


class Device(HasProperties,
             collections.namedtuple('Device',
                                    ['name', 'parent', 'flags',
                                     'properties'])):
    pass


def register_address_subclass(families):

    def decorator(subclass):
        for family in families:
            Address.register_subclass(family=family, subclass=subclass)
        return subclass

    return decorator


@register_address_subclass(['inet', 'inet6'])
class InetAddress(Address):

    @property
    def ip(self):
        return self.network.ip

    @property
    def network(self):
        return netaddr.IPNetwork(self.address)


def parse_routes(command_output):
    for line in command_output.split('\n'):
        fields = line.strip().split()
        if fields:
            dest = fields[0]
            properties = dict(parse_properties(fields[1:]))
            if dest == 'default':
                dest = constants.IPv4_ANY
                via = properties.get('via')
                if via:
                    dest = constants.IP_ANY[netaddr.IPAddress(via).version]
            yield Route(dest=dest, properties=properties)


def list_ip_addresses(addresses, ip_addresses=None, port=None,
                      subnets=None):
    if port:
        # filter addresses by port IP addresses
        ip_addresses = set(ip_addresses) if ip_addresses else set()
        ip_addresses.update(list_port_ip_addresses(port=port,
                                                   subnets=subnets))
    if ip_addresses:
        addresses = [a for a in addresses if (hasattr(a, 'ip') and
                                              str(a.ip) in ip_addresses)]
    return addresses


def list_port_ip_addresses(port, subnets=None):
    fixed_ips = port['fixed_ips']
    if subnets:
        subnets = {subnet['id']: subnet for subnet in subnets}
        fixed_ips = [fixed_ip
                     for fixed_ip in fixed_ips
                     if fixed_ip['subnet_id'] in subnets]
    return [ip['ip_address'] for ip in port['fixed_ips']]


def get_port_device_name(addresses, port):
    for address in list_ip_addresses(addresses=addresses, port=port):
        return address.device.name

    msg = "Port %r fixed IPs not found on server.".format(port['id'])
    raise ValueError(msg)


def _get_ip_address_prefix_len_pairs(port, subnets):
    subnets = {subnet['id']: subnet for subnet in subnets}
    for fixed_ip in port['fixed_ips']:
        subnet = subnets.get(fixed_ip['subnet_id'])
        if subnet:
            yield (fixed_ip['ip_address'],
                   netaddr.IPNetwork(subnet['cidr']).prefixlen)


def arp_table():
    # 192.168.0.16  0x1  0x2  dc:a6:32:06:56:51  *  enp0s31f6
    regex_str = (r"([^ ]+)\s+(0x\d+)\s+(0x\d+)\s+(\w{2}\:\w{2}\:\w{2}\:\w{2}\:"
                 r"\w{2}\:\w{2})\s+([\w+\*]+)\s+([\-\w]+)")
    regex = re.compile(regex_str)
    arp_table = []
    with open('/proc/net/arp', 'r') as proc_file:
        for line in proc_file.readlines():
            m = regex.match(line)
            if m:
                arp_table.append(ARPregister(
                    ip_address=m.group(1), hw_type=m.group(2),
                    flags=m.group(3), mac_address=m.group(4),
                    mask=m.group(5), device=m.group(6)))
    return arp_table


class Route(HasProperties,
            collections.namedtuple('Route',
                                   ['dest', 'properties'])):

    @property
    def dest_ip(self):
        return netaddr.IPNetwork(self.dest)

    @property
    def via_ip(self):
        return netaddr.IPAddress(self.via)

    @property
    def src_ip(self):
        return netaddr.IPAddress(self.src)

    def __str__(self):
        properties_str = ' '.join('%s %s' % (k, v)
                                  for k, v in self.properties.items())
        return '%(dest)s %(properties)s' % {'dest': self.dest,
                                            'properties': properties_str}


class ARPregister(collections.namedtuple(
        'ARPregister',
        ['ip_address', 'hw_type', 'flags', 'mac_address', 'mask', 'device'])):

    def __str__(self):
        return '%s %s %s %s %s %s' % (self.ip_address, self.hw_type,
                                      self.flags, self.mac_address, self.mask,
                                      self.device)


def find_valid_cidr(valid_cidr='10.0.0.0/8', used_cidr=None):
    total_ips = netaddr.IPSet(netaddr.IPNetwork(valid_cidr))
    if used_cidr:
        used_network = netaddr.IPNetwork(used_cidr)
        netmask = used_network.netmask.netmask_bits()
        valid_ips = total_ips.difference(netaddr.IPSet(used_network))
    else:
        valid_ips = total_ips
        netmask = 24

    for ip in valid_ips:
        valid_network = netaddr.IPNetwork('%s/%s' % (ip, netmask))
        if valid_network in valid_ips:
            return valid_network.cidr

    exception_str = 'No valid CIDR found in %s' % valid_cidr
    if used_cidr:
        exception_str += ', used CIDR %s' % used_cidr
    raise Exception(exception_str)
