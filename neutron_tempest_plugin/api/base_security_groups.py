# Copyright 2013 OpenStack Foundation
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

from neutron_lib import constants


# NOTE(yamamoto): The list of protocols here is what we had in Ocata.
# (neutron-lib 1.1.0)
# Why don't we just use neutron_lib.constants.IP_PROTOCOL_MAP etc here?
# Tempest is branchless and thus supposed to work against older deployments.
# Also, it's supposed to work against other implementations, which might not
# support the same set as the reference implementation. Ideally SG can have
# a way to discover the set of usable protocols. But for now, we need to be
# conservative.

V4_PROTOCOL_NAMES = {
    'ah',
    'dccp',
    'egp',
    'esp',
    'gre',
    'icmp',
    'igmp',
    'ospf',
    'pgm',
    'rsvp',
    'sctp',
    'tcp',
    'udp',
    'udplite',
    'vrrp',
}

V4_PROTOCOL_INTS = {v
                    for k, v in constants.IP_PROTOCOL_MAP.items()
                    if k in V4_PROTOCOL_NAMES}

V6_PROTOCOL_NAMES = {
    'ipv6-encap',
    'ipv6-frag',
    'ipv6-icmp',
    'ipv6-nonxt',
    'ipv6-opts',
    'ipv6-route',
}

V6_PROTOCOL_INTS = {v
                    for k, v in constants.IP_PROTOCOL_MAP.items()
                    if k in V6_PROTOCOL_NAMES}
