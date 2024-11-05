# Copyright (c) 2012 OpenStack Foundation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from neutron_lib import constants as lib_constants


ROUTER_PORT_OWNERS = lib_constants.ROUTER_INTERFACE_OWNERS_SNAT + \
    (lib_constants.DEVICE_OWNER_ROUTER_GW,)

ROUTER_STATUS_ACTIVE = 'ACTIVE'
ROUTER_STATUS_ERROR = 'ERROR'

DEVICE_ID_RESERVED_DHCP_PORT = "reserved_dhcp_port"

HA_ROUTER_STATE_KEY = '_ha_state'
METERING_LABEL_KEY = '_metering_labels'
FLOATINGIP_AGENT_INTF_KEY = '_floatingip_agent_interfaces'
SNAT_ROUTER_INTF_KEY = '_snat_router_interfaces'
DVR_SNAT_BOUND = 'dvr_snat_bound'
L3_AGENT_MODE_DVR_NO_EXTERNAL = 'dvr_no_external'

HA_NETWORK_NAME = 'HA network tenant %s'
HA_SUBNET_NAME = 'HA subnet tenant %s'
HA_PORT_NAME = 'HA port tenant %s'
HA_ROUTER_STATE_ACTIVE = 'active'
HA_ROUTER_STATE_STANDBY = 'standby'

PAGINATION_INFINITE = 'infinite'

SORT_DIRECTION_ASC = 'asc'
SORT_DIRECTION_DESC = 'desc'

ETHERTYPE_NAME_ARP = 'arp'
ETHERTYPE_ARP = 0x0806
ETHERTYPE_IP = 0x0800
ETHERTYPE_IPV6 = 0x86DD

IP_PROTOCOL_NAME_ALIASES = {lib_constants.PROTO_NAME_IPV6_ICMP_LEGACY:
                            lib_constants.PROTO_NAME_IPV6_ICMP}

VALID_DSCP_MARKS = [0, 8, 10, 12, 14, 16, 18, 20, 22, 24, 26, 28, 30, 32, 34,
                    36, 38, 40, 46, 48, 56]

IP_PROTOCOL_NUM_TO_NAME_MAP = {
    str(v): k for k, v in lib_constants.IP_PROTOCOL_MAP.items()}

# When using iptables-save we specify '-p {proto} -m {module}',
# but sometimes those values are not identical.  This is a map
# of known protocols that require a '-m {module}', along with
# the module name that should be used.
IPTABLES_PROTOCOL_MAP = {lib_constants.PROTO_NAME_DCCP: 'dccp',
                         lib_constants.PROTO_NAME_ICMP: 'icmp',
                         lib_constants.PROTO_NAME_IPV6_ICMP: 'icmp6',
                         lib_constants.PROTO_NAME_SCTP: 'sctp',
                         lib_constants.PROTO_NAME_TCP: 'tcp',
                         lib_constants.PROTO_NAME_UDP: 'udp'}

# Special provisional prefix for IPv6 Prefix Delegation
PROVISIONAL_IPV6_PD_PREFIX = '::/64'

# Timeout in seconds for getting an IPv6 LLA
LLA_TASK_TIMEOUT = 40

# length of all device prefixes (e.g. qvo, tap, qvb)
LINUX_DEV_PREFIX_LEN = 3
# must be shorter than linux IFNAMSIZ (which is 16)
LINUX_DEV_LEN = 14

# Possible prefixes to partial port IDs in interface names used by the OVS,
# Linux Bridge, and IVS VIF drivers in Nova and the neutron agents. See the
# 'get_ovs_interfaceid' method in Nova (nova/virt/libvirt/vif.py) for details.
INTERFACE_PREFIXES = (lib_constants.TAP_DEVICE_PREFIX,
                      lib_constants.VETH_DEVICE_PREFIX,
                      lib_constants.SNAT_INT_DEV_PREFIX)

ATTRIBUTES_TO_UPDATE = 'attributes_to_update'

# Maximum value integer can take in MySQL.
# In SQLite integer can be stored in 1, 2, 3, 4, 6, or 8 bytes,
# but here it will be limited by this value for consistency.
DB_INTEGER_MAX_VALUE = 2 ** 31 - 1

# TODO(amuller): Re-define the RPC namespaces once Oslo messaging supports
# Targets with multiple namespaces. Neutron will then implement callbacks
# for its RPC clients in order to support rolling upgrades.

# RPC Interface for agents to call DHCP API implemented on the plugin side
RPC_NAMESPACE_DHCP_PLUGIN = None
# RPC interface for the metadata service to get info from the plugin side
RPC_NAMESPACE_METADATA = None
# RPC interface for agent to plugin security group API
RPC_NAMESPACE_SECGROUP = None
# RPC interface for agent to plugin DVR api
RPC_NAMESPACE_DVR = None
# RPC interface for reporting state back to the plugin
RPC_NAMESPACE_STATE = None
# RPC interface for agent to plugin resources API
RPC_NAMESPACE_RESOURCES = None

# Default network MTU value when not configured
DEFAULT_NETWORK_MTU = 1500
IPV6_MIN_MTU = 1280

ROUTER_MARK_MASK = "0xffff"

# Agent states as detected by server, used to reply on agent's state report
# agent has just been registered
AGENT_NEW = 'new'
# agent is alive
AGENT_ALIVE = 'alive'
# agent has just returned to alive after being dead
AGENT_REVIVED = 'revived'

VALID_ETHERTYPES = (lib_constants.IPv4, lib_constants.IPv6)

IP_ALLOWED_VERSIONS = [lib_constants.IP_VERSION_4, lib_constants.IP_VERSION_6]

PORT_RANGE_MIN = 1
PORT_RANGE_MAX = 65535

# Configuration values for accept_ra sysctl, copied from linux kernel
# networking (netdev) tree, file Documentation/networking/ip-sysctl.txt
#
# Possible values are:
#         0 Do not accept Router Advertisements.
#         1 Accept Router Advertisements if forwarding is disabled.
#         2 Overrule forwarding behaviour. Accept Router Advertisements
#           even if forwarding is enabled.
ACCEPT_RA_DISABLED = 0
ACCEPT_RA_WITHOUT_FORWARDING = 1
ACCEPT_RA_WITH_FORWARDING = 2

# Some components communicate using private address ranges, define
# them all here. These address ranges should not cause any issues
# even if they overlap since they are used in disjoint namespaces,
# but for now they are unique.
# We define the metadata cidr since it falls in the range.
PRIVATE_CIDR_RANGE = '169.254.0.0/16'
DVR_FIP_LL_CIDR = '169.254.64.0/18'
L3_HA_NET_CIDR = '169.254.192.0/18'
METADATA_CIDR = '169.254.169.254/32'

# The only defined IpamAllocation status at this stage is 'ALLOCATED'.
# More states will be available in the future - e.g.: RECYCLABLE
IPAM_ALLOCATION_STATUS_ALLOCATED = 'ALLOCATED'

VALID_IPAM_ALLOCATION_STATUSES = (IPAM_ALLOCATION_STATUS_ALLOCATED,)

# Port binding states for Live Migration
PORT_BINDING_STATUS_ACTIVE = 'ACTIVE'
PORT_BINDING_STATUS_INACTIVE = 'INACTIVE'
PORT_BINDING_STATUSES = (PORT_BINDING_STATUS_ACTIVE,
                         PORT_BINDING_STATUS_INACTIVE)

VALID_FLOATINGIP_STATUS = (lib_constants.FLOATINGIP_STATUS_ACTIVE,
                           lib_constants.FLOATINGIP_STATUS_DOWN,
                           lib_constants.FLOATINGIP_STATUS_ERROR)

# Possible types of values (e.g. in QoS rule types)
VALUES_TYPE_CHOICES = "choices"
VALUES_TYPE_RANGE = "range"

# Security group parameters values mapped by IP version
DEFAULT_SECURITY_GROUP_RULE_PARAMS = {
    lib_constants.IP_VERSION_4: {'ethertype': lib_constants.IPv4,
                                 'remote_ip_prefix': lib_constants.IPv4_ANY},
    lib_constants.IP_VERSION_6: {'ethertype': lib_constants.IPv6,
                                 'remote_ip_prefix': lib_constants.IPv6_ANY},
}
