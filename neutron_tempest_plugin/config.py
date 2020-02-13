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

from oslo_config import cfg
from tempest import config


CONF = config.CONF


NeutronPluginOptions = [
    cfg.ListOpt('provider_vlans',
                default=[],
                help='List of provider networks available in the deployment.'),
    cfg.IntOpt('provider_net_base_segm_id',
               default=3000,
               help='Base segmentation ID to create provider networks. '
                    'This value will be increased in case of conflict.'),
    cfg.BoolOpt('specify_floating_ip_address_available',
                default=True,
                help='Allow passing an IP Address of the floating ip when '
                     'creating the floating ip'),
    cfg.ListOpt('available_type_drivers',
                default=[],
                help='List of network types available to neutron, '
                     'e.g. vxlan,vlan,gre.'),
    cfg.StrOpt('agent_availability_zone',
               help='The availability zone for all agents in the deployment. '
                    'Configure this only when the single value is used by '
                    'all agents in the deployment.'),
    cfg.IntOpt('max_networks_per_project',
               default=4,
               help='Max number of networks per project. '
                    'Configure this only when project is limited with real '
                    'vlans in deployment.'),
    cfg.StrOpt('l3_agent_mode',
               help='The agent mode for L3 agents in the deployment. '
                    'Configure this only when the single value is used by '
                    'all agents in the deployment.'),
    cfg.StrOpt('test_mtu_networks',
               default='[{"provider:network_type":"vxlan",'
                       '"mtu":1200, "cidr":"10.100.0.0/16"}'
                       ','
                       '{"provider:network_type":"vxlan",'
                       '"mtu":1300, "cidr":"10.200.0.0/16"}]',
               help='Configuration for test networks. The format is JSON. '
                    '"provider:network_type":<TYPE> - string '
                    '"mtu":<MTU> - integer '
                    '"cidr"<SUBNET/MASK> - string '
                    '"provider:segmentation_id":<VLAN_ID> - integer'),
    cfg.IntOpt('max_mtu',
               default=1500,
               help='Max mtu value of default deployments".'),
    cfg.StrOpt('q_agent',
               default=None,
               choices=['None', 'linuxbridge', 'ovs', 'sriov'],
               help='Agent used for devstack@q-agt.service'),

    # Multicast tests settings
    cfg.StrOpt('multicast_group_range',
               default='225.0.0.120-225.0.0.250',
               help='Unallocated multi-cast IPv4 range, which will be used to '
                    'test the multi-cast support.'),

    # Option for feature to connect via SSH to VMs using an intermediate SSH
    # server
    cfg.StrOpt('ssh_proxy_jump_host',
               default=None,
               help='Proxy jump host used to connect via SSH to VMs..'),
    cfg.StrOpt('ssh_proxy_jump_username',
               default='root',
               help='User name used to connect to "ssh_proxy_jump_host".'),
    cfg.StrOpt('ssh_proxy_jump_password',
               default=None,
               help='Password used to connect to "ssh_proxy_jump_host".'),
    cfg.StrOpt('ssh_proxy_jump_keyfile',
               default=None,
               help='Keyfile used to connect to "ssh_proxy_jump_host".'),
    cfg.IntOpt('ssh_proxy_jump_port',
               default=22,
               help='Port used to connect to "ssh_proxy_jump_host".'),

    # Options for special, "advanced" image like e.g. Ubuntu. Such image can be
    # used in tests which require some more advanced tool than available in
    # Cirros
    cfg.BoolOpt('default_image_is_advanced',
                default=False,
                help='Default image is an image which supports features '
                     'that Cirros does not, like Ubuntu or CentOS supporting '
                     'advanced features. '
                     'If this is set to True, "advanced_image_ref" option '
                     'is not required to be set.'),
    cfg.StrOpt('advanced_image_ref',
               default=None,
               help='Valid advanced image uuid to be used in tests. '
                    'It is an image that supports features that Cirros '
                    'does not, like Ubuntu or CentOS supporting advanced '
                    'features.'),
    cfg.StrOpt('advanced_image_flavor_ref',
               default=None,
               help='Valid flavor to use with advanced image in tests. '
                    'This is required if advanced image has to be used in '
                    'tests.'),
    cfg.StrOpt('advanced_image_ssh_user',
               default=None,
               help='Name of ssh user to use with advanced image in tests. '
                    'This is required if advanced image has to be used in '
                    'tests.'),

    # Option for creating QoS policies configures as "shared".
    # The default is false in order to prevent undesired usage
    # while testing in parallel.
    cfg.BoolOpt('create_shared_resources',
                default=False,
                help='Allow creation of shared resources.'
                     'The default value is false.'),
    cfg.BoolOpt('is_igmp_snooping_enabled',
                default=False,
                help='Indicates whether IGMP snooping is enabled or not. '
                     'If True, multicast test(s) will assert that multicast '
                     'traffic is not being flooded to all ports. Defaults '
                     'to False.'),
]

# TODO(amuller): Redo configuration options registration as part of the planned
# transition to the Tempest plugin architecture
for opt in NeutronPluginOptions:
    CONF.register_opt(opt, 'neutron_plugin_options')

# TODO(slaweq): This config option is added to avoid running bgpvpn tests twice
# on stable branches till stable/stein. We need to remove this config option
# once stable/stein is EOL. Bgpvpn tempest plugin has been merged into
# neutron-tempest-plugin from Train. Train onwards bgpvpn tests will run from
# neutron-tempest-plugins.
BgpvpnGroup = [
    cfg.BoolOpt('run_bgpvpn_tests',
                default=True,
                help=("If it is set to False bgpvpn api and scenario tests "
                      "will be skipped")),
    cfg.IntOpt('min_asn',
               default=100,
               help=("Minimum number for the range of "
                     "autonomous system number for distinguishers.")),
    cfg.IntOpt('min_nn',
               default=100,
               help=("Minimum number for the range of "
                     "assigned number for distinguishers.")),
    cfg.IntOpt('max_asn',
               default=200,
               help=("Maximum number for the range of "
                     "autonomous system number for distinguishers.")),
    cfg.IntOpt('max_nn',
               default=200,
               help=("Maximum number for the range of "
                     "assigned number for distinguishers.")),
]

bgpvpn_group = cfg.OptGroup(name="bgpvpn", title=("Networking-Bgpvpn Service "
                                                  "Options"))
CONF.register_group(bgpvpn_group)
CONF.register_opts(BgpvpnGroup, group="bgpvpn")

# TODO(slaweq): This config option is added to avoid running fwaas tests twice
# on stable branches till stable/stein. We need to remove this config option
# once stable/stein is EOL. Fwaas tempest plugin has been merged into
# neutron-tempest-plugin from Train. Train onwards fwaas tests will run from
# neutron-tempest-plugins.
FwaasGroup = [
    cfg.BoolOpt('run_fwaas_tests',
                default=True,
                help=("If it is set to False fwaas api and scenario tests "
                      "will be skipped")),
]

fwaas_group = cfg.OptGroup(
    name="fwaas", title=("Neutron-fwaas Service Options"))
CONF.register_group(fwaas_group)
CONF.register_opts(FwaasGroup, group="fwaas")

# TODO(slaweq): This config option is added to avoid running SFC tests twice
# on stable branches till stable/stein. We need to remove this config option
# once stable/stein is EOL. SFC tempest plugin has been merged into
# neutron-tempest-plugin from Train. Train onwards SFC tests will run from
# neutron-tempest-plugins.
SfcGroup = [
    cfg.BoolOpt('run_sfc_tests',
                default=True,
                help=("If it is set to False SFC api and scenario tests "
                      "will be skipped")),
]

sfc_group = cfg.OptGroup(name="sfc", title=("Networking-sfc Service Options"))
CONF.register_group(sfc_group)
CONF.register_opts(SfcGroup, group="sfc")

config_opts_translator = {
    'project_network_cidr': 'tenant_network_cidr',
    'project_network_v6_cidr': 'tenant_network_v6_cidr',
    'project_network_mask_bits': 'tenant_network_mask_bits',
    'project_network_v6_mask_bits': 'tenant_network_v6_mask_bits'}


def safe_get_config_value(group, name):
    """Safely get Oslo config opts from Tempest, using old and new names."""
    conf_group = getattr(CONF, group)

    try:
        return getattr(conf_group, name)
    except cfg.NoSuchOptError:
        return getattr(conf_group, config_opts_translator[name])
