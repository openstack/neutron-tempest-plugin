Set up connection between infra bridge and Neutron external bridge

Network topology used in CI multinode jobs is described In `Devstack documention
<https://opendev.org/openstack/devstack-gate/src/branch/master/multinode_setup_info.txt#L81>`_

In case when DVR is used, there is also additional bridge ``br-infra`` added
on each node to provide connectivity to floating IPs from main node.

This bridge needs to be connected with bridge used by Neutron as
external bridge. Typically it is ``br-ex`` and this role adds patch ports
between those bridges.

**Role Variables**

.. zuul:rolevar:: neutron_external_bridge_name
   :default: br-ex

   Name of the Neutron external bridge.

.. zuul:rolevar:: infra_bridge_name
   :default: br-infra

   Name of the infra bridge.
