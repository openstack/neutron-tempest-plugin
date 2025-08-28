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

import time
from urllib import parse as urlparse

from neutron_lib._i18n import _
from oslo_serialization import jsonutils
from tempest.lib.common import rest_client as service_client
from tempest.lib import exceptions as lib_exc


class NetworkClientJSON(service_client.RestClient):
    """NetworkClientJSON class

    Tempest REST client for Neutron. Uses v2 of the Neutron API, since the
    V1 API has been removed from the code base.

    Implements create, delete, update, list and show for the basic Neutron
    abstractions (networks, sub-networks, routers, ports and floating IP):

    Implements add/remove interface to router using subnet ID / port ID

    It also implements list, show, update and reset for OpenStack Networking
    quotas
    """

    version = '2.0'
    uri_prefix = "v2.0"

    def get_uri(self, plural_name):
        # get service prefix from resource name

        # The following list represents resource names that do not require
        # changing underscore to a hyphen
        hyphen_exceptions = ["service_profiles", "availability_zones"]
        # The following map is used to construct proper URI
        # for the given neutron resource.
        # No need to populate this map if the neutron resource
        # doesn't have a URI prefix.
        service_resource_prefix_map = {
            'metering_labels': 'metering',
            'metering_label_rules': 'metering',
            'policies': 'qos',
            'bandwidth_limit_rules': 'qos',
            'minimum_bandwidth_rules': 'qos',
            'rule_types': 'qos',
            'logs': 'log',
            'loggable_resources': 'log',
        }
        service_prefix = service_resource_prefix_map.get(
            plural_name)
        if plural_name not in hyphen_exceptions:
            plural_name = plural_name.replace("_", "-")
        if service_prefix:
            uri = '%s/%s/%s' % (self.uri_prefix, service_prefix,
                                plural_name)
        else:
            uri = '%s/%s' % (self.uri_prefix, plural_name)
        return uri

    def build_uri(self, plural_name, **kwargs):
        uri = self.get_uri(plural_name)
        if kwargs:
            uri += '?' + urlparse.urlencode(kwargs, doseq=1)
        return uri

    def pluralize(self, resource_name):
        # get plural from map or just add 's'

        # map from resource name to a plural name
        # needed only for those which can't be constructed as name + 's'
        resource_plural_map = {
            'security_groups': 'security_groups',
            'security_group_rules': 'security_group_rules',
            'quotas': 'quotas',
            'qos_policy': 'policies',
            'rbac_policy': 'rbac_policies',
            'network_ip_availability': 'network_ip_availabilities',
        }
        return resource_plural_map.get(resource_name, resource_name + 's')

    def get_uri_with_links(self, plural_name, uri):
        resp, body = self.get(uri)
        result = {plural_name: self.deserialize_list(body)}
        links = self.deserialize_links(body)
        self.expected_success(200, resp.status)
        return links, service_client.ResponseBody(resp, result)

    def _lister(self, plural_name):
        def _list(**filters):
            uri = self.build_uri(plural_name, **filters)
            resp, body = self.get(uri)
            result = {plural_name: self.deserialize_list(body)}
            self.expected_success(200, resp.status)
            return service_client.ResponseBody(resp, result)

        return _list

    def _deleter(self, resource_name):
        def _delete(resource_id):
            plural = self.pluralize(resource_name)
            uri = '%s/%s' % (self.get_uri(plural), resource_id)
            resp, body = self.delete(uri)
            self.expected_success(204, resp.status)
            return service_client.ResponseBody(resp, body)

        return _delete

    def _shower(self, resource_name):
        def _show(resource_id, **fields):
            # fields is a dict which key is 'fields' and value is a
            # list of field's name. An example:
            # {'fields': ['id', 'name']}
            plural = self.pluralize(resource_name)
            if 'details_quotas' in plural:
                details, plural = plural.split('_')
                uri = '%s/%s/%s' % (self.get_uri(plural),
                                    resource_id, details)
            else:
                uri = '%s/%s' % (self.get_uri(plural), resource_id)

            if fields:
                uri += '?' + urlparse.urlencode(fields, doseq=1)
            resp, body = self.get(uri)
            body = self.deserialize_single(body)
            self.expected_success(200, resp.status)
            return service_client.ResponseBody(resp, body)

        return _show

    def _creater(self, resource_name):
        def _create(**kwargs):
            plural = self.pluralize(resource_name)
            uri = self.get_uri(plural)
            post_data = self.serialize({resource_name: kwargs})
            resp, body = self.post(uri, post_data)
            body = self.deserialize_single(body)
            self.expected_success(201, resp.status)
            return service_client.ResponseBody(resp, body)

        return _create

    def _updater(self, resource_name):
        def _update(res_id, **kwargs):
            headers = kwargs.pop('headers', {})
            plural = self.pluralize(resource_name)
            uri = '%s/%s' % (self.get_uri(plural), res_id)
            post_data = self.serialize({resource_name: kwargs})
            resp, body = self.put(uri, post_data, headers=headers)
            body = self.deserialize_single(body)
            self.expected_success(200, resp.status)
            return service_client.ResponseBody(resp, body)

        return _update

    def __getattr__(self, name):
        method_prefixes = ["list_", "delete_", "show_", "create_", "update_"]
        method_functors = [self._lister,
                           self._deleter,
                           self._shower,
                           self._creater,
                           self._updater]
        for index, prefix in enumerate(method_prefixes):
            prefix_len = len(prefix)
            if name[:prefix_len] == prefix:
                return method_functors[index](name[prefix_len:])
        raise AttributeError(name)

    # Subnetpool methods
    def create_subnetpool(self, name, **kwargs):
        subnetpool_data = {'name': name}
        for arg in kwargs:
            subnetpool_data[arg] = kwargs[arg]

        post_data = {'subnetpool': subnetpool_data}
        body = self.serialize_list(post_data, "subnetpools", "subnetpool")
        uri = self.get_uri("subnetpools")
        resp, body = self.post(uri, body)
        body = {'subnetpool': self.deserialize_list(body)}
        self.expected_success(201, resp.status)
        return service_client.ResponseBody(resp, body)

    def get_subnetpool(self, id):
        uri = self.get_uri("subnetpools")
        subnetpool_uri = '%s/%s' % (uri, id)
        resp, body = self.get(subnetpool_uri)
        body = {'subnetpool': self.deserialize_list(body)}
        self.expected_success(200, resp.status)
        return service_client.ResponseBody(resp, body)

    def delete_subnetpool(self, id):
        uri = self.get_uri("subnetpools")
        subnetpool_uri = '%s/%s' % (uri, id)
        resp, body = self.delete(subnetpool_uri)
        self.expected_success(204, resp.status)
        return service_client.ResponseBody(resp, body)

    def list_subnetpools(self, **filters):
        uri = self.get_uri("subnetpools")
        if filters:
            uri = '?'.join([uri, urlparse.urlencode(filters)])
        resp, body = self.get(uri)
        body = {'subnetpools': self.deserialize_list(body)}
        self.expected_success(200, resp.status)
        return service_client.ResponseBody(resp, body)

    def update_subnetpool(self, id, **kwargs):
        subnetpool_data = {}
        for arg in kwargs:
            subnetpool_data[arg] = kwargs[arg]

        post_data = {'subnetpool': subnetpool_data}
        body = self.serialize_list(post_data, "subnetpools", "subnetpool")
        uri = self.get_uri("subnetpools")
        subnetpool_uri = '%s/%s' % (uri, id)
        resp, body = self.put(subnetpool_uri, body)
        body = {'subnetpool': self.deserialize_list(body)}
        self.expected_success(200, resp.status)
        return service_client.ResponseBody(resp, body)

    def add_subnetpool_prefix(self, id, **kwargs):
        return self._subnetpool_prefix_operation(id, 'add_prefixes', kwargs)

    def remove_subnetpool_prefix(self, id, **kwargs):
        return self._subnetpool_prefix_operation(id,
                                                 'remove_prefixes',
                                                 kwargs)

    def _subnetpool_prefix_operation(self, id, operation, op_body):
        uri = self.get_uri("subnetpools")
        op_prefix_uri = '%s/%s/%s' % (uri, id, operation)
        body = jsonutils.dumps(op_body)
        resp, body = self.put(op_prefix_uri, body)
        body = jsonutils.loads(body)
        self.expected_success(200, resp.status)
        return service_client.ResponseBody(resp, body)

    # Common methods that are hard to automate
    def create_bulk_network(self, names, shared=False):
        network_list = [{'name': name, 'shared': shared} for name in names]
        post_data = {'networks': network_list}
        body = self.serialize_list(post_data, "networks", "network")
        uri = self.get_uri("networks")
        resp, body = self.post(uri, body)
        body = {'networks': self.deserialize_list(body)}
        self.expected_success(201, resp.status)
        return service_client.ResponseBody(resp, body)

    def create_bulk_subnet(self, subnet_list):
        post_data = {'subnets': subnet_list}
        body = self.serialize_list(post_data, 'subnets', 'subnet')
        uri = self.get_uri('subnets')
        resp, body = self.post(uri, body)
        body = {'subnets': self.deserialize_list(body)}
        self.expected_success(201, resp.status)
        return service_client.ResponseBody(resp, body)

    def create_bulk_port(self, port_list):
        post_data = {'ports': port_list}
        body = self.serialize_list(post_data, 'ports', 'port')
        uri = self.get_uri('ports')
        resp, body = self.post(uri, body)
        body = {'ports': self.deserialize_list(body)}
        self.expected_success(201, resp.status)
        return service_client.ResponseBody(resp, body)

    def create_bulk_security_groups(self, security_group_list,
                                    stateless=False):
        group_list = [{'security_group': {'name': name}}
                      for name in security_group_list]
        if stateless:
            for group in group_list:
                group['security_group']['stateful'] = False
        post_data = {'security_groups': group_list}
        body = self.serialize_list(post_data, 'security_groups',
                                   'security_group')
        uri = self.get_uri("security-groups")
        resp, body = self.post(uri, body)
        body = {'security_groups': self.deserialize_list(body)}
        self.expected_success(201, resp.status)
        return service_client.ResponseBody(resp, body)

    def wait_for_resource_deletion(self, resource_type, id):
        """Waits for a resource to be deleted."""
        start_time = int(time.time())
        while True:
            if self.is_resource_deleted(resource_type, id):
                return
            if int(time.time()) - start_time >= self.build_timeout:
                raise lib_exc.TimeoutException
            time.sleep(self.build_interval)

    def is_resource_deleted(self, resource_type, id):
        method = 'show_' + resource_type
        try:
            getattr(self, method)(id)
        except AttributeError:
            raise Exception(_("Unknown resource type %s " % resource_type))
        except lib_exc.NotFound:
            return True
        return False

    def deserialize_single(self, body):
        return jsonutils.loads(body)

    def deserialize_list(self, body):
        res = jsonutils.loads(body)
        # expecting response in form
        # {'resources': [ res1, res2] } => when pagination disabled
        # {'resources': [..], 'resources_links': {}} => if pagination enabled
        for k in res.keys():
            if k.endswith("_links"):
                continue
            return res[k]

    def deserialize_links(self, body):
        res = jsonutils.loads(body)
        # expecting response in form
        # {'resources': [ res1, res2] } => when pagination disabled
        # {'resources': [..], 'resources_links': {}} => if pagination enabled
        for k in res.keys():
            if k.endswith("_links"):
                return {
                    link['rel']: link['href']
                    for link in res[k]
                }
        return {}

    def serialize(self, data):
        return jsonutils.dumps(data)

    def serialize_list(self, data, root=None, item=None):
        return self.serialize(data)

    def update_quotas(self, tenant_id, **kwargs):
        put_body = {'quota': kwargs}
        body = jsonutils.dumps(put_body)
        uri = '%s/quotas/%s' % (self.uri_prefix, tenant_id)
        resp, body = self.put(uri, body)
        self.expected_success(200, resp.status)
        body = jsonutils.loads(body)
        return service_client.ResponseBody(resp, body['quota'])

    def reset_quotas(self, tenant_id):
        uri = '%s/quotas/%s' % (self.uri_prefix, tenant_id)
        resp, body = self.delete(uri)
        self.expected_success(204, resp.status)
        return service_client.ResponseBody(resp, body)

    def create_router(self, name, admin_state_up=True, **kwargs):
        post_body = {'router': kwargs}
        post_body['router']['name'] = name
        post_body['router']['admin_state_up'] = admin_state_up
        body = jsonutils.dumps(post_body)
        uri = '%s/routers' % (self.uri_prefix)
        resp, body = self.post(uri, body)
        self.expected_success(201, resp.status)
        body = jsonutils.loads(body)
        return service_client.ResponseBody(resp, body)

    def _update_router(self, router_id, set_enable_snat, **kwargs):
        uri = '%s/routers/%s' % (self.uri_prefix, router_id)
        resp, body = self.get(uri)
        self.expected_success(200, resp.status)
        body = jsonutils.loads(body)
        update_body = {}
        update_body['name'] = kwargs.get('name', body['router']['name'])
        update_body['admin_state_up'] = kwargs.get(
            'admin_state_up', body['router']['admin_state_up'])
        if 'description' in kwargs:
            update_body['description'] = kwargs['description']
        cur_gw_info = body['router']['external_gateway_info']
        if cur_gw_info:
            # TODO(kevinbenton): setting the external gateway info is not
            # allowed for a regular tenant. If the ability to update is also
            # merged, a test case for this will need to be added similar to
            # the SNAT case.
            cur_gw_info.pop('external_fixed_ips', None)
            if not set_enable_snat:
                cur_gw_info.pop('enable_snat', None)
        update_body['external_gateway_info'] = kwargs.get(
            'external_gateway_info', body['router']['external_gateway_info'])
        if 'distributed' in kwargs:
            update_body['distributed'] = kwargs['distributed']
        if 'ha' in kwargs:
            update_body['ha'] = kwargs['ha']
        if 'routes' in kwargs:
            update_body['routes'] = kwargs['routes']
        if 'enable_ndp_proxy' in kwargs:
            update_body['enable_ndp_proxy'] = kwargs['enable_ndp_proxy']
        for attr in ('enable_default_route_bfd', 'enable_default_route_ecmp'):
            if attr in kwargs:
                update_body[attr] = kwargs[attr]
        update_body = dict(router=update_body)
        update_body = jsonutils.dumps(update_body)
        resp, body = self.put(uri, update_body)
        self.expected_success(200, resp.status)
        body = jsonutils.loads(body)
        return service_client.ResponseBody(resp, body)

    def update_router(self, router_id, **kwargs):
        """Update a router leaving enable_snat to its default value."""
        # If external_gateway_info contains enable_snat the request will fail
        # with 404 unless executed with admin client, and therefore we instruct
        # _update_router to not set this attribute
        # NOTE(salv-orlando): The above applies as long as Neutron's default
        # policy is to restrict enable_snat usage to admins only.
        return self._update_router(router_id, set_enable_snat=False, **kwargs)

    def update_router_with_snat_gw_info(self, router_id, **kwargs):
        """Update a router passing also the enable_snat attribute.

        This method must be execute with admin credentials, otherwise the API
        call will return a 404 error.
        """
        return self._update_router(router_id, set_enable_snat=True, **kwargs)

    def add_router_interface_with_subnet_id(self, router_id, subnet_id):
        uri = '%s/routers/%s/add_router_interface' % (self.uri_prefix,
                                                      router_id)
        update_body = {"subnet_id": subnet_id}
        update_body = jsonutils.dumps(update_body)
        resp, body = self.put(uri, update_body)
        self.expected_success(200, resp.status)
        body = jsonutils.loads(body)
        return service_client.ResponseBody(resp, body)

    def add_router_interface_with_port_id(self, router_id, port_id):
        uri = '%s/routers/%s/add_router_interface' % (self.uri_prefix,
                                                      router_id)
        update_body = {"port_id": port_id}
        update_body = jsonutils.dumps(update_body)
        resp, body = self.put(uri, update_body)
        self.expected_success(200, resp.status)
        body = jsonutils.loads(body)
        return service_client.ResponseBody(resp, body)

    def remove_router_interface_with_subnet_id(self, router_id, subnet_id):
        uri = '%s/routers/%s/remove_router_interface' % (self.uri_prefix,
                                                         router_id)
        update_body = {"subnet_id": subnet_id}
        update_body = jsonutils.dumps(update_body)
        resp, body = self.put(uri, update_body)
        self.expected_success(200, resp.status)
        body = jsonutils.loads(body)
        return service_client.ResponseBody(resp, body)

    def remove_router_interface_with_port_id(self, router_id, port_id):
        uri = '%s/routers/%s/remove_router_interface' % (self.uri_prefix,
                                                         router_id)
        update_body = {"port_id": port_id}
        update_body = jsonutils.dumps(update_body)
        resp, body = self.put(uri, update_body)
        self.expected_success(200, resp.status)
        body = jsonutils.loads(body)
        return service_client.ResponseBody(resp, body)

    def list_router_interfaces(self, uuid):
        uri = '%s/ports?device_id=%s' % (self.uri_prefix, uuid)
        resp, body = self.get(uri)
        self.expected_success(200, resp.status)
        body = jsonutils.loads(body)
        return service_client.ResponseBody(resp, body)

    def remove_router_extra_routes(self, router_id):
        self.update_router(router_id, routes=None)

    def router_add_external_gateways(self, router_id, external_gateways):
        uri = '%s/routers/%s/add_external_gateways' % (self.uri_prefix,
                                                       router_id)
        update_body = {
                'router': {'external_gateways': external_gateways},
        }
        update_body = jsonutils.dumps(update_body)
        resp, body = self.put(uri, update_body)
        self.expected_success(200, resp.status)
        body = jsonutils.loads(body)
        return service_client.ResponseBody(resp, body)

    def router_remove_external_gateways(self, router_id, external_gateways):
        uri = '%s/routers/%s/remove_external_gateways' % (self.uri_prefix,
                                                          router_id)
        update_body = {
                'router': {'external_gateways': external_gateways},
        }
        update_body = jsonutils.dumps(update_body)
        resp, body = self.put(uri, update_body)
        self.expected_success(200, resp.status)
        body = jsonutils.loads(body)
        return service_client.ResponseBody(resp, body)

    def router_update_external_gateways(self, router_id, external_gateways):
        uri = '%s/routers/%s/update_external_gateways' % (self.uri_prefix,
                                                          router_id)
        update_body = {
                'router': {'external_gateways': external_gateways},
        }
        update_body = jsonutils.dumps(update_body)
        resp, body = self.put(uri, update_body)
        self.expected_success(200, resp.status)
        body = jsonutils.loads(body)
        return service_client.ResponseBody(resp, body)

    def update_agent(self, agent_id, agent_info):
        """Update an agent

        :param agent_info: Agent update information.
        E.g {"admin_state_up": True}
        """
        uri = '%s/agents/%s' % (self.uri_prefix, agent_id)
        agent = {"agent": agent_info}
        body = jsonutils.dumps(agent)
        resp, body = self.put(uri, body)
        self.expected_success(200, resp.status)
        body = jsonutils.loads(body)
        return service_client.ResponseBody(resp, body)

    def delete_agent(self, agent_id):
        uri = '%s/agents/%s' % (self.uri_prefix, agent_id)
        resp, body = self.delete(uri)
        self.expected_success(204, resp.status)
        return service_client.ResponseBody(resp, body)

    def list_routers_on_l3_agent(self, agent_id):
        uri = '%s/agents/%s/l3-routers' % (self.uri_prefix, agent_id)
        resp, body = self.get(uri)
        self.expected_success(200, resp.status)
        body = jsonutils.loads(body)
        return service_client.ResponseBody(resp, body)

    def list_l3_agents_hosting_router(self, router_id):
        uri = '%s/routers/%s/l3-agents' % (self.uri_prefix, router_id)
        resp, body = self.get(uri)
        self.expected_success(200, resp.status)
        body = jsonutils.loads(body)
        return service_client.ResponseBody(resp, body)

    def add_router_to_l3_agent(self, agent_id, router_id):
        uri = '%s/agents/%s/l3-routers' % (self.uri_prefix, agent_id)
        post_body = {"router_id": router_id}
        body = jsonutils.dumps(post_body)
        resp, body = self.post(uri, body)
        self.expected_success(201, resp.status)
        body = jsonutils.loads(body)
        return service_client.ResponseBody(resp, body)

    def remove_router_from_l3_agent(self, agent_id, router_id):
        uri = '%s/agents/%s/l3-routers/%s' % (
            self.uri_prefix, agent_id, router_id)
        resp, body = self.delete(uri)
        self.expected_success(204, resp.status)
        return service_client.ResponseBody(resp, body)

    def list_dhcp_agent_hosting_network(self, network_id):
        uri = '%s/networks/%s/dhcp-agents' % (self.uri_prefix, network_id)
        resp, body = self.get(uri)
        self.expected_success(200, resp.status)
        body = jsonutils.loads(body)
        return service_client.ResponseBody(resp, body)

    def list_networks_hosted_by_one_dhcp_agent(self, agent_id):
        uri = '%s/agents/%s/dhcp-networks' % (self.uri_prefix, agent_id)
        resp, body = self.get(uri)
        self.expected_success(200, resp.status)
        body = jsonutils.loads(body)
        return service_client.ResponseBody(resp, body)

    def remove_network_from_dhcp_agent(self, agent_id, network_id):
        uri = '%s/agents/%s/dhcp-networks/%s' % (self.uri_prefix, agent_id,
                                                 network_id)
        resp, body = self.delete(uri)
        self.expected_success(204, resp.status)
        return service_client.ResponseBody(resp, body)

    def update_extra_routes(self, router_id, nexthop, destination):
        uri = '%s/routers/%s' % (self.uri_prefix, router_id)
        put_body = {
            'router': {
                'routes': [{'nexthop': nexthop,
                            "destination": destination}]
            }
        }
        body = jsonutils.dumps(put_body)
        resp, body = self.put(uri, body)
        self.expected_success(200, resp.status)
        body = jsonutils.loads(body)
        return service_client.ResponseBody(resp, body)

    def delete_extra_routes(self, router_id):
        uri = '%s/routers/%s' % (self.uri_prefix, router_id)
        null_routes = None
        put_body = {
            'router': {
                'routes': null_routes
            }
        }
        body = jsonutils.dumps(put_body)
        resp, body = self.put(uri, body)
        self.expected_success(200, resp.status)
        body = jsonutils.loads(body)
        return service_client.ResponseBody(resp, body)

    def add_extra_routes_atomic(self, router_id, routes):
        uri = '%s/routers/%s/add_extraroutes' % (self.uri_prefix, router_id)
        request_body = {'router': {'routes': routes}}
        resp, response_body = self.put(uri, jsonutils.dumps(request_body))
        self.expected_success(200, resp.status)
        return service_client.ResponseBody(
            resp, jsonutils.loads(response_body))

    def remove_extra_routes_atomic(self, router_id, routes):
        uri = '%s/routers/%s/remove_extraroutes' % (self.uri_prefix, router_id)
        request_body = {'router': {'routes': routes}}
        resp, response_body = self.put(uri, jsonutils.dumps(request_body))
        self.expected_success(200, resp.status)
        return service_client.ResponseBody(
            resp, jsonutils.loads(response_body))

    def add_dhcp_agent_to_network(self, agent_id, network_id):
        post_body = {'network_id': network_id}
        body = jsonutils.dumps(post_body)
        uri = '%s/agents/%s/dhcp-networks' % (self.uri_prefix, agent_id)
        resp, body = self.post(uri, body)
        self.expected_success(201, resp.status)
        body = jsonutils.loads(body)
        return service_client.ResponseBody(resp, body)

    def list_qos_policies(self, **filters):
        if filters:
            uri = '%s/qos/policies?%s' % (self.uri_prefix,
                                          urlparse.urlencode(filters))
        else:
            uri = '%s/qos/policies' % self.uri_prefix
        resp, body = self.get(uri)
        self.expected_success(200, resp.status)
        body = jsonutils.loads(body)
        return service_client.ResponseBody(resp, body)

    def create_qos_policy(self, name, description=None, shared=False,
                          project_id=None, is_default=False):
        uri = '%s/qos/policies' % self.uri_prefix
        post_data = {
            'policy': {
                'name': name,
                'shared': shared,
                'is_default': is_default
            }
        }
        if description is not None:
            post_data['policy']['description'] = description
        if project_id is not None:
            post_data['policy']['project_id'] = project_id
        resp, body = self.post(uri, self.serialize(post_data))
        body = self.deserialize_single(body)
        self.expected_success(201, resp.status)
        return service_client.ResponseBody(resp, body)

    def update_qos_policy(self, policy_id, **kwargs):
        uri = '%s/qos/policies/%s' % (self.uri_prefix, policy_id)
        post_data = self.serialize({'policy': kwargs})
        resp, body = self.put(uri, post_data)
        body = self.deserialize_single(body)
        self.expected_success(200, resp.status)
        return service_client.ResponseBody(resp, body)

    def create_dscp_marking_rule(self, policy_id, dscp_mark):
        uri = '%s/qos/policies/%s/dscp_marking_rules' % (
            self.uri_prefix, policy_id)
        post_data = self.serialize({
            'dscp_marking_rule': {
                'dscp_mark': dscp_mark
            }
        })
        resp, body = self.post(uri, post_data)
        self.expected_success(201, resp.status)
        body = jsonutils.loads(body)
        return service_client.ResponseBody(resp, body)

    def list_dscp_marking_rules(self, policy_id):
        uri = '%s/qos/policies/%s/dscp_marking_rules' % (
            self.uri_prefix, policy_id)
        resp, body = self.get(uri)
        body = self.deserialize_single(body)
        self.expected_success(200, resp.status)
        return service_client.ResponseBody(resp, body)

    def show_dscp_marking_rule(self, policy_id, rule_id):
        uri = '%s/qos/policies/%s/dscp_marking_rules/%s' % (
            self.uri_prefix, policy_id, rule_id)
        resp, body = self.get(uri)
        body = self.deserialize_single(body)
        self.expected_success(200, resp.status)
        return service_client.ResponseBody(resp, body)

    def update_dscp_marking_rule(self, policy_id, rule_id, **kwargs):
        uri = '%s/qos/policies/%s/dscp_marking_rules/%s' % (
            self.uri_prefix, policy_id, rule_id)
        post_data = {'dscp_marking_rule': kwargs}
        resp, body = self.put(uri, jsonutils.dumps(post_data))
        body = self.deserialize_single(body)
        self.expected_success(200, resp.status)
        return service_client.ResponseBody(resp, body)

    def delete_dscp_marking_rule(self, policy_id, rule_id):
        uri = '%s/qos/policies/%s/dscp_marking_rules/%s' % (
            self.uri_prefix, policy_id, rule_id)
        resp, body = self.delete(uri)
        self.expected_success(204, resp.status)
        return service_client.ResponseBody(resp, body)

    def list_qos_rule_types(self):
        uri = '%s/qos/rule-types' % self.uri_prefix
        resp, body = self.get(uri)
        self.expected_success(200, resp.status)
        body = jsonutils.loads(body)
        return service_client.ResponseBody(resp, body)

    def show_qos_rule_type(self, rule_type_name):
        uri = '%s/qos/rule-types/%s' % (
            self.uri_prefix, rule_type_name)
        resp, body = self.get(uri)
        self.expected_success(200, resp.status)
        body = jsonutils.loads(body)
        return service_client.ResponseBody(resp, body)

    def create_trunk(self, parent_port_id=None, subports=None,
                     tenant_id=None, name=None, admin_state_up=None,
                     description=None, **kwargs):
        uri = '%s/trunks' % self.uri_prefix
        if parent_port_id:
            kwargs['port_id'] = parent_port_id
        if subports is not None:
            kwargs['sub_ports'] = subports
        if tenant_id is not None:
            kwargs['tenant_id'] = tenant_id
        if name is not None:
            kwargs['name'] = name
        if description is not None:
            kwargs['description'] = description
        if admin_state_up is not None:
            kwargs['admin_state_up'] = admin_state_up
        resp, body = self.post(uri, self.serialize({'trunk': kwargs}))
        body = self.deserialize_single(body)
        self.expected_success(201, resp.status)
        return service_client.ResponseBody(resp, body)

    def update_trunk(self, trunk_id, **kwargs):
        put_body = {'trunk': kwargs}
        body = jsonutils.dumps(put_body)
        uri = '%s/trunks/%s' % (self.uri_prefix, trunk_id)
        resp, body = self.put(uri, body)
        self.expected_success(200, resp.status)
        body = jsonutils.loads(body)
        return service_client.ResponseBody(resp, body)

    def show_trunk(self, trunk_id):
        uri = '%s/trunks/%s' % (self.uri_prefix, trunk_id)
        resp, body = self.get(uri)
        body = self.deserialize_single(body)
        self.expected_success(200, resp.status)
        return service_client.ResponseBody(resp, body)

    def list_trunks(self, **kwargs):
        uri = '%s/trunks' % self.uri_prefix
        if kwargs:
            uri += '?' + urlparse.urlencode(kwargs, doseq=1)
        resp, body = self.get(uri)
        self.expected_success(200, resp.status)
        body = self.deserialize_single(body)
        return service_client.ResponseBody(resp, body)

    def delete_trunk(self, trunk_id):
        uri = '%s/trunks/%s' % (self.uri_prefix, trunk_id)
        resp, body = self.delete(uri)
        self.expected_success(204, resp.status)
        return service_client.ResponseBody(resp, body)

    def _subports_action(self, action, trunk_id, subports):
        uri = '%s/trunks/%s/%s' % (self.uri_prefix, trunk_id, action)
        resp, body = self.put(uri, jsonutils.dumps({'sub_ports': subports}))
        body = self.deserialize_single(body)
        self.expected_success(200, resp.status)
        return service_client.ResponseBody(resp, body)

    def add_subports(self, trunk_id, subports):
        return self._subports_action('add_subports', trunk_id, subports)

    def remove_subports(self, trunk_id, subports):
        return self._subports_action('remove_subports', trunk_id, subports)

    def get_subports(self, trunk_id):
        uri = '%s/trunks/%s/%s' % (self.uri_prefix, trunk_id, 'get_subports')
        resp, body = self.get(uri)
        self.expected_success(200, resp.status)
        body = jsonutils.loads(body)
        return service_client.ResponseBody(resp, body)

    def validate_auto_allocated_topology_requirements(self, tenant_id=None):
        uri = '%s/auto-allocated-topology/%s?fields=dry-run' % (
            self.uri_prefix, tenant_id)
        resp, body = self.get(uri)
        self.expected_success(200, resp.status)
        body = jsonutils.loads(body)
        return service_client.ResponseBody(resp, body)

    def get_auto_allocated_topology(self, tenant_id=None):
        uri = '%s/auto-allocated-topology/%s' % (self.uri_prefix, tenant_id)
        resp, body = self.get(uri)
        self.expected_success(200, resp.status)
        body = jsonutils.loads(body)
        return service_client.ResponseBody(resp, body)

    def delete_auto_allocated_topology(self, tenant_id=None):
        uri = '%s/auto-allocated-topology/%s' % (self.uri_prefix, tenant_id)
        resp, body = self.delete(uri)
        self.expected_success(204, resp.status)
        return service_client.ResponseBody(resp, body)

    def create_flavor_service_profile(self, flavor_id, service_profile_id):
        body = jsonutils.dumps({'service_profile': {'id': service_profile_id}})
        uri = '%s/flavors/%s/service_profiles' % (self.uri_prefix, flavor_id)
        resp, body = self.post(uri, body)
        self.expected_success(201, resp.status)
        body = jsonutils.loads(body)
        return service_client.ResponseBody(resp, body)

    def list_flavor_service_profiles(self, flavor_id):
        uri = '%s/flavors/%s/service_profiles' % (self.uri_prefix, flavor_id)
        resp, body = self.get(uri)
        self.expected_success(200, resp.status)
        body = jsonutils.loads(body)
        return service_client.ResponseBody(resp, body)

    def delete_flavor_service_profile(self, flavor_id, service_profile_id):
        uri = '%s/flavors/%s/service_profiles/%s' % (self.uri_prefix,
                                                     flavor_id,
                                                     service_profile_id)
        resp, body = self.delete(uri)
        self.expected_success(204, resp.status)
        return service_client.ResponseBody(resp, body)

    def list_security_group_rules(self, **kwargs):
        uri = '%s/security-group-rules' % self.uri_prefix
        if kwargs:
            uri += '?' + urlparse.urlencode(kwargs, doseq=1)
        resp, body = self.get(uri)
        self.expected_success(200, resp.status)
        body = jsonutils.loads(body)
        return service_client.ResponseBody(resp, body)

    def create_security_group_rule(self, direction, security_group_id,
                                   **kwargs):
        post_body = {'security_group_rule': kwargs}
        post_body['security_group_rule']['direction'] = direction
        post_body['security_group_rule'][
            'security_group_id'] = security_group_id
        body = jsonutils.dumps(post_body)
        uri = '%s/security-group-rules' % self.uri_prefix
        resp, body = self.post(uri, body)
        self.expected_success(201, resp.status)
        body = jsonutils.loads(body)
        return service_client.ResponseBody(resp, body)

    def delete_security_group_rule(self, security_group_rule_id):
        uri = '%s/security-group-rules/%s' % (self.uri_prefix,
                                              security_group_rule_id)
        resp, body = self.delete(uri)
        self.expected_success(204, resp.status)
        return service_client.ResponseBody(resp, body)

    def list_security_groups(self, **kwargs):
        uri = '%s/security-groups' % self.uri_prefix
        if kwargs:
            uri += '?' + urlparse.urlencode(kwargs, doseq=1)
        resp, body = self.get(uri)
        self.expected_success(200, resp.status)
        body = jsonutils.loads(body)
        return service_client.ResponseBody(resp, body)

    def delete_security_group(self, security_group_id):
        uri = '%s/security-groups/%s' % (
            self.uri_prefix, security_group_id)
        resp, body = self.delete(uri)
        self.expected_success(204, resp.status)
        return service_client.ResponseBody(resp, body)

    def list_default_security_group_rules(self, **kwargs):
        uri = '%s/default-security-group-rules' % self.uri_prefix
        if kwargs:
            uri += '?' + urlparse.urlencode(kwargs, doseq=1)
        resp, body = self.get(uri)
        self.expected_success(200, resp.status)
        body = jsonutils.loads(body)
        return service_client.ResponseBody(resp, body)

    def get_default_security_group_rule(self, rule_id):
        uri = '%s/default-security-group-rules/%s' % (self.uri_prefix,
                                                      rule_id)
        get_resp, get_resp_body = self.get(uri)
        self.expected_success(200, get_resp.status)
        body = jsonutils.loads(get_resp_body)
        return service_client.ResponseBody(get_resp, body)

    def create_default_security_group_rule(self, **kwargs):
        post_body = {'default_security_group_rule': kwargs}
        body = jsonutils.dumps(post_body)
        uri = '%s/default-security-group-rules' % self.uri_prefix
        resp, body = self.post(uri, body)
        self.expected_success(201, resp.status)
        body = jsonutils.loads(body)
        return service_client.ResponseBody(resp, body)

    def delete_default_security_group_rule(self, rule_id):
        uri = '%s/default-security-group-rules/%s' % (self.uri_prefix, rule_id)
        resp, body = self.delete(uri)
        self.expected_success(204, resp.status)
        return service_client.ResponseBody(resp, body)

    def list_ports(self, **kwargs):
        uri = '%s/ports' % self.uri_prefix
        if kwargs:
            uri += '?' + urlparse.urlencode(kwargs, doseq=1)
        resp, body = self.get(uri)
        self.expected_success(200, resp.status)
        body = jsonutils.loads(body)
        return service_client.ResponseBody(resp, body)

    def list_floatingips(self, **kwargs):
        uri = '%s/floatingips' % self.uri_prefix
        if kwargs:
            uri += '?' + urlparse.urlencode(kwargs, doseq=1)
        resp, body = self.get(uri)
        self.expected_success(200, resp.status)
        body = jsonutils.loads(body)
        return service_client.ResponseBody(resp, body)

    def create_floatingip(self, floating_network_id, **kwargs):
        post_body = {'floatingip': {
            'floating_network_id': floating_network_id}}
        if kwargs:
            post_body['floatingip'].update(kwargs)
        body = jsonutils.dumps(post_body)
        uri = '%s/floatingips' % self.uri_prefix
        resp, body = self.post(uri, body)
        self.expected_success(201, resp.status)
        body = jsonutils.loads(body)
        return service_client.ResponseBody(resp, body)

    def get_floatingip(self, fip_id):
        uri = '%s/floatingips/%s' % (self.uri_prefix, fip_id)
        get_resp, get_resp_body = self.get(uri)
        self.expected_success(200, get_resp.status)
        body = jsonutils.loads(get_resp_body)
        return service_client.ResponseBody(get_resp, body)

    def update_floatingip(self, fip_id, **kwargs):
        uri = '%s/floatingips/%s' % (self.uri_prefix, fip_id)
        get_resp, _ = self.get(uri)
        self.expected_success(200, get_resp.status)
        put_body = jsonutils.dumps({'floatingip': kwargs})
        put_resp, resp_body = self.put(uri, put_body)
        self.expected_success(200, put_resp.status)
        body = jsonutils.loads(resp_body)
        return service_client.ResponseBody(put_resp, body)

    def create_port_forwarding(self, fip_id, internal_port_id,
                               internal_port, external_port,
                               internal_ip_address=None, protocol='tcp'):
        post_body = {'port_forwarding': {
            'protocol': protocol,
            'internal_port_id': internal_port_id,
            'internal_port': int(internal_port),
            'external_port': int(external_port)}}
        if internal_ip_address:
            post_body['port_forwarding']['internal_ip_address'] = (
                internal_ip_address)
        body = jsonutils.dumps(post_body)
        uri = '%s/floatingips/%s/port_forwardings' % (self.uri_prefix, fip_id)
        resp, body = self.post(uri, body)
        self.expected_success(201, resp.status)
        body = jsonutils.loads(body)
        return service_client.ResponseBody(resp, body)

    def get_port_forwarding(self, fip_id, pf_id):
        uri = '%s/floatingips/%s/port_forwardings/%s' % (self.uri_prefix,
                                                         fip_id, pf_id)
        get_resp, get_resp_body = self.get(uri)
        self.expected_success(200, get_resp.status)
        body = jsonutils.loads(get_resp_body)
        return service_client.ResponseBody(get_resp, body)

    def list_port_forwardings(self, fip_id):
        uri = '%s/floatingips/%s/port_forwardings' % (self.uri_prefix, fip_id)
        resp, body = self.get(uri)
        self.expected_success(200, resp.status)
        body = jsonutils.loads(body)
        return service_client.ResponseBody(resp, body)

    def update_port_forwarding(self, fip_id, pf_id, **kwargs):
        uri = '%s/floatingips/%s/port_forwardings/%s' % (self.uri_prefix,
                                                         fip_id, pf_id)
        put_body = jsonutils.dumps({'port_forwarding': kwargs})
        put_resp, resp_body = self.put(uri, put_body)
        self.expected_success(200, put_resp.status)
        body = jsonutils.loads(resp_body)
        return service_client.ResponseBody(put_resp, body)

    def delete_port_forwarding(self, fip_id, pf_id):
        uri = '%s/floatingips/%s/port_forwardings/%s' % (self.uri_prefix,
                                                         fip_id, pf_id)
        resp, body = self.delete(uri)
        self.expected_success(204, resp.status)
        service_client.ResponseBody(resp, body)

    def create_local_ip(self, network_id, **kwargs):
        post_body = {'local_ip': {
            'network_id': network_id}}
        if kwargs:
            post_body['local_ip'].update(kwargs)
        body = jsonutils.dumps(post_body)
        uri = '%s/local_ips' % self.uri_prefix
        resp, body = self.post(uri, body)
        self.expected_success(201, resp.status)
        body = jsonutils.loads(body)
        return service_client.ResponseBody(resp, body)

    def list_local_ips(self, **kwargs):
        uri = '%s/local_ips' % self.uri_prefix
        if kwargs:
            uri += '?' + urlparse.urlencode(kwargs, doseq=1)
        resp, body = self.get(uri)
        self.expected_success(200, resp.status)
        body = jsonutils.loads(body)
        return service_client.ResponseBody(resp, body)

    def get_local_ip(self, local_ip_id):
        uri = '%s/local_ips/%s' % (self.uri_prefix, local_ip_id)
        get_resp, get_resp_body = self.get(uri)
        self.expected_success(200, get_resp.status)
        body = jsonutils.loads(get_resp_body)
        return service_client.ResponseBody(get_resp, body)

    def update_local_ip(self, local_ip_id, **kwargs):
        uri = '%s/local_ips/%s' % (self.uri_prefix, local_ip_id)
        get_resp, _ = self.get(uri)
        self.expected_success(200, get_resp.status)
        put_body = jsonutils.dumps({'local_ip': kwargs})
        put_resp, resp_body = self.put(uri, put_body)
        self.expected_success(200, put_resp.status)
        body = jsonutils.loads(resp_body)
        return service_client.ResponseBody(put_resp, body)

    def delete_local_ip(self, local_ip_id):
        uri = '%s/local_ips/%s' % (
            self.uri_prefix, local_ip_id)
        resp, body = self.delete(uri)
        self.expected_success(204, resp.status)
        return service_client.ResponseBody(resp, body)

    def create_local_ip_association(self, local_ip_id, fixed_port_id,
                                    fixed_ip=None):
        post_body = {'port_association': {
            'fixed_port_id': fixed_port_id}}
        if fixed_ip:
            post_body['port_association']['fixed_ip'] = (
                fixed_ip)
        body = jsonutils.dumps(post_body)
        uri = '%s/local_ips/%s/port_associations' % (self.uri_prefix,
                                                     local_ip_id)
        resp, body = self.post(uri, body)
        self.expected_success(201, resp.status)
        body = jsonutils.loads(body)
        return service_client.ResponseBody(resp, body)

    def get_local_ip_association(self, local_ip_id, fixed_port_id):
        uri = '%s/local_ips/%s/port_associations/%s' % (self.uri_prefix,
                                                        local_ip_id,
                                                        fixed_port_id)
        get_resp, get_resp_body = self.get(uri)
        self.expected_success(200, get_resp.status)
        body = jsonutils.loads(get_resp_body)
        return service_client.ResponseBody(get_resp, body)

    def list_local_ip_associations(self, local_ip_id):
        uri = '%s/local_ips/%s/port_associations' % (self.uri_prefix,
                                                     local_ip_id)
        resp, body = self.get(uri)
        self.expected_success(200, resp.status)
        body = jsonutils.loads(body)
        return service_client.ResponseBody(resp, body)

    def delete_local_ip_association(self, local_ip_id, fixed_port_id):

        uri = '%s/local_ips/%s/port_associations/%s' % (self.uri_prefix,
                                                        local_ip_id,
                                                        fixed_port_id)
        resp, body = self.delete(uri)
        self.expected_success(204, resp.status)
        service_client.ResponseBody(resp, body)

    def create_conntrack_helper(self, router_id, helper, protocol, port):
        post_body = {'conntrack_helper': {
            'helper': helper,
            'protocol': protocol,
            'port': port}}
        body = jsonutils.dumps(post_body)
        uri = '%s/routers/%s/conntrack_helpers' % (self.uri_prefix, router_id)
        resp, body = self.post(uri, body)
        self.expected_success(201, resp.status)
        body = jsonutils.loads(body)
        return service_client.ResponseBody(resp, body)

    def get_conntrack_helper(self, router_id, cth_id):
        uri = '%s/routers/%s/conntrack_helpers/%s' % (self.uri_prefix,
                                                      router_id, cth_id)
        get_resp, get_resp_body = self.get(uri)
        self.expected_success(200, get_resp.status)
        body = jsonutils.loads(get_resp_body)
        return service_client.ResponseBody(get_resp, body)

    def list_conntrack_helpers(self, router_id):
        uri = '%s/routers/%s/conntrack_helpers' % (self.uri_prefix, router_id)
        resp, body = self.get(uri)
        self.expected_success(200, resp.status)
        body = jsonutils.loads(body)
        return service_client.ResponseBody(resp, body)

    def update_conntrack_helper(self, router_id, cth_id, **kwargs):
        uri = '%s/routers/%s/conntrack_helpers/%s' % (self.uri_prefix,
                                                      router_id, cth_id)
        put_body = jsonutils.dumps({'conntrack_helper': kwargs})
        put_resp, resp_body = self.put(uri, put_body)
        self.expected_success(200, put_resp.status)
        body = jsonutils.loads(resp_body)
        return service_client.ResponseBody(put_resp, body)

    def delete_conntrack_helper(self, router_id, cth_id):
        uri = '%s/routers/%s/conntrack_helpers/%s' % (self.uri_prefix,
                                                      router_id, cth_id)
        resp, body = self.delete(uri)
        self.expected_success(204, resp.status)
        service_client.ResponseBody(resp, body)

    def list_extensions(self, **filters):
        uri = self.get_uri("extensions")
        if filters:
            uri = '?'.join([uri, urlparse.urlencode(filters)])
        resp, body = self.get(uri)
        body = {'extensions': self.deserialize_list(body)}
        self.expected_success(200, resp.status)
        return service_client.ResponseBody(resp, body)

    def get_extension(self, alias):
        uri = '%s/%s' % (
            self.get_uri('extensions'), alias)
        resp, body = self.get(uri)
        self.expected_success(200, resp.status)
        body = jsonutils.loads(body)
        return service_client.ResponseBody(resp, body)

    def get_tags(self, resource_type, resource_id):
        uri = '%s/%s/%s/tags' % (
            self.uri_prefix, resource_type, resource_id)
        resp, body = self.get(uri)
        self.expected_success(200, resp.status)
        body = jsonutils.loads(body)
        return service_client.ResponseBody(resp, body)

    def get_tag(self, resource_type, resource_id, tag):
        uri = '%s/%s/%s/tags/%s' % (
            self.uri_prefix, resource_type, resource_id, tag)
        resp, body = self.get(uri)
        self.expected_success(204, resp.status)

    def update_tag(self, resource_type, resource_id, tag):
        uri = '%s/%s/%s/tags/%s' % (
            self.uri_prefix, resource_type, resource_id, tag)
        resp, body = self.put(uri, None)
        self.expected_success(201, resp.status)

    def update_tags(self, resource_type, resource_id, tags):
        uri = '%s/%s/%s/tags' % (
            self.uri_prefix, resource_type, resource_id)
        req_body = jsonutils.dumps({'tags': tags})
        resp, body = self.put(uri, req_body)
        self.expected_success(200, resp.status)
        body = jsonutils.loads(body)
        return service_client.ResponseBody(resp, body)

    def delete_tags(self, resource_type, resource_id):
        uri = '%s/%s/%s/tags' % (
            self.uri_prefix, resource_type, resource_id)
        resp, body = self.delete(uri)
        self.expected_success(204, resp.status)

    def delete_tag(self, resource_type, resource_id, tag):
        uri = '%s/%s/%s/tags/%s' % (
            self.uri_prefix, resource_type, resource_id, tag)
        resp, body = self.delete(uri)
        self.expected_success(204, resp.status)

    def add_addresses_to_address_group(self, address_group_id, addresses):
        uri = '%s/address-groups/%s/add_addresses' % (
            self.uri_prefix, address_group_id)
        request_body = {'addresses': addresses}
        resp, response_body = self.put(uri, jsonutils.dumps(request_body))
        self.expected_success(200, resp.status)
        return service_client.ResponseBody(
            resp, jsonutils.loads(response_body))

    def remove_addresses_from_address_group(self, address_group_id, addresses):
        uri = '%s/address-groups/%s/remove_addresses' % (
            self.uri_prefix, address_group_id)
        request_body = {'addresses': addresses}
        resp, response_body = self.put(uri, jsonutils.dumps(request_body))
        self.expected_success(200, resp.status)
        return service_client.ResponseBody(
            resp, jsonutils.loads(response_body))

    def create_ndp_proxy(self, **kwargs):
        uri = '%s/ndp_proxies' % self.uri_prefix
        post_body = jsonutils.dumps({'ndp_proxy': kwargs})
        resp, response_body = self.post(uri, post_body)
        self.expected_success(201, resp.status)
        body = jsonutils.loads(response_body)
        return service_client.ResponseBody(resp, body)

    def list_ndp_proxies(self, **kwargs):
        uri = '%s/ndp_proxies' % self.uri_prefix
        if kwargs:
            uri += '?' + urlparse.urlencode(kwargs, doseq=1)
        resp, response_body = self.get(uri)
        self.expected_success(200, resp.status)
        body = jsonutils.loads(response_body)
        return service_client.ResponseBody(resp, body)

    def get_ndp_proxy(self, ndp_proxy_id):
        uri = '%s/ndp_proxies/%s' % (self.uri_prefix, ndp_proxy_id)
        get_resp, response_body = self.get(uri)
        self.expected_success(200, get_resp.status)
        body = jsonutils.loads(response_body)
        return service_client.ResponseBody(get_resp, body)

    def update_ndp_proxy(self, ndp_proxy_id, **kwargs):
        uri = '%s/ndp_proxies/%s' % (self.uri_prefix, ndp_proxy_id)
        get_resp, _ = self.get(uri)
        self.expected_success(200, get_resp.status)
        put_body = jsonutils.dumps({'ndp_proxy': kwargs})
        put_resp, response_body = self.put(uri, put_body)
        self.expected_success(200, put_resp.status)
        body = jsonutils.loads(response_body)
        return service_client.ResponseBody(put_resp, body)

    def delete_ndp_proxy(self, ndp_proxy_id):
        uri = '%s/ndp_proxies/%s' % (
            self.uri_prefix, ndp_proxy_id)
        resp, body = self.delete(uri)
        self.expected_success(204, resp.status)
        return service_client.ResponseBody(resp, body)
