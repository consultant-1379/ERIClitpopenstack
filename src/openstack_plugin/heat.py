##############################################################################
# COPYRIGHT Ericsson AB 2014
#
# The copyright to the computer program(s) herein is the property of
# Ericsson AB. The programs may be used and/or copied only with written
# permission from Ericsson AB. or in accordance with the terms and
# conditions stipulated in the agreement/contract under which the
# program(s) have been supplied.
##############################################################################

from collections import defaultdict
from time import sleep, time
import datetime
import os
import tempfile
import yaml

from keystoneclient.v2_0.client import Client as KeystoneClient
from heatclient.v1.client import Client as HeatClient
from heatclient.exc import HTTPConflict

from litp.core.litp_logging import LitpLogger

from litp.core.execution_manager import (CallbackExecutionException,
                                         PlanStoppedException)
from litp.core.validators import ValidationError
from .exceptions import ActionException
from .environments import ENVIRONMENT, FILES
from .utils import (patch_helper_callback, get_cluster, get_stack, get_tenant,
                    has_changed_dependencies, get_ancestor, get_stack_resource,
                    PLAN_STOPPED_MESSAGE)
from string import upper


LOG = LitpLogger()
MAX_WAIT_SECONDS = 600
UPDATE_POLICY_PAUSE = 30


def unicode_representer(_, uni):
    node = yaml.ScalarNode(tag=u'tag:yaml.org,2002:str', value=uni)
    return node


class Folded(unicode):
    pass


class Literal(unicode):
    pass


class Resource(unicode):
    '''
    Subclasses unicode so the class can be properly represented by yaml
    '''
    def __new__(cls, item, suffix=None):
        subpath = item.get_vpath().replace(
            get_stack(item).get_vpath(), '')[1:]

        subpath = subpath.replace('/', '_')

        if suffix:
            subpath = u"{0}_{1}".format(subpath, suffix)
        return super(Resource, cls).__new__(cls, subpath)

    def name(self):
        return unicode(self)


class Action(object):
    CREATE = "create"
    UPDATE = "update"
    REMOVE = "remove"


def _folded_representer(dumper, data):
    return dumper.represent_scalar(u'tag:yaml.org,2002:str', data, style='>')


def _literal_representer(dumper, data):
    return dumper.represent_scalar(u'tag:yaml.org,2002:str', data, style='|')


def _serialize(obj):
    '''
    Recursively prepare python dictionary for yaml dump
    Python objects should converted to Python inbuilt types for pyyaml to
    understand or have an equivalent representer.
    Using the conversion approach here as it was simpler to convert to built
    ins than to provide a complex representer. Also we can check for the
    HeatSerialisable superclass here, where as a representer for each subclass
    would need to be registered.
    '''
    if isinstance(obj, Resource):
        return {"get_resource": obj}
    if isinstance(obj, HeatSerialisable):
        data = {}
        for key, value in obj.__getstate__().iteritems():
            try:
                data[key] = _serialize(value)
            except AttributeError:
                data[key] = value
    elif isinstance(obj, dict):
        data = {}
        for key, value in obj.iteritems():
            data[key] = _serialize(value)
    elif isinstance(obj, list):
        data = []
        for value in obj:
            data.append(_serialize(value))
    else:
        data = obj
    return data


class Stack(object):

    def __init__(self, stack):
        self.provider = None
        self.user = None
        self.volumes = None
        self.stack = stack
        self.resources = {}

    def get_provider(self):
        if not self.provider:
            infra = self.stack.query_by_vpath('/infrastructure')
            self.provider = infra.query(
                'openstack-provider',
                name=get_cluster(self.stack).provider_name)[0]
        return self.provider

    def get_user(self):
        if not self.user:
            self.user = get_tenant(self.stack).query("tenant-user")[0]
        return self.user

    def get_volumes(self):
        if not self.volumes:
            self.volumes = get_tenant(self.stack).query("tenant-volume")
        return self.volumes

    def _load_resources(self):
        self.resources.update(_get_networks(self.stack))
        self.resources.update(_get_routers(self.stack))
        self.resources.update(_get_servers(self.stack))
        self.resources.update(_get_lb_monitors(self.stack))
        self.resources.update(_get_lb_groups(self.stack))
        self.resources.update(_get_keypairs(self.stack))
        self.resources.update(_get_security_groups(self.stack))
        self.resources.update(_get_ports(self.stack))

    def create_template(self):
        self._load_resources()
        yaml.add_representer(unicode, unicode_representer)
        yaml.add_representer(Resource, unicode_representer)
        yaml.add_representer(Folded, _folded_representer)
        yaml.add_representer(Literal, _literal_representer)

        template = {"heat_template_version": "2014-10-16",
                    "resources": _serialize(self.resources)}
        return yaml.dump(template, default_flow_style=False)

    def template_to_file(self, template_dump):
        template_file_path = self._get_template_dump_filepath()
        with open(template_file_path, 'w') as template_file:
            template_file.write(template_dump)

    def _get_template_dump_dir(self):
        template_dump_dir = "{0}/litp_heat_templates".format(
            tempfile.gettempdir())
        if not os.path.exists(template_dump_dir):
            os.makedirs(template_dump_dir)
        return template_dump_dir

    def _get_template_dump_filepath(self):
        """Generates the path for the template dump file in the format
        temp_folder/deployment_cloud_tenant_stack_timestamp.yaml
        """
        current_time = datetime.datetime.now()
        vpath_split = self.stack.get_vpath().split('/')[1:]
        vpath_for_file = [v for v in vpath_split if vpath_split.index(v) % 2]
        vpath_for_file = '_'.join(vpath_for_file)
        template_file_path = "{0}/{1}_{2}.yaml".format(
            self._get_template_dump_dir(), vpath_for_file,
            current_time.strftime("%Y%m%d%H%M%S"))
        return template_file_path

    @property
    def name(self):
        return self.stack.item_id

    @property
    def apd(self):
        return self.stack.applied_properties_determinable


class HeatSerialisable(object):
    resource = ""

    def __init__(self, item, **kwargs):
        self.properties = {}
        self.depends_on = []
        self.item = item
        depends = getattr(item, "depends_on", "")
        if depends:
            self.depends_on = [_find_dependent_resource(item, x)
                               for x in depends.split(",")]
        self._setup(item, **kwargs)

    def _setup(self, item, **kwargs):
        pass

    def __getstate__(self):
        template = {"type": self.resource}
        if self.properties:
            template["properties"] = self.properties
        if self.depends_on:
            depends = [unicode(x) for x in self.depends_on]
            template["depends_on"] = depends
        return template

    def add_property(self, key, value):
        self.properties[key] = value

    def add_depends(self, value):
        self.depends_on.append(value)


class AutoScaleLBGroup(HeatSerialisable):
    resource = "OS::Heat::AutoScalingGroup"

    def _setup(self, group):
        self.depends_on = []
        update_policy = {"min_in_service": int(group.max),
               "pause_time": UPDATE_POLICY_PAUSE,
               "max_batch_size": int(group.max)}
        self.add_property("cooldown", 30)
        self.add_property("max_size", group.max)
        self.add_property("min_size", group.min)
        self.add_property("rolling_updates",
               update_policy)

        alarms = len(group.query("tenant-alarm", is_for_removal=False))
        if alarms:
            resource = LBAlarmedServer(group)
        else:
            resource = LBServer(group)

        self.add_property('resource', resource)


class HealthMonitor(HeatSerialisable):
    resource = "OS::Neutron::HealthMonitor"

    def _setup(self, monitor):
        self.add_property("type", upper(monitor.type))
        self.add_property("delay", monitor.delay)
        self.add_property("max_retries", monitor.max_retries)
        self.add_property("timeout", monitor.timeout)
        if upper(monitor.type) in ["HTTP", "HTTPS"]:
            self.add_property("http_method", monitor.http_method)
            self.add_property("url_path", monitor.url_path)
            self.add_property("expected_codes", monitor.expected_codes)


class Pool(HeatSerialisable):
    resource = "OS::Neutron::Pool"

    def __init__(self, item, lb, **kwargs):
        self.lb = lb
        super(Pool, self).__init__(item, **kwargs)

    def _setup(self, lb_group):
        self.depends_on = []
        self.add_property("protocol", upper(self.lb.protocol))
        self.add_property("lb_method", upper(self.lb.lb_method))
        monitors = []
        for monitor in self.lb.monitors.split(','):
            m = get_stack_resource(lb_group, 'tenant-lb-monitor',
                                   name=monitor)
            monitors.append(Resource(m))
        self.add_property("monitors", monitors)
        self.add_property("vip",
                          {"protocol_port": self.lb.vip_port})
        subnet = get_stack_resource(lb_group,
                                    "tenant-network-subnet",
                                    name=self.lb.network_name)
        self.add_property("subnet",
                          Resource(subnet))


class LoadBalancer(HeatSerialisable):
    resource = "OS::Neutron::LoadBalancer"

    def _setup(self, lb):
        self.add_property("protocol_port", lb.vip_port)
        self.add_property("pool_id",
                          Resource(lb, 'pool'))


class Router(HeatSerialisable):
    resource = "OS::Neutron::Router"

    def _setup(self, router):
        self.add_property("external_gateway_info",
                          {"network": router.public_network})


class RouterInterface(HeatSerialisable):
    resource = "OS::Neutron::RouterInterface"

    def _setup(self, router):
        self.add_property("router_id", Resource(router))
        self.add_property("subnet_id", Resource(
            get_stack_resource(router,
                               "tenant-network-subnet",
                               name=router.network_name)))


class Subnet(HeatSerialisable):
    resource = "OS::Neutron::Subnet"

    def _setup(self, subnet):
        self.add_property("ip_version", subnet.ip_version)
        self.add_property("enable_dhcp", subnet.enable_dhcp)
        self.add_property("cidr", subnet.cidr)
        if subnet.disable_gateway:
            self.add_property("gateway_ip", "")


class Network(HeatSerialisable):
    resource = "OS::Neutron::Net"

    def _setup(self, network):
        pass


class Server(HeatSerialisable):
    resource = "OS::Nova::Server"

    def _setup(self, server):
        self.add_property("flavor", server.flavor)
        self.add_property("image", server.image_name)

        # Inject public key to the server
        keys = get_stack(server).query('tenant-keypair',
                                       name=server.key_name)
        if keys:
            key = keys[0]  # should only be one, trust validation in API
            self.add_property('key_name', Resource(key, 'key'))
        else:
            # Assume key is available in the cloud.
            self.add_property('key_name', server.key_name)

        # Attach networks to the server
        networks = []
        for network in server.networks:
            networks.append({"network": Resource(
                get_stack_resource(server,
                                   'tenant-network',
                                   name=network.network_name))})
        if networks:
            self.add_property("networks", networks)

        volumes = []
        for volume in server.volumes:
            if volume.name:
                uuid = get_tenant(server).volumes.query(
                    'tenant-volume',
                    name=volume.name)[0].uuid
                volumes.append({
                    "volume_id": uuid,
                    "device_name": volume.device_name}
                )
            else:
                volumes.append({
                    "volume_id": Resource(volume),
                    "device_name": volume.device_name}
                )

        if volumes:
            self.add_property("block_device_mapping",
                              volumes)

        # Add ports if security groups exist
        if server.security_group_names:
            self.add_property('networks',
                                [{'port': Resource(server, 'port')}])

        self.add_property('user_data_format', 'RAW')
        self.add_property('user_data', Resource(server, 'multipart_mime'))


class Volume(HeatSerialisable):
    resource = "OS::Cinder::Volume"

    def _setup(self, volume):
        self.add_property("size", volume.size)


class Keypair(HeatSerialisable):
    resource = "OS::Nova::KeyPair"

    def _setup(self, key):
        self.add_property("name", key.name)
        self.add_property("public_key", key.public_key)


class CloudConfig(HeatSerialisable):
    resource = "OS::Heat::CloudConfig"

    def _setup(self, item, **kwargs):
        if "yumrepos" in kwargs:
            self.add_property("cloud_config", self.get_config_yumrepos())
        elif "packages" in kwargs:
            self.add_property("cloud_config", self.get_config_packages())
        elif "network_mounts" in kwargs:
            self.add_property("cloud_config", self.get_config_network_mounts())
        elif "hostentries" in kwargs:
            self.add_property("cloud_config", self.get_config_hostentries())

    def get_config_yumrepos(self):
        repos = {}
        for repo in self.item.yumrepos:
            repos[repo.name] = {"baseurl": repo.baseurl,
                                "name": repo.name,
                                "gpgcheck": False,
                                "checksum": repo.checksum}
        return {"yum_repos": repos}

    def get_config_packages(self):
        packages = [package.name for package in self.item.packages]
        return {"packages": packages}

    def get_config_network_mounts(self):
        mounts = []
        for nmount in self.item.network_mounts:
            all_opts = "rsize=%s,wsize=%s,timeo=%s" % (
                nmount.read_size, nmount.write_size, nmount.timeout)
            if nmount.options:
                all_opts += ",%s" % nmount.options
            mount = ["%s:%s" % (nmount.provider, nmount.export_path),
                     nmount.mount_point,
                     "nfs",
                     all_opts,
                     "0",
                     "0"]
            mounts.append(mount)
        return {"mounts": mounts}

    def get_config_hostentries(self):
        command_template = "echo %s %s >> /etc/hosts"
        svc_hostentries = [command_template %
                           (hostentry.ip,
                            hostentry.hostentry)
                           for hostentry in self.item.hostentries]
        # Adding it to the bootcmd makes it run only once
        # on boot
        return {"bootcmd": svc_hostentries}


class MultipartMime(HeatSerialisable):
    resource = "OS::Heat::MultipartMime"

    def __init__(self, *args, **kwargs):
        self.parts = []
        self.resources = {}
        super(MultipartMime, self).__init__(*args, **kwargs)

    def _setup(self, server):
        if len(server.yumrepos):
            cloud_item = CloudConfig(server, yumrepos=True)
            self.update_parts_and_resources(server.yumrepos, cloud_item)

        if len(server.packages):
            cloud_item = CloudConfig(server, packages=True)
            self.update_parts_and_resources(server.packages, cloud_item)

        if len(server.network_mounts):
            cloud_item = CloudConfig(server, network_mounts=True)
            self.update_parts_and_resources(server.network_mounts, cloud_item)

        if len(server.hostentries):
            cloud_item = CloudConfig(server, hostentries=True)
            self.update_parts_and_resources(server.hostentries, cloud_item)

        self.add_property("parts", self.parts)

    def update_parts_and_resources(self, item, resource):
        name = Resource(item, 'multipart_mime').name()
        self.parts.append({'config': {'get_resource': name}})
        self.resources[name] = resource


class LBServer(Server):
    resource = "LITP::LITP::LBServer"

    def _setup(self, lb_group):
        # _setup for super is instance, not group!
        super(LBServer, self)._setup(lb_group.instance)
        for network in lb_group.instance.networks:
            self.add_property("network", Resource(
                get_stack_resource(lb_group.instance,
                                   'tenant-network',
                                   name=network.network_name)))
        # get the lb configured with vip_floating_ip_pool
        lb = [lb for lb in (lb_group.loadbalancers.
                query("tenant-lb", is_for_removal=False))
                if lb.vip_floating_ip_pool][0]
        self.add_property('lb_pool_id', Resource(lb, 'pool'))
        self.add_property("lb_member_port", lb.member_port)


class LBAlarmedServer(LBServer):
    resource = "LITP::LITP::LBAlarmedServer"

    def _setup(self, lb_group):
        super(LBAlarmedServer, self)._setup(lb_group)
        # get the lb containing the tenant-alarm
        lb = [lb for lb in (lb_group.loadbalancers.
                query("tenant-lb", is_for_removal=False))
                if lb.query("tenant-alarm", is_for_removal=False)][0]
        self.add_property('health_check_pool_id', Resource(lb, 'pool'))
        self.add_property("health_check_member_port", lb.member_port)

        alarm = lb.query("tenant-alarm", is_for_removal=False)[0]
        self.add_property('wait_timeout', alarm.wait_timeout)
        self.add_property('period', alarm.period)
        self.add_property('evaluation_periods', alarm.evaluation_periods)


class FloatingIP(HeatSerialisable):
    resource = "OS::Neutron::FloatingIP"

    def _setup(self, net):
        instance = get_ancestor(net, "tenant-instance")
        network = get_stack_resource(net,
                                     'tenant-network',
                                     name=net.network_name)
        # If the router does not exist, the network is private and it has no
        # access to the internet. This is intentional if disable_gateway is set
        # to true on the subnet
        router = self._get_router_or_none(net)
        if router is not None:
            self.add_depends(Resource(router, "interface"))
        self.add_property("floating_network", net.floating_ip_pool)
        self.add_property("port_id",
            {"get_attr": [Resource(instance).name(),
                          "addresses",
                          {"get_attr": [Resource(network).name(), "name"]},
                          0,
                          "port"]
            }
        )

    def _get_router_or_none(self, net):
        try:
            return get_stack_resource(net,
                                      'tenant-router',
                                      network_name=net.network_name)
        except IndexError:
            return None


class FloatingIPLB(HeatSerialisable):
    resource = "OS::Neutron::FloatingIP"

    def _setup(self, lb):
        router = get_stack_resource(lb,
                                    'tenant-router',
                                    network_name=lb.network_name)
        self.add_depends(Resource(router, "interface"))
        self.add_property(
            "floating_network", lb.vip_floating_ip_pool)
        self.add_property(
            "port_id",
            {"get_attr": [Resource(lb, 'pool').name(),
                          "vip",
                          "port_id"]}
            )


class SecurityGroup(HeatSerialisable):
    resource = "OS::Neutron::SecurityGroup"

    def _setup(self, security_group):
        self.add_property('name', security_group.name)
        self.add_property('description', security_group.description)
        model_rules = security_group.query('tenant-security-group-rule')
        rules = [{
            'remote_ip_prefix': rule.remote_ip_prefix,
            'protocol': rule.protocol,
            'port_range_min': rule.port_range_min,
            'port_range_max': rule.port_range_max,
            'direction': rule.direction,
            'ethertype': _get_ethertype(rule.remote_ip_prefix)
        } for rule in model_rules]
        self.add_property('rules', rules)


class Port(HeatSerialisable):
    resource = "OS::Neutron::Port"

    def _setup(self, instance, **kwargs):
        security_groups = [Resource(security_group)
            for security_group
            in instance.security_groups]

        self.add_property('security_groups', security_groups)

        network = get_stack_resource(instance, 'tenant-network',
            name=kwargs['network'].network_name)
        # only one subnet supported
        subnet = [subnet for subnet in network.subnets][0]

        self.add_property('network_id', Resource(network))
        self.add_property('fixed_ips', [{'subnet_id': Resource(subnet)}])


def _get_ethertype(cidr):
    if ":" in cidr:
        return 'IPv6'
    return 'IPv4'


def _validate_unique_packages(context):
    errors = []

    instances = context.query('tenant-instance')
    seen = defaultdict(list)
    for instance in instances:
        for package in instance.packages:
            seen[package.name].append(package.get_vpath())
    for name, paths in seen.iteritems():
        if len(paths) > 1:
            for path in paths:
                errors.append(
                    ValidationError(path, name, "Duplicate package"))

    return errors


def _validate_unique_yumrepos(context):
    errors = []
    instances = context.query('tenant-instance')
    seen = defaultdict(list)
    for instance in instances:
        for repo in instance.yumrepos:
            seen[repo.name].append(repo.get_vpath())
    for name, paths in seen.iteritems():
        if len(paths) > 1:
            for path in paths:
                errors.append(ValidationError(path, name,
                                              "Duplicate repo name"))

    return errors


@patch_helper_callback
class Heat(object):

    """
    LITP openstack plugin
    """

    def __init__(self, plugin):
        self.plugin = plugin

    #pylint: disable=R0201
    def validate_model(self, context):
        """
        This method can be used to validate the model

        .. warning::
        Please provide a summary of the model validation performed by
        openstack here
        """
        errors = []
        errors.extend(_validate_unique_packages(context))
        errors.extend(_validate_unique_yumrepos(context))
        return errors

    def _get_task_description(self, action, name):
        if action == Action.CREATE:
            return 'Create stack "{0}"'.format(name)
        elif action == Action.REMOVE:
            return 'Remove stack "{0}"'.format(name)
        elif action == Action.UPDATE:
            return 'Update stack "{0}"'.format(name)
        else:
            raise ActionException("Action type unkown: {0}".format(action))

    # pylint: disable=E1101
    def create_configuration(self, context):
        tasks = []
        for stack in _get_stacks(context):
            action = None
            if stack.stack.is_initial():
                action = Action.CREATE
            elif stack.stack.is_for_removal():
                action = Action.REMOVE
            elif has_changed_dependencies(stack.stack):
                action = Action.UPDATE
            if action:
                name = stack.stack.item_id
                task = self.create_callback_task(
                        self.plugin,
                        stack.stack,
                        self._get_task_description(action, name),
                        self.callback,
                        name=name,
                        stack_vpath=stack.stack.get_vpath(),
                        action=action,
                        tenant_name=get_tenant(stack.stack).name,
                        provider_vpath=stack.get_provider().get_vpath(),
                        user_vpath=stack.get_user().get_vpath())
                task.model_items.add(stack.get_user())
                for volume in stack.get_volumes():
                    task.model_items.add(volume)
                tasks.append(task)
                if action != Action.REMOVE:
                    template = stack.create_template()
                    stack.template_to_file(template)

        LOG.trace.debug('Heat tasks: %s', tasks)
        return tasks

    @staticmethod
    def callback(api, name, stack_vpath, action, tenant_name,
                 provider_vpath, user_vpath):
        stack = Stack(api.query_by_vpath(stack_vpath))
        if action != Action.REMOVE:
            template = stack.create_template()

        provider = api.query_by_vpath(provider_vpath)
        user = api.query_by_vpath(user_vpath)

        keystone = KeystoneClient(username=user.name,
                                  password=api.get_escaped_password(
                                      user.password_key, user.name),
                                  tenant_name=tenant_name,
                                  auth_url=provider.auth_url)

        heat = HeatClient(
            endpoint=keystone.service_catalog.url_for(
                service_type='orchestration', endpoint_type='publicURL'),
            token=keystone.auth_token)

        if action == Action.CREATE:
            LOG.trace.debug('Calling Heat with template: %s',
                            yaml.load(template))
            try:
                heat.stacks.create(stack_name=name,
                                   template=template,
                                   environment=ENVIRONMENT,
                                   files=FILES)
            except HTTPConflict:
                # stack already exists, try to update
                LOG.trace.info('Stack "{0}" already exists. '
                    'Trying to update the stack.'.format(name))
                stack_id = _get_stack_id(heat, name)
                heat.stacks.update(stack_id,
                                   template=template,
                                   environment=ENVIRONMENT,
                                   files=FILES)
                status = _wait_for_stack(api, heat, name, Action.UPDATE,
                                         return_on_fail=True)
                # update successful, nothing else needed
                if status == 'COMPLETE':
                    return
                LOG.trace.info('Failed to update stack "{0}". '
                    'Trying to remove and create the stack again.'
                    .format(name))
                heat.stacks.delete(stack_id)
                status = _wait_for_stack(api, heat, name, Action.REMOVE,
                    target_status=None, return_on_fail=True)
                # if we have status, we have a stack and removal failed
                if status:
                    raise CallbackExecutionException('Failed to remove '
                        'stack "0". Stack is in state "{1}".'
                        .format(name, status))
                heat.stacks.create(stack_name=name,
                                   template=template,
                                   environment=ENVIRONMENT,
                                   files=FILES)
            _wait_for_stack(api, heat, name, action)
            LOG.trace.debug('Stack "%s" created.', name)

        if action == Action.REMOVE:
            stack_id = _get_stack_id(heat, name)
            if stack_id:
                heat.stacks.delete(stack_id)
                _wait_for_stack(api, heat, name, action, target_status=None)
            else:
                LOG.trace.debug('Stack "%s" not found. Skipping...', name)

        if action == Action.UPDATE:
            LOG.trace.debug('Calling Heat with template: %s',
                            yaml.load(template))
            heat.stacks.update(_get_stack_id(heat, name),
                               template=template,
                               environment=ENVIRONMENT,
                               files=FILES)
            _wait_for_stack(api, heat, name, action)
            LOG.trace.debug('Stack "%s" updated.', name)


def _get_stack_log_message(stack_name, action, start=False):
    if action == Action.CREATE:
        action_word = 'creation'
    elif action == Action.UPDATE:
        action_word = 'update'
    elif action == Action.REMOVE:
        action_word = 'removal'
    else:
        raise ActionException("Action type unkown: {0}".format(action))
    stage = 'started' if start else 'in progress'
    return 'Stack "{0}" {1} {2}.'.format(stack_name, action_word, stage)


def _wait_for_stack(callback_api, heat_client, stack_name, action,
                    target_status='COMPLETE', timeout=MAX_WAIT_SECONDS,
                    return_on_fail=False):
    LOG.trace.info(_get_stack_log_message(stack_name, action, start=True))
    passed = 0
    t1 = time()
    minute = 0
    while callback_api.is_running():
        stack = _get_stack(heat_client, stack_name)
        if not stack and not target_status:
            # NOTE(xigomil) We are removing the stack, `target_status` is None,
            # and we can not find one, so we should stop waiting...
            LOG.trace.info('Stack "%s" was removed.', stack_name)
            return None
        else:
            status = stack.status

        if _in_status(stack, 'FAILED'):
            fail_message = ('Stack Failed. Stack "{0}" is in state "{1}". '
                'Reason: {2}'.format(stack_name, status,
                    stack.stack_status_reason))
            if return_on_fail:
                LOG.trace.info(fail_message)
                return status
            raise CallbackExecutionException(fail_message)
        if _in_status(stack, target_status):
            LOG.trace.info('Stack "%s" in state "%s".', stack_name, status)
            return status
        passed = time() - t1
        if passed // 60 != minute:
            minute += 1
            LOG.trace.info(_get_stack_log_message(stack_name, action))
        LOG.trace.debug('Stack "%s" update in progress. Passed %f '
                        'second(s), timeout at %f second(s).',
                        stack, passed, timeout)

        if passed > timeout:
            raise CallbackExecutionException(
                'Callback timeout. Stack "{0}" is in state "{1}"'
                .format(stack_name, status))

        sleep(1)
    else:
        # pylint: disable=W0120
        raise PlanStoppedException(PLAN_STOPPED_MESSAGE)

    return status


def _in_status(stack, status):
    return status == getattr(stack, 'status', None)


def _get_stack(heat_client, stack_name):
    stack = None
    try:
        stack = list(heat_client.stacks.list(name=stack_name))[0]
    except IndexError:
        LOG.trace.debug('Stack not found: %s', stack)
    else:
        LOG.trace.debug('Stack found: %s', stack)

    return stack


def _get_stack_id(heat, name):
    return getattr(_get_stack(heat, name), 'id', None)


def _get_keypairs(stack):
    resources = {}
    keypairs = stack.query("tenant-keypair")
    for keypair in keypairs:
        LOG.trace.debug('Parsing key "%s"', keypair)
        resources[Resource(keypair, 'key')] = Keypair(keypair)
    return resources


def _get_networks(stack):
    resources = {}
    for network in stack.networks:
        # The decision of using item_id instead of names hits in this point:
        # Original plugin uses .name to refer to networks, heat's doesn't.
        resources[Resource(network)] = Network(network)
        for subnet in network.subnets:
            sub = Subnet(subnet)
            sub.add_property("network_id", Resource(network))
            resources[Resource(subnet)] = sub
    return resources


def _get_routers(stack):
    resources = {}
    for router in stack.routers:
        resources[Resource(router)] = Router(router)
        resources[Resource(router, "interface")] = RouterInterface(router)
    return resources


def _get_servers(stack):
    resources = {}
    for instance in stack.instances:
        server = Server(instance)
        for net in instance.networks:
            server.add_depends(
                Resource(get_stack_resource(instance,
                                            'tenant-network-subnet',
                                            name=net.network_name)))
            if net.floating_ip_pool:
                fip = FloatingIP(net)
                resources[Resource(instance, 'fip')] = fip
        # Filter volumes without names so they can be created by heat
        for volume in [vol for vol in instance.volumes if not vol.name]:
            resources[Resource(volume)] = Volume(volume)

        multipart_mime = MultipartMime(instance)
        resources.update(multipart_mime.resources)
        resources[Resource(instance, 'multipart_mime')] = multipart_mime

        resources[Resource(instance)] = server
    return resources


def _get_monitor_names(lb):
    return lb.monitors.split(",")


def _get_lb_monitors(stack):
    """Only adds the monitors to the stack if they are
    referrenced in any of the lb.monitors children.
    monitors can be reused by multiple lb-groups
    """
    monitors_in_lbs = set()
    for lb_group in stack.instance_lb_groups:
        for lb in lb_group.loadbalancers:
            monitors_in_lbs.update(_get_monitor_names(lb))

    resources = {}
    for monitor in stack.lb_monitors:
        if monitor.name in monitors_in_lbs:
            resources[Resource(monitor)] = HealthMonitor(monitor)

    return resources


def _add_network_deps(group, asg):
    for net in group.instance.networks:
        asg.add_depends(
            Resource(
                get_stack_resource(group,
                                   'tenant-network-subnet',
                                   name=net.network_name)))
    return asg


def _get_lb_groups(stack):
    resources = {}
    for lb_group in stack.instance_lb_groups:
        asg = AutoScaleLBGroup(lb_group)
        asg = _add_network_deps(lb_group, asg)
        resources[Resource(lb_group)] = asg

        multipart_mime = MultipartMime(lb_group.instance)
        resources.update(multipart_mime.resources)
        resources[Resource(lb_group.instance,
                           'multipart_mime')] = multipart_mime

        for lb in lb_group.loadbalancers:
            loadbalancer = LoadBalancer(lb)
            resources[Resource(lb)] = loadbalancer

            pool = Pool(lb_group, lb)
            resources[Resource(lb, "pool")] = pool

            if lb.vip_floating_ip_pool:
                fip = FloatingIPLB(lb)
                resources[Resource(lb, "fip")] = fip

    return resources


def _get_stacks(api):
    stacks = []
    for tenant in api.query('cloud-tenant'):
        for tenant_stack in tenant.stacks:
            stacks.append(Stack(tenant_stack))
    return stacks


def _find_dependent_resource(item, name):
    stack = get_stack(item)
    instances = stack.instances.query('tenant-instance', instance_name=name)
    if instances:
        return Resource(instances[0])
    groups = stack.instance_lb_groups.query('tenant-instance-lb-group',
                                            group_name=name)
    if groups:
        return Resource(groups[0])


def _get_security_groups(stack):
    resources = {}
    for security_group in stack.security_groups:
        resources[Resource(security_group)] = SecurityGroup(security_group)
    return resources


def _get_ports(stack):
    resources = {}
    # This covers the instances in the instance groups as well
    instances = stack.query('tenant-instance', is_for_removal=False)
    for instance in instances:
        if instance.security_group_names:
            for network in instance.networks:
                resources[Resource(instance, 'port')] = Port(instance,
                                                             network=network)
    return resources
