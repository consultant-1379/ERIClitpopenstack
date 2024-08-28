##############################################################################
# COPYRIGHT Ericsson AB 2014
#
# The copyright to the computer program(s) herein is the property of
# Ericsson AB. The programs may be used and/or copied only with written
# permission from Ericsson AB. or in accordance with the terms and
# conditions stipulated in the agreement/contract under which the
# program(s) have been supplied.
##############################################################################

import hashlib

from collections import namedtuple, defaultdict
from litp.core.plugin import Plugin
from litp.core.execution_manager import CallbackTask
from litp.core.validators import ValidationError
from litp.core.litp_logging import LitpLogger
from .exceptions import OSYumRepoException
from .heat import Heat
from .osapi import Image, Volume
from .utils import (patch_plugin_callback, get_tenant,
                    repoquery)


LOG = LitpLogger()


@patch_plugin_callback
class OpenStackPlugin(Plugin):
    """
    LITP openstack plugin
    """

    def validate_model(self, api):
        """
        This method can be used to validate the model ...

        .. warning::
          Please provide a summary of the model validation performed by
          openstack here
        """
        errors = []

        errors.extend(self._check_instance_lb_group_has_instance(api))
        errors.extend(self._check_instance_lb_group_alarms(api))
        errors.extend(self._check_instance_lb_group_two_lbs_has_alarm(api))
        errors.extend(self._check_instance_lb_group_floating_ip(api))
        errors.extend(self._check_instance_lb_group_not_both_alarm_floating_ip(
            api))

        errors.extend(self._on_remove_router(api))
        errors.extend(self._on_remove_network(api))

        errors.extend(self._on_instance_create(api))
        errors.extend(self._on_instance_create_lb_group(api))

        errors.extend(self._on_cloud_load_balancer_create_check_network(api))
        errors.extend(self._on_cloud_load_balancer_create_check_monitor(api))

        errors.extend(self._on_create_subnet_without_gateway_check_no_router(
            api))
        errors.extend(self._on_router_create_check_network(api))

        errors.extend(self._on_cloud_image_create_check_unique_name(api))

        errors.extend(
            self._on_security_group_create_check_duplicate_names_per_tenant(
                api))
        errors.extend(self._on_security_group_create_check_default_name(api))
        errors.extend(
            self._on_security_group_rule_create_check_port_range(api))
        errors.extend(
            self._on_tenant_instances_check_security_groups_unique(api))
        errors.extend(
            self._on_tenant_instances_check_security_groups_exist(api))
        errors.extend(
            self._on_tenant_instances_check_default_security_group(api))

        errors.extend(self._check_instance_volume_exist(api))
        errors.extend(self._check_instance_volume_has_size(api))
        errors.extend(self._check_instance_volume_has_device_name(api))
        errors.extend(self._check_instance_volume_device_name_uniqueness(api))
        errors.extend(self._check_tenant_volume_have_name_and_size(api))
        errors.extend(self._check_user_for_stack_exists(api))
        errors.extend(self._check_if_provider_is_in_use(api))

        return errors

    def _check_instance_lb_group_has_instance(self, api):
        errors = []
        igroups = api.query('tenant-instance-lb-group', is_for_removal=False)
        for igroup in igroups:
            if not igroup.instance:
                message_error = ('The property "instance" of the instance '
                                 'group "{0}" is not defined'.
                                 format(igroup.group_name))
                errors.append(ValidationError(
                    igroup.get_vpath(),
                    property_name='instance',
                    error_message=message_error))
        return errors

    def _check_instance_lb_group_alarms(self, api):
        errors = []
        igroups = api.query('tenant-instance-lb-group', is_for_removal=False)
        for igroup in igroups:
            alarms = igroup.query('tenant-alarm', is_for_removal=False)
            if len(alarms) > 1:
                message_error = ('Only one "tenant-alarm" can be created for '
                                 'the group "{0}".'.
                                 format(igroup.group_name))
                errors.append(ValidationError(
                    igroup.get_vpath(),
                    error_message=message_error))
        return errors

    def _check_instance_lb_group_two_lbs_has_alarm(self, api):
        errors = []
        igroups = api.query('tenant-instance-lb-group', is_for_removal=False)
        for igroup in igroups:
            lbs = igroup.query('tenant-lb', is_for_removal=False)
            if len(lbs) == 2:
                alarms = igroup.query('tenant-alarm', is_for_removal=False)
                if not alarms:
                    message_error = ('One of the two "tenant-lb" from group '
                                     '"{0}" must have a "tenant-alarm".'.
                                     format(igroup.group_name))
                    errors.append(ValidationError(
                        igroup.get_vpath(),
                        error_message=message_error))
        return errors

    def _check_instance_lb_group_floating_ip(self, api):
        errors = []
        igroups = api.query('tenant-instance-lb-group', is_for_removal=False)
        for igroup in igroups:
            lbs = igroup.query('tenant-lb', is_for_removal=False)
            if lbs:
                floating_ip_lb = [lb for lb in lbs
                                  if lb.vip_floating_ip_pool]
                if len(floating_ip_lb) != 1:
                    message_error = ('Exactly one "tenant-lb" from group '
                                     '"{0}" must have the property '
                                     '"vip_floating_ip_pool" set.'.
                                     format(igroup.group_name))
                    errors.append(ValidationError(
                        igroup.get_vpath(),
                        error_message=message_error))
        return errors

    def _check_instance_lb_group_not_both_alarm_floating_ip(self, api):
        errors = []
        igroups = api.query('tenant-instance-lb-group', is_for_removal=False)
        for igroup in igroups:
            for lb in igroup.query('tenant-lb', is_for_removal=False):
                alarms = lb.query('tenant-alarm', is_for_removal=False)
                if lb.vip_floating_ip_pool and alarms:
                    message_error = ('The "tenant-lb" "{0}" cannot have both '
                                     'a "tenant-alarm" and the property '
                                     '"vip_floating_ip_pool" set '
                                     'at the same time.'.
                                     format(lb.name))
                    errors.append(ValidationError(
                        lb.get_vpath(),
                        error_message=message_error))
        return errors

    def _on_tenant_instances_check_security_groups_unique(self, api):
        errors = []
        instances = api.query('tenant-instance', is_for_removal=False)
        for instance in instances:
            if not instance.security_group_names:
                continue
            attached_security_groups = instance.security_group_names.split(',')
            duplicates = set([security_group for security_group
                in attached_security_groups if attached_security_groups.count(
                security_group) > 1])
            if duplicates:
                if len(duplicates) == 1:
                    message_error = ('The security group "{0}" is repeated in '
                        'the instance "{1}". It can only be used once per '
                        'instance.'.format(''.join(duplicates), instance.name))
                elif len(duplicates) > 1:
                    message_error = ('The security groups "{0}" are repeated '
                        'in the instance "{1}". They can only be used once '
                        'per instance.'.format(', '.join(duplicates),
                            instance.name))
                errors.append(ValidationError(
                    instance.get_vpath(),
                    property_name='security_group_names',
                    error_message=message_error))
        return errors

    def _on_tenant_instances_check_security_groups_exist(self, api):
        errors = []
        instances = api.query('tenant-instance', is_for_removal=False)
        for instance in instances:
            if not instance.security_group_names:
                continue
            attached_security_groups = frozenset(
                instance.security_group_names.split(','))
            retrieved_security_groups = frozenset([security_group.name
                for security_group in instance.security_groups])
            diff = list(attached_security_groups.difference(
                retrieved_security_groups))
            if diff:
                if len(diff) == 1:
                    message_error = ('The security group "{0}" is not defined.'
                        .format(diff[0]))
                elif len(diff) > 1:
                    message_error = ('The security groups "{0}" are not '
                        'defined.'.format(', '.join(diff)))
                errors.append(ValidationError(
                    instance.get_vpath(),
                    property_name='security_group_names',
                    error_message=message_error))
        return errors

    def _on_tenant_instances_check_default_security_group(self, api):
        errors = []
        instances = api.query('tenant-instance', is_for_removal=False)
        for instance in instances:
            if not instance.security_group_names:
                continue
            attached_security_groups = set(
                instance.security_group_names.split(','))
            if 'default' in attached_security_groups:
                message_error = ('The security group "default" must not be '
                        'used in the instance security group names.')
                errors.append(ValidationError(
                    instance.get_vpath(),
                    property_name='security_group_names',
                    error_message=message_error))
        return errors

    def _on_security_group_create_check_duplicate_names_per_tenant(self, api):
        errors = set()
        tenants = api.query('tenant-stack')
        for tenant in tenants:
            appearances = defaultdict(int)
            security_groups = tenant.query('tenant-security-group',
                is_initial=True)
            for security_group in security_groups:
                appearances[security_group.name] += 1
                if appearances[security_group.name] > 1:
                    errors.add(ValidationError(
                        item_path=tenant.get_vpath(),
                        error_message='The security group "{name}" is '
                                      'duplicated within the tenant stack '
                                      '"{tenant}". All security group names '
                                      'associated with tenant must be '
                                      'unique.'.format(
                                          name=security_group.name,
                                          tenant=tenant.item_id)
                    ))
        return list(errors)

    def _on_security_group_create_check_default_name(self, api):
        errors = []
        tenants = api.query('tenant-stack')
        for tenant in tenants:
            security_groups = tenant.query('tenant-security-group',
                is_initial=True, name='default')
            for security_group in security_groups:
                errors.append(ValidationError(
                    item_path=security_group.get_vpath(),
                    error_message='The security group named "default" must '
                                  'not be used.'
                ))
        return errors

    def _on_security_group_rule_create_check_port_range(self, api):
        errors = []
        rules = api.query('tenant-security-group-rule', is_initial=True)
        for rule in rules:
            if int(rule.port_range_min) > int(rule.port_range_max):
                message_error = ('Security group rule "{0}" has an invalid '
                                 'port range. Minimum port must be smaller or '
                                 'equal to maximum port.'.format(rule.item_id))
                errors.append(ValidationError(rule.get_vpath(),
                                              error_message=message_error))
        return errors

    def _check_instance_volume_device_name_uniqueness(self, api):

        errors = []
        instances = api.query('tenant-instance', is_initial=True)
        for instance in instances:
            instance_volumes = instance.query('tenant-volume', is_initial=True)
            instance_volumes_device_names = []
            for volume in instance_volumes:
                if volume.device_name in instance_volumes_device_names:
                    message_error = ('Volume cannot be attached. '
                                     'Another Volume is already attached '
                                     'to "%s" device.'
                                     % volume.device_name)
                    errors.append(ValidationError
                                 (volume.get_vpath(),
                                  property_name="device_name",
                                  error_message=message_error))
                else:
                    instance_volumes_device_names.append(volume.device_name)

        return errors

    def _check_instance_volume_has_device_name(self, api):

        errors = []
        instances = api.query('tenant-instance', is_initial=True)
        for instance in instances:
            instance_volumes = instance.query('tenant-volume', is_initial=True)
            for volume in instance_volumes:
                if not volume.device_name:
                    message_error = ('Volume cannot be created '
                                     'without specifying '
                                     'device_name property.')
                    errors.append(ValidationError
                                 (volume.get_vpath(),
                                  property_name="device_name",
                                  error_message=message_error))
        return errors

    def _check_instance_volume_has_size(self, api):

        errors = []
        instances = api.query('tenant-instance', is_initial=True)
        for instance in instances:
            instance_volumes = instance.query('tenant-volume')
            for volume in instance_volumes:
                if not volume.name:
                    if not volume.size:
                        message_error = ('Volume cannot be attached, '
                                         'without specifying size property.')
                        errors.append(ValidationError
                                     (volume.get_vpath(),
                                      property_name="size",
                                      error_message=message_error))

        return errors

    def _check_tenant_volume_have_name_and_size(self, api):

        errors = []
        all_volumes_defined = self._get_all_volumes_defined(api)
        only_volumes_tenant = self._get_only_volumes_tenant(
                                   all_volumes_defined)

        for volume in only_volumes_tenant:
            if not volume.name:
                message_error = ('Volume cannot be created, '
                                 'the name property must be present.')
                errors.append(ValidationError(volume.get_vpath(),
                                              property_name="name",
                                              error_message=message_error))
            if not volume.size:
                message_error = ('Volume cannot be created, '
                                 'the size property must be present.')
                errors.append(ValidationError
                             (volume.get_vpath(),
                              property_name="size",
                              error_message=message_error))

        return errors

    def _check_instance_volume_exist(self, api):

        errors = []
        all_volumes_defined = self._get_all_volumes_defined(api)
        only_volumes_tenant = self._get_only_volumes_tenant(
                                    all_volumes_defined)
        only_volumes_tenant_names = [v.name for v in only_volumes_tenant]
        instances = api.query('tenant-instance', is_initial=True)

        for instance in instances:
            instance_volumes = instance.query('tenant-volume', is_initial=True)
            for volume in instance_volumes:
                if volume.name:
                    if volume.name not in only_volumes_tenant_names:
                        message_error = ('Volume cannot be attached, '
                                         'a tenant-volume with name "%s"'
                                         ' must exist.'
                                         % volume.name)
                        errors.append(ValidationError
                                     (volume.get_vpath(),
                                      property_name="name",
                                      error_message=message_error))

        return errors

    def _check_user_for_stack_exists(self, api):
        errors = []
        for tenant in api.query('cloud-tenant'):
            if not len(tenant.users):
                message_error = ("User must be specified for "
                        "the tenant \"%s\"." % tenant.name)
                errors.append(ValidationError
                        (tenant.get_vpath(),
                            property_name="user",
                            error_message=message_error))
        return errors

    def _check_if_provider_is_in_use(self, api):
        errors = []
        for provider in api.query('openstack-provider', is_for_removal=True):
            for cluster in api.query('tenant-cluster',
                                     provider_name=provider.name,
                                     is_for_removal=False):
                message_error = ('Provider: "{0}" is in use on '
                                 'cluster "{1}",'
                                 ' cannot be removed'
                                 .format(provider.name,
                                         cluster.get_vpath()))
                errors.append(ValidationError(
                        provider.get_vpath(),
                        property_name="name",
                        error_message=message_error))
        return errors

    def _get_all_volumes_defined(self, api):
        return api.query('tenant-volume', is_initial=True)

    def _get_only_volumes_tenant(self, volumes):

        volumes_tenant = []
        for vol in volumes:
            if 'stacks' not in vol.get_vpath():
                volumes_tenant.append(vol)
        return volumes_tenant

    def _on_cloud_image_create_check_unique_name(self, api):

        errors = []
        cloudimages = api.query('tenant-image', is_initial=True)
        names_image = [i.name for i in cloudimages]
        already_checked = []
        #iteration on cloud images and not on names_image
        #because in this way
        # i can pass cloud image to ValidationError
        for image in cloudimages:
            if (names_image.count(image.name) > 1 and
               (image.name not in already_checked)):
                already_checked.append(image.name)
                message_error = ('Image cannot be created, '
                                 'the name "%s" is already present'
                                 % (image.name))
                errors.append(ValidationError(image.get_vpath(),
                                              property_name="name",
                                              error_message=message_error))
        return errors

    def _on_instance_create_check_image_name(self, api):

        errors = []
        cloudimages = api.query('tenant-image', is_for_removal=False)
        names_image = [i.name for i in cloudimages]

        instances = api.query('tenant-instance', is_initial=True)

        for instance in instances:
            if not instance.image_name:
                continue
            if instance.image_name not in names_image:
                errors.append(ValidationError(
                              instance.get_vpath(),
                              error_message=('Instance '
                                             'cannot be created, '
                                             'image "%s" must be present'
                                             % (instance.image_name))))
        return errors

    def _on_create_subnet_without_gateway_check_no_router(self, api):
        errors = []
        subnets = api.query('tenant-network-subnet', is_initial=True,
            disable_gateway="true")
        routers = api.query('tenant-router', is_for_removal=False)
        if routers and subnets:
            router_network_names = [r.network_name for r in routers]
            for subnet in subnets:
                network_name = subnet.get_parent().get_parent().name
                if network_name in router_network_names:
                    message_error = ('Subnet "{0}" with this configuration '
                                     'must not have a router'.format(
                                      subnet.name))
                    errors.append(ValidationError(subnet.get_vpath(),
                                                  error_message=message_error))
        return errors

    def _on_router_create_check_network(self, api):

        errors = []

        networks = api.query('tenant-network', is_for_removal=False)
        net_names = [n.name for n in networks]

        routers = api.query('tenant-router', is_initial=True)

        for router in routers:
            #if don't specific a network you can't create a router.
            #litp create fails.
            if not router.network_name:
                message_error = ('Router "%s" has to attach a network'
                                 % router.name)
                errors.append(ValidationError(router.get_vpath(),
                                              property_name='network_name',
                                              error_message=message_error))
                continue
            if router.network_name not in net_names:
                message_error = ('Router "%s" cannot be created, '
                                 'network "%s" must be present'
                                 % (router.name, router.network_name))
                errors.append(ValidationError(router.get_vpath(),
                                              error_message=message_error))
        return errors

    def _on_cloud_load_balancer_create_check_network(self, api):
        errors = []
        #take tenant's networks defined at start
        networks = api.query('tenant-network', is_for_removal=False)
        #save network names of tenant in a vector
        net_names = [n.name for n in networks]
        cloudlbs = api.query('tenant-lb', is_initial=True)

        for cloudlb in cloudlbs:
            if not cloudlb.network_name:
                continue
            #there is only one network for a cloud load balancer
            if cloudlb.network_name not in net_names:
                message_error = ('Cloud Load Balancer "%s" '
                                 'cannot be created, '
                                 'network "%s" must be present'
                                 % (cloudlb.name, cloudlb.network_name))
                errors.append(ValidationError(cloudlb.get_vpath(),
                                              property_name="network_name",
                                              error_message=message_error))
        return errors

    def _on_cloud_load_balancer_create_check_monitor(self, api):
        errors = []
        monitors = api.query('tenant-lb-monitor', is_for_removal=False)
        monitors_name = [m.name for m in monitors]
        cloudlbs = api.query('tenant-lb', is_initial=True)

        for cloudlb in cloudlbs:
            if not cloudlb.monitors:
                continue
            for lb_monitor_name in cloudlb.monitors.split(","):
                if lb_monitor_name not in monitors_name:
                    errors.append(ValidationError(
                        cloudlb.get_vpath(),
                        property_name="monitors",
                        error_message=('Cloud Load Balancer "%s" '
                                       'cannot be created, '
                                       'monitor "%s" must be present'
                                       % (cloudlb.name, lb_monitor_name))))
        return errors

    def _on_instance_create(self, api):
        errors = []

        networks = api.query('tenant-network', is_for_removal=False)
        net_names = [n.name for n in networks]

        instances = api.query('tenant-instance', is_initial=True)

        for instance in instances:
            # validate modeled networks
            if not instance.networks:
                continue
            for i_network in instance.networks:
                if i_network.network_name not in net_names:
                    errors.append(ValidationError(
                        instance.get_vpath(),
                        error_message=('Instance cannot be created, '
                                       'network "%s" must be present'
                                       % (i_network.network_name))))

        return errors

    def _on_instance_create_lb_group(self, api):
        errors = []

        networks = api.query('tenant-network', is_for_removal=False,
                             is_removed=False)
        net_names = [n.name for n in networks]

        instance_groups = api.query('tenant-instance-lb-group',
                                    is_initial=True)

        for igroup in instance_groups:
            if not igroup.instance or not igroup.instance.networks:
                continue
            for i_network in igroup.instance.networks:
                if i_network.network_name not in net_names:
                    errors.append(ValidationError(
                        igroup.get_vpath(),
                        error_message=('Instance cannot be created, '
                                       'network "%s" must be present'
                                       % (i_network.network_name))
                    ))

        return errors

    def _on_remove_network(self, api):
        errors = []

        networks = api.query('tenant-network', is_for_removal=True)

        for network in networks:
            # instances must be removed first
            for instance in api.query('tenant-instance',
                                      is_for_removal=False,
                                      network=network.name):
                errors.append(ValidationError(
                    instance.get_vpath(),
                    error_message=('Instance "%s" must be removed, '
                                   'before removing the network "%s".' %
                                   (instance.instance_name, network.name))
                ))

            # instance groups must be removed first
            for igroup in api.query('tenant-instance-lb-group',
                                    is_for_removal=False,
                                    network=network.name):
                errors.append(ValidationError(
                    igroup.get_vpath(),
                    error_message=('Instance "%s" must be removed, '
                                   'before removing the network "%s".' %
                                   (igroup.group_name, network.name))
                ))

            for router in api.query('tenant-router',
                                    is_for_removal=False,
                                    network_name=network.name):
                errors.append(ValidationError(
                    router.get_vpath(),
                    error_message=('Router "%s" must be removed, '
                                   'before removing the network "%s".' %
                                   (router.name, network.name))
                ))

        return errors

    def _on_remove_router(self, api):
        errors = []
        routers = api.query('tenant-router', is_for_removal=True)
        networks = api.query('tenant-network', is_for_removal=False)

        for router in routers:
            # networks attached to router must be marked for removal
            for net in networks:
                if router.network_name == net.name:
                    errors.append(ValidationError(
                        net.get_vpath(),
                        error_message=('Network "%s" must be removed, '
                                       'before this router "%s" can be '
                                       'removed' % (net.name, router.name))
                    ))
        return errors

    @staticmethod
    def _get_provider(api, cloud_cluster):
        for provider in api.query('openstack-provider'):
            if provider.name == cloud_cluster.provider_name:
                return provider

    @staticmethod
    def _build_provider(cb_api, provider, user):
        Provider = namedtuple('Provider',
            ['auth_url', 'tenant', 'username', 'password'])

        auth = Provider(provider.auth_url, get_tenant(user).name, user.name,
            cb_api.get_escaped_password(user.password_key, user.name))

        return auth

    def create_configuration(self, api):
        """
        Plugin to manage cloud based deployment in pre-provisioned OpenStack
        environment.
        Create and remove ``tenant-image``.
        Create and remove Heat-based stacks via ``tenant-stack`` item.


        *Example CLI for this plugin:*

        .. code-block:: bash

            litp create -p /software/items/vm_image1 -t tenant-image -o \
name='cirros32' path='/tmp/cirros-0.3.2-x86_64-disk.img'

            litp create -p /infrastructure/system_providers/openstack1 \
-t openstack-provider -o name='openstack1' \
auth_url='http://172.16.0.2:5000/v2.0/'

            litp create -p /deployments/site1 -t deployment
            litp create -p /deployments/site1/clusters/cloud1 \
-t tenant-cluster -o provider_name='openstack1'
            litp create -p /deployments/site1/clusters/cloud1/instances/ \
instance1 -t tenant-instance -o instance_name="instance1" flavor="m1.tiny" \
image_name='cirros32' network='litp' key_name="litp"
        """
        create_tasks = []
        removal_tasks = []

        for cc in api.query('tenant-cluster'):
            for tenant in cc.tenants:

                provider = self._get_provider(api, cc)
                try:
                    # NOTE(xigomil) Only 1 user supported per tenant
                    user = [u for u in tenant.users][0]
                    LOG.trace.debug('Auth as user: "%s"' % user.name)
                except KeyError:
                    err_msg = "User not defined. Tasks are not generated."
                    LOG.event.error(err_msg)
                    raise Exception(err_msg)

                # Manage images: remove and create
                removal_tasks.extend(self._images_tasks_remove(
                    api, provider, user, tenant))
                create_tasks.extend(self._images_tasks_create(
                    api, provider, user, tenant))
                removal_tasks.extend(self._volume_tasks_remove(
                    api, provider, user, tenant))
                create_tasks.extend(self._volume_tasks_create(
                    api, provider, user, tenant))

        tasks = create_tasks
        tasks.extend(Heat(self).create_configuration(api))
        tasks.extend(removal_tasks)

        # Removal tasks run after heat tasks to ensure stacks are deconfigured
        # before removing attached volumes

        LOG.trace.debug('TASKS: %s' % tasks)
        return tasks

    def _images_tasks_remove(self, api, provider, user, tenant):
        """ From the tenant, gets its instances,
            checks if the image belonging to an instance is
            defined in the model.
            If the image is found then the plugin tries to remove it.
            If not, it will do nothing hoping that it has manually
            been uploaded to the openstack deployment
        """
        instances = tenant.query('tenant-instance')
        images_to_remove = []
        for instance in instances:
            images_to_remove.extend(api.query('tenant-image',
                                              name=instance.image_name,
                                              is_for_removal=True))

        tasks = []
        for image in images_to_remove:
            tasks.append(self._image_callbacktask(provider, user,
                                                  image, 'remove'))
            LOG.trace.info('Added task to remove image "%s"' % image.name)

        return tasks

    # TODO(xluiguz): _image_tasks_update is missing (needs validation that not
    # other images are using the updating image) If glance client allows
    # updates, happy days. if not, then remove it from the deployment and
    # create a new one.
    def _images_tasks_create(self, api, provider, user, tenant):
        """ From the tenant, gets its instances,
            checks if the image belonging to an instance is
            defined in the model.
            If the image is found then the plugin tries to create it.
            If not, it will do nothing hoping that it has manually
            been uploaded to the openstack deployments
        """
        instances = tenant.query('tenant-instance')
        images_to_create = []
        for instance in instances:
            images_to_create.extend(api.query('tenant-image',
                                              name=instance.image_name,
                                              is_initial=True))
            # DELETEME(xluiguz): once the update image is taken care of.
            images_to_create.extend(api.query('tenant-image',
                                              name=instance.image_name,
                                              is_updated=True))
        tasks = []
        for image in images_to_create:
            tasks.append(self._image_callbacktask(provider, user,
                                                  image, 'create'))
            LOG.trace.info('Added task to create image "%s"' % image.name)

        return tasks

    def _image_callbacktask(self, provider, user, image, action):
        provider_vpath = provider.get_vpath()
        user_vpath = user.get_vpath()
        image_vpath = image.get_vpath()

        cb_task = CallbackTask(
            image,
            '{1} Openstack Image "{0}"'.format(
                image.name, action.capitalize()),
            self._image_action,
            provider_vpath, user_vpath, image_vpath, action)
        LOG.event.info('Created task: %s' % (cb_task))

        return cb_task

    def _image_action(self, api, provider_vpath, user_vpath, image_vpath,
                      action):
        provider = api.query_by_vpath(provider_vpath)
        user = api.query_by_vpath(user_vpath)
        image_item = api.query_by_vpath(image_vpath)

        provider = self._build_provider(api, provider, user)

        image = Image(provider, image_item)

        actions = {
            'create': image.create,
            'remove': image.remove
        }
        actions[action](api, image_item)

    def _volume_tasks_remove(self, _, provider, user, tenant):
        """ From the tenant, gets its volumes,
            A remove task is returned for every volume in for_removal state
        """
        tasks = []
        for volume in [vol for vol in tenant.volumes if vol.is_for_removal()]:
            tasks.append(self._volume_callbacktask(provider, user,
                                                   volume, 'remove'))
            LOG.trace.info('Added task to remove volume "%s"' % volume.name)

        return tasks

    def _volume_tasks_create(self, _, provider, user, tenant):
        """ From the tenant, gets its volumes,
            A create task is returned for every volume in initial state
        """
        tasks = []
        for volume in [vol for vol in tenant.volumes if vol.is_initial()]:
            tasks.append(self._volume_callbacktask(provider, user,
                                                   volume, 'create'))
            LOG.trace.info('Added task to create image "%s"',
                           volume.name)

        return tasks

    def _volume_callbacktask(self, provider, user, volume, action):
        provider_vpath = provider.get_vpath()
        user_vpath = user.get_vpath()
        volume_vpath = volume.get_vpath()

        cb_task = CallbackTask(
            volume,
            '{1} Openstack Volume "{0}"'.format(
                volume.name, action.capitalize()),
            self._volume_action,
            provider_vpath, user_vpath, volume_vpath, action)
        LOG.event.info('Created task: %s' % (cb_task))

        return cb_task

    def _volume_action(self, api, provider_vpath, user_vpath, volume_vpath,
                       action):
        provider = api.query_by_vpath(provider_vpath)
        user = api.query_by_vpath(user_vpath)
        volume_item = api.query_by_vpath(volume_vpath)

        provider = self._build_provider(api, provider, user)

        volume = Volume(provider, volume_item)

        actions = {
            'create': volume.create,
            'remove': volume.remove
        }
        actions[action](api)

    def update_model(self, api):
        """ This is called before the create stage to set
        an initial checksum on the tenant-yum-repo item.
        """
        yumrepos = api.query("tenant-yum-repo", is_for_removal=False)
        for repo in yumrepos:
            try:
                repoquery_out = repoquery(repo)
                repo.checksum = hashlib.md5(repoquery_out).hexdigest()
            except OSYumRepoException:
                LOG.trace.info("Repoquery command failed on repo at"
                        "url: %s" % repo.baseurl)
