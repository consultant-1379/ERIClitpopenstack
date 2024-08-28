##############################################################################
# COPYRIGHT Ericsson AB 2014
#
# The copyright to the computer program(s) herein is the property of
# Ericsson AB. The programs may be used and/or copied only with written
# permission from Ericsson AB. or in accordance with the terms and
# conditions stipulated in the agreement/contract under which the
# program(s) have been supplied.
##############################################################################

import unittest
from mock import Mock, MagicMock, patch

patch("openstack_plugin.heat.Heat").start()

from litp.core.execution_manager import CallbackExecutionException
from openstack_plugin.openstackplugin import OpenStackPlugin

from litp.core.validators import ValidationError


def _mock_instance_lb_group():
    igroup = Mock()
    igroup.name = 'igroup1'

    igroup.get_vpath = lambda: ("/deployments/site1/clusters/cloud1/"
                                "tenants/litp/stacks/stack1/"
                                "instance_groups/igroup1")
    return igroup


class TestOpenStackPlugin(unittest.TestCase):

    def setUp(self):
        self.plugin = OpenStackPlugin()

    def test__check_instance_group_has_instance(self):
        igroup = _mock_instance_lb_group()
        igroup.instance = None

        context = Mock()
        context.query = lambda itemtype, **kwargs: [igroup]

        errors = self.plugin._check_instance_lb_group_has_instance(context)
        self.assertEqual(1, len(errors))

    def test__check_instance_lb_group_alarms(self):
        igroup = _mock_instance_lb_group()
        alarm1 = Mock()
        alarm2 = Mock()

        def mockquery(itemtype, **kwargs):
            if itemtype == 'tenant-instance-lb-group':
                return [igroup]
            if itemtype == 'tenant-alarm':
                return [alarm1, alarm2]

        context = Mock()
        context.query = mockquery
        igroup.query = mockquery

        errors = self.plugin._check_instance_lb_group_alarms(context)
        self.assertEqual(1, len(errors))

    def test__check_instance_lb_group_two_lbs_has_alarm(self):
        igroup = _mock_instance_lb_group()
        lb1 = Mock()
        lb2 = Mock()

        def mockquery(itemtype, **kwargs):
            if itemtype == 'tenant-instance-lb-group':
                return [igroup]
            if itemtype == 'tenant-alarm':
                return []
            if itemtype == 'tenant-lb':
                return [lb1, lb2]

        context = Mock()
        context.query = mockquery
        igroup.query = mockquery

        errors = self.plugin._check_instance_lb_group_two_lbs_has_alarm(
            context)
        self.assertEqual(1, len(errors))

    def test__check_instance_lb_group_floating_ip(self):
        igroup = _mock_instance_lb_group()
        lb1 = Mock()
        lb1.vip_floating_ip_pool = "public"
        lb2 = Mock()
        lb2.vip_floating_ip_pool = "public"

        def mockquery(itemtype, **kwargs):
            if itemtype == 'tenant-instance-lb-group':
                return [igroup]
            if itemtype == 'tenant-lb':
                return [lb1, lb2]

        context = Mock()
        context.query = mockquery
        igroup.query = mockquery

        errors = self.plugin._check_instance_lb_group_floating_ip(context)
        self.assertEqual(1, len(errors))

    def test__check_instance_lb_group_not_both_alarm_floating_ip(self):
        igroup = _mock_instance_lb_group()
        lb1 = Mock()
        lb1.name = "lb1"
        lb1.vip_floating_ip_pool = "public"
        lb1.get_vpath = lambda: ("/deployments/site1/clusters/cloud1/"
                                 "tenants/litp/stacks/stack1/"
                                 "instance_groups/igroup1/loadbalancers/lb1")
        alarm1 = Mock()

        def mockquery(itemtype, **kwargs):
            if itemtype == 'tenant-instance-lb-group':
                return [igroup]
            if itemtype == 'tenant-alarm':
                return [alarm1]
            if itemtype == 'tenant-lb':
                return [lb1]

        context = Mock()
        context.query = mockquery
        igroup.query = mockquery
        lb1.query = mockquery

        errors = (self.plugin.
            _check_instance_lb_group_not_both_alarm_floating_ip(context))
        self.assertEqual(1, len(errors))

    def test_validate__check_instance_volume_device_name_uniqueness(self):

        i1 = Mock()
        instances = [i1]
        vol1 = Mock()
        vol2 = Mock()
        vol1.name = "vol1"
        vol2.name = "vol2"
        vol1.device_name = "vdb"
        vol2.device_name = "vdb"
        volumes = [vol1, vol2]

        vol1.get_vpath = lambda: ("/deployments/site1/clusters/cloud1/"
                                  "tenants/litp/stacks/stack1/instances/"
                                  "instance1/volumes/vol1")

        vol2.get_vpath = lambda: ("/deployments/site1/clusters/cloud1/"
                                  "tenants/litp/stacks/stack1/instances/"
                                  "instance1/volumes/vol2")

        def mockquery(itemtype, **kwargs):
            if itemtype == 'tenant-volume':
                return volumes
            if itemtype == 'tenant-instance':
                return instances

        def mockqueryInstance(itemtype, **kwargs):
            if itemtype == 'tenant-volume':
                return volumes

        i1.query = mockqueryInstance
        context = Mock()
        context.query = mockquery
        errors = self.plugin._check_instance_volume_device_name_uniqueness(context)
        self.assertEqual(1, len(errors))
        self.assertEqual('Volume cannot be attached. '
                         'Another Volume is already attached '
                         'to "vdb" device.',
                         errors[0].error_message)

    def test_validate__check_instance_volume_has_device_name(self):

        i1 = Mock()
        instances = [i1]
        vol1 = Mock()
        vol1.name = "vol1"
        #vol1.size = ""
        vol1.device_name = ""
        #tenant volume with name vol1
        volumes = [vol1]

        vol1.get_vpath = lambda: ("/deployments/site1/clusters/cloud1/"
                                  "tenants/litp/stacks/stack1/instances/"
                                  "instance1/volumes/vol1")

        def mockquery(itemtype, **kwargs):
            if itemtype == 'tenant-volume':
                return volumes
            if itemtype == 'tenant-instance':
                return instances

        def mockqueryInstance(itemtype, **kwargs):
            if itemtype == 'tenant-volume':
                return volumes

        i1.query = mockqueryInstance
        context = Mock()
        context.query = mockquery
        errors = self.plugin._check_instance_volume_has_device_name(context)
        self.assertEqual(1, len(errors))
        self.assertEqual('Volume cannot be created '
                         'without specifying '
                         'device_name property.',
                         errors[0].error_message)

    def test_validate__check_instance_volume_exist(self):

        i1 = Mock()
        instances = [i1]
        vol1 = Mock()
        vol1.name = "vol1"
        vol1.size = ""
        volumes = [vol1]

        vol1.get_vpath = lambda: ("/deployments/site1/clusters/cloud1/"
                                  "tenants/litp/stacks/stack1/instances/"
                                  "instance1/volumes/vol1")

        def mockquery(itemtype, **kwargs):
            if itemtype == 'tenant-volume':
                return volumes
            if itemtype == 'tenant-instance':
                return instances

        def mockqueryInstance(itemtype, **kwargs):
            if itemtype == 'tenant-volume':
                return volumes

        i1.query = mockqueryInstance
        context = Mock()
        context.query = mockquery
        errors = self.plugin._check_instance_volume_exist(context)
        self.assertEqual(1, len(errors))
        self.assertEqual('Volume cannot be attached, a tenant-volume with '
                         'name "vol1" must exist.',
                         errors[0].error_message)
        vol2 = Mock()
        #tenant volume with name vol1
        vol2.name = "vol1"

        vol2.get_vpath = lambda: ('/deployments/site1/clusters/'
                                  'cloud1/tenants/litp/volumes/vol2')

        volumes.append(vol2)
        errors = self.plugin._check_instance_volume_exist(context)
        self.assertEqual(0, len(errors))

    def test_validate__check_provider_is_in_use(self):

        provider = Mock()
        cluster = Mock()

        providers = [provider]
        clusters = [cluster]

        provider.get_vpath = lambda:  ('/infrastructure/system_providers/'
                                       'openstack1')
        cluster.get_vpath = lambda: ('/deployments/site1/clusters/cloud1')

        def mockquery(itemtype, **kwargs):
            if itemtype == 'openstack-provider':
                return providers
            if itemtype == 'tenant-cluster':
                return clusters

        provider.is_for_removal = Mock(return_value=True)
        cluster.is_for_removal = Mock(return_value=False)

        provider.name = 'openstack1'
        cluster.provider_name = 'openstack1'

        context = Mock()
        context.query = mockquery

        errors = self.plugin._check_if_provider_is_in_use(context)
        self.assertEqual(1, len(errors))
        self.assertEqual('Provider: "openstack1" is in use on cluster '
                         '"/deployments/site1/clusters/cloud1", '
                         'cannot be removed',
                         errors[0].error_message)

    def test_validate__check_instance_volume_has_size(self):

        i1 = Mock()
        instances = [i1]
        vol1, vol2 = Mock(), Mock()
        vol1.name = ""
        vol2.name = ""
        vol1.size = ""
        vol2.size = ""

        volumes = [vol1, vol2]

        vol1.get_vpath = lambda: ("/deployments/site1/clusters/cloud1/"
                                  "tenants/litp/stacks/stack1/instances/"
                                  "instance1/volumes/vol1")

        vol2.get_vpath = lambda: ("/deployments/site1/clusters/cloud1/"
                                  "tenants/litp/stacks/stack1/instances/"
                                  "instance1/volumes/vol2")

        def mockquery(itemtype, **kwargs):
            if itemtype == 'tenant-volume':
                return volumes
            if itemtype == 'tenant-instance':
                return instances

        def mockqueryInstance(itemtype, **kwargs):
            if itemtype == 'tenant-volume':
                return volumes

        i1.query = mockqueryInstance
        context = Mock()
        context.query = mockquery
        errors = self.plugin._check_instance_volume_has_size(context)
        self.assertEqual(2, len(errors))
        self.assertEqual('Volume cannot be attached, '
                         'without specifying size property.',
                         errors[0].error_message)

    def test_validate__check_tenant_volume_have_name_and_size(self):

        vol1, vol2 = Mock(), Mock()
        vol1.name = "vol1"
        vol2.name = "vol2"
        vol1.size = ""
        vol2.size = ""
        volumes = [vol1, vol2]

        vol1.get_vpath = lambda: ("/deployments/site1/clusters/"
                                  "cloud1/tenants/litp/volumes/vol1")

        vol2.get_vpath = lambda: ("/deployments/site1/clusters/"
                                  "cloud1/tenants/litp/volumes/vol2")

        def mockquery(itemtype, **kwargs):
            if itemtype == 'tenant-volume':
                return volumes

        context = Mock()
        context.query = mockquery
        errors = self.plugin._check_tenant_volume_have_name_and_size(context)
        self.assertEqual(2, len(errors))
        self.assertEqual('Volume cannot be created, '
                         'the size property must be present.',
                         errors[0].error_message)
        vol3 = Mock()
        vol3.name = ""
        vol3.size = "100"
        volumes = [vol3]

        vol3.get_vpath = lambda: ("/deployments/site1/clusters/"
                                  "cloud1/tenants/litp/volumes/vol3")

        errors = self.plugin._check_tenant_volume_have_name_and_size(context)
        self.assertEqual(1, len(errors))
        self.assertEqual('Volume cannot be created, '
                         'the name property must be present.',
                         errors[0].error_message)

    def test_validate__on_cloud_load_balancer_create_check_monitor(self):

        clb1, clb2 = Mock(), Mock()
        mon1, mon2 = Mock(), Mock()
        clb1.name = 'clb1'
        clb2.name = 'clb2'
        mon1.name = 'monitor1'
        mon2.name = 'monitor2'
        loadbalancers = [clb1, clb2]
        monitors = [mon1, mon2]

        def mockquery(itemtype, **kwargs):
            if itemtype == 'tenant-lb':
                return loadbalancers
            if itemtype == 'tenant-lb-monitor':
                return monitors

        clb1.monitors = 'monitor1,monitor2'
        clb2.monitors = 'monitor3'

        context = Mock()
        context.query = mockquery
        errors = self.plugin._on_cloud_load_balancer_create_check_monitor(context)
        self.assertEqual(1, len(errors))
        self.assertEqual('Cloud Load Balancer "clb2" '
                         'cannot be created,'
                         ' monitor "monitor3" must be present',
                         errors[0].error_message)

    def test_validate__on_cloud_load_balancer_create_check_network(self):

        clb1, clb2, = Mock(), Mock()
        net1, net2 = Mock(), Mock()
        net1.name = 'net1'
        net2.name = 'net2'
        clb1.name = 'clb1'
        clb2.name = 'clb2'
        loadbalancers = [clb1, clb2]
        networks = [net1, net2]

        def mockquery(itemtype, **kwargs):
            if itemtype == 'tenant-lb':
                return loadbalancers
            if itemtype == 'tenant-network':
                return networks

        clb1.network_name = 'net1'
        clb2.network_name = 'net3'
        context = Mock()
        context.query = mockquery
        errors = self.plugin._on_cloud_load_balancer_create_check_network(context)
        self.assertEqual(1, len(errors))
        self.assertEqual('Cloud Load Balancer "clb2" '
                         'cannot be created, network "net3" must be present',
                         errors[0].error_message)

    def test_validate__on_cloud_image_create_check_unique_name(self):
        #ci = cloud image
        ci1, ci2, ci3, ci4 = Mock(), Mock(), Mock(), Mock()
        ci1.name, ci2.name, ci3.name, ci4.name = ('cirros32',
                                                  'cirros33',
                                                  'cirros34',
                                                  'cirros35')
        ci1.path, ci2.path = ('file:///tmp/cirros-0.3.2-x86_64-disk.img',
                              'file:///tmp/cirros-0.3.2-x86_64-disk.img')
        ci3.path = 'file:///tmp/cirros-0.3.2-x86_64-disk.img'
        ci4.path = 'file:///tmp/cirros-0.3.2-x86_64-disk.img'

        cloudImages = [ci1, ci2, ci3, ci4]

        def mockquery(itemtype, **kwargs):
            if itemtype == 'tenant-image':
                return cloudImages

        context = Mock()
        context.query = mockquery
        errors = self.plugin._on_cloud_image_create_check_unique_name(context)
        self.assertEqual([], errors)
        ci1.name, ci2.name, ci3.name, ci4.name = ('cirros32',
                                                  'cirros32',
                                                  'cirros33',
                                                  'cirros33')
        errors = self.plugin._on_cloud_image_create_check_unique_name(context)
        self.assertEqual(2, len(errors))
        for x in range(0, len(errors)):
            self.assertTrue(isinstance(errors[x], ValidationError))

    def test_validate__on_router_create_check_network(self):
        net1 = Mock()
        #router
        r1, r2 = Mock(network_name=None), Mock(network_name=None)
        net1.name = 'net1'
        r1.name, r2.name = 'router1', 'router2'
        networks = [net1]
        routers = [r1, r2]

        def mockquery(itemtype, **kwargs):
            if itemtype == 'tenant-network':
                return networks
            elif itemtype == 'tenant-router':
                return routers

        context = Mock()
        context.query = mockquery
        errors = self.plugin._on_router_create_check_network(context)
        #router network are emptpy.
        self.assertEqual(2, len(errors))
        r1.network_name, r2.network_name = 'net1', 'net2'
        errors = self.plugin._on_router_create_check_network(context)
        self.assertEqual(1, len(errors))
        self.assertEqual('Router "router2" cannot be created, '
                         'network "net2" must be present',
                         errors[0].error_message)

    def test_validate__on_instance_create(self):
        net1, net2 = Mock(), Mock()
        i_net1, i_net2 = Mock(), Mock()
        net1.name, net2.name = 'net1', 'net2'
        i_net1.network_name, i_net2.network_name = 'net1', 'net2'
        networks = [net1, net2]

        key1 = Mock()
        key1.name = 'key'
        key1.public_key = ('ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQEA6oiPy3K7mAdm'
                           'GxG0d4OkfsTEByOCrITEW0JfT1QlfGw6ay4zRD/czKTVInp5I'
                           '/meNtQ0HUE3dNH7CaJfXSYADaJkmSJ7zo5HJDz0ALbWugftAy'
                           'gQDCbj+EEgYNB7ia2OtPo7oJSQanlnS7vA7GIqryVU6IFXjpu'
                           'NREvU+knUvnekHLag9KzhV02OAMiSQrEPyWGrPALlieyjnjU2'
                           'gzlKoo0ATkBJVde056P7BpQIjsPpvcD07CS5TmhypZcvaGPXf'
                           'NjxAOcbCrxR54gk6JT0jJZXG4UkR7oN1d18Jt85XOGPuK9lnd'
                           'YvDlIwl0POBq03eajJ9IYrZNWL71AzC12121== igor@CHG5J')
        keypairs = [key1]

        i1 = Mock()
        i1.networks = [i_net1]
        i1.key_name = 'key'
        i2 = Mock()
        i2.networks = [i_net1]
        i2.key_name = 'key'
        i3 = Mock()
        i3.networks = [i_net1, i_net2]
        i3.key_name = 'key'
        instances = [i1, i2, i3]

        def mockquery(itemtype, **kwargs):
            if itemtype == 'tenant-network':
                return networks
            elif itemtype == 'tenant-instance':
                return instances
            elif itemtype == 'tenant-keypair':
                return keypairs

        context = Mock()
        context.query = mockquery
        errors = self.plugin._on_instance_create(context)
        self.assertEqual([], errors)

        i3 = Mock()
        i3.networks = [i_net1]
        instances = [i1, i2, i3]
        errors = self.plugin._on_instance_create(context)
        #self.assertEqual(ValidationError, type(errors[0]))
        # what if there were no errors ?

    def test__find_untranslated_fixed_ip(self):
        nova = Mock()

        class NotFound(BaseException):
            pass

        # The following test doesnt work yet, since we are mocking exceptions
        # and usage of mocked exceptions causes failing of test
        #
        #def floating_ips_find(fixed_ip=None):
        #    if fixed_ip == '10.10.0.2':
        #        raise NotFound
        #
        #nova.floating_ips.find = floating_ips_find

        #addrs = {'litp': [{'addr': '10.10.0.2', 'OS-EXT-IPS:type': 'fixed'}],
        #    'litp2': [{'addr': '10.11.0.3', 'OS-EXT-IPS:type': 'fixed'}],
        #}

        #result = self.plugin._find_untranslated_fixed_ip(nova, addrs, 'litp')
        #self.assertEqual(result, '10.10.0.2')

        #result = self.plugin._find_untranslated_fixed_ip(nova, addrs, 'litp2')
        #self.assertEqual(result, None)

    def test_update_plugin_empty_query(self):
        api = Mock()
        def mockquery(itemtype, **kwargs):
            if itemtype == 'tenant-yum-repo' and not kwargs['is_for_removal']:
                return []
        api.query = mockquery

        _ = self.plugin.update_model(api)
        self.assertEqual(None, _)
