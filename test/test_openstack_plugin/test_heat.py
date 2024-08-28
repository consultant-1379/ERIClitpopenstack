##############################################################################
# COPYRIGHT Ericsson AB 2014
#
# The copyright to the computer program(s) herein is the property of
# Ericsson AB. The programs may be used and/or copied only with written
# permission from Ericsson AB. or in accordance with the terms and
# conditions stipulated in the agreement/contract under which the
# program(s) have been supplied.
##############################################################################

import unittest2
import tempfile
import yaml
import types
from .mocks import mock_model_item
from mock import MagicMock, Mock, patch

from heatclient.exc import HTTPConflict

from litp.core.execution_manager import CallbackExecutionException
from litp.core.validators import ValidationError

from openstack_plugin.heat import (Heat, Stack, HeatSerialisable, Server,
                                   Network, Subnet, Router, Action)
from openstack_plugin.heat import (FloatingIPLB, AutoScaleLBGroup,
                                   HealthMonitor, LoadBalancer, Pool)
from openstack_plugin.heat import _wait_for_stack, _get_stack_log_message

from openstack_plugin.environments import ENVIRONMENT, FILES
from openstack_plugin.openstackplugin import OpenStackPlugin
from openstack_plugin import exceptions, utils

STACK_COLLECTIONS = ['networks',
                     'routers',
                     'instance_lb_groups',
                     'lb_monitors',
                     'instances',
                     'security_groups']

SERVER_COLLECTIONS = ['networks',
                      'network_mounts',
                      'packages',
                      'yumrepos',
                      'volumes',
                      'hostentries']


class BaseTest(unittest2.TestCase):

    def setUp(self):
        # remove this dummy comment
        self.plugin = OpenStackPlugin()

        root = mock_model_item("/", "root")
        infra = mock_model_item('infrastructure', 'infrastructure')
        root.add_child(infra)
        provider = mock_model_item('os-provider', 'openstack-provider',
                                   name="os-provider")
        infra.add_child_to_collection(provider, 'providers')
        cluster = mock_model_item("cluster", "tenant-cluster",
                                  provider_name="os-provider")
        tenant = mock_model_item("tenant1", "cloud-tenant", name="tenant")
        stack = mock_model_item("stack1", "tenant-stack",
                                collections=STACK_COLLECTIONS)
        server = mock_model_item("server", "tenant-instance", flavor="m1.small",
                                 key_name='litp', image_name='image',
                                 instance_name="name",
                                 security_group_names="",
                                 collections=SERVER_COLLECTIONS)
        key = mock_model_item("litp", "tenant-keypair",
                              name="litp", public_key="publickey")
        user = mock_model_item("user", "tenant-user", name="user",
                               password_key="password_key")
        root.add_child_to_collection(cluster, 'clusters')
        cluster.add_child_to_collection(tenant, 'tenants')

        stack.instances.add_child(server)
        stack.add_child_to_collection(key, "keypairs")

        tenant.add_child_to_collection(stack, 'stacks')
        tenant.add_child_to_collection(user, 'users')

        self.root = root
        self.stack = stack

    def _get_template_dump(self):
        s = Stack(self.stack)
        return s.create_template()


class TestHeat(BaseTest):
    def test_create_configuration1(self):
        tasks = Heat(self.plugin).create_configuration(self.root)
        self.assertEqual(len(tasks), 1)
        self.assertEqual(
            tasks[0].kwargs['action'],
            Action.CREATE)

    def test_create_provider(self):
        provider2 = mock_model_item('os-provider2', 'openstack-provider',
                                    name="os-provider2")
        self.root.infrastructure.add_child_to_collection(provider2,
                                                         'providers')

        self.root.clusters[0].provider_name = "os-provider2"
        self.assertEqual(
            provider2,
            Stack(self.root.query("tenant-stack")[0]).get_provider())

    def test_stack_name(self):
        self.assertEqual(
            "stack1",
            Stack(self.root.query("tenant-stack")[0]).name)

    def test_all_applied(self):
        self.root.set_all_applied()
        tasks = Heat(self.plugin).create_configuration(self.root)
        self.assertEqual(len(tasks), 0)

    def test_all_updated(self):
        self.root.set_all_updated()
        tasks = Heat(self.plugin).create_configuration(self.root)
        self.assertEqual(len(tasks), 1)
        self.assertEqual(
            tasks[0].kwargs['action'],
            Action.UPDATE)

    def test_applied_stack_updated_dependencies(self):
        self.root.set_all_updated()
        self.root.query("tenant-stack")[0].set_applied()
        tasks = Heat(self.plugin).create_configuration(self.root)
        self.assertEqual(len(tasks), 1)
        self.assertEqual(
            tasks[0].kwargs['action'],
            Action.UPDATE)

    def test_initial_stack_updated_dependencies(self):
        self.root.set_all_updated()
        self.root.query("tenant-stack")[0].set_initial()
        tasks = Heat(self.plugin).create_configuration(self.root)
        self.assertEqual(len(tasks), 1)
        self.assertEqual(
            tasks[0].kwargs['action'],
            Action.CREATE)

    def test_removed_stack_updated_dependencies(self):
        self.root.set_all_updated()
        self.root.query("tenant-stack")[0].set_for_removal()
        tasks = Heat(self.plugin).create_configuration(self.root)
        self.assertEqual(len(tasks), 1)
        self.assertEqual(
            tasks[0].kwargs['action'],
            Action.REMOVE)

    def test_validation_unique_packages(self):
        instance = self.root.query('tenant-instance')[0]
        package1 = mock_model_item("package1", "tenant-package",
                                   name="package-name")
        package2 = mock_model_item("package2", "tenant-package",
                                   name="package-name")
        instance.add_child_to_collection(package1, "packages")
        instance.add_child_to_collection(package2, "packages")
        errors = Heat(self.plugin).validate_model(self.root)
        self.assertEqual(len(errors), 2)
        self.assertEqual(errors[0],
                         ValidationError(package1.get_vpath(),
                                         'package-name',
                                         'Duplicate package'))
        self.assertEqual(errors[1],
                         ValidationError(package2.get_vpath(),
                                         'package-name',
                                         'Duplicate package'))
        instance.add_collection('packages')
        package1 = mock_model_item("package1", "tenant-package",
                                   name="package-name1")
        package2 = mock_model_item("package2", "tenant-package",
                                   name="package-name2")
        instance.add_child_to_collection(package1, "packages")
        instance.add_child_to_collection(package2, "packages")
        errors = Heat(self.plugin).validate_model(self.root)
        self.assertEqual(len(errors), 0)

    def test_validation_unique_repos(self):
        instance = self.root.query('tenant-instance')[0]
        yumrepo1 = mock_model_item("yumrepo1", "tenant-yum-repo",
                                   name="yumrepo-name",
                                   baseurl="http://yumrepo")
        yumrepo2 = mock_model_item("yumrepo2", "tenant-yum-repo",
                                   name="yumrepo-name",
                                   baseurl="http://yumrepo")
        instance.add_child_to_collection(yumrepo1, "yumrepos")
        instance.add_child_to_collection(yumrepo2, "yumrepos")
        errors = Heat(self.plugin).validate_model(self.root)
        self.assertEqual(len(errors), 2)
        self.assertEqual(errors[0],
                         ValidationError(yumrepo1.get_vpath(),
                                         'yumrepo-name',
                                         'Duplicate repo name'))
        self.assertEqual(errors[1],
                         ValidationError(yumrepo2.get_vpath(),
                                         'yumrepo-name',
                                         'Duplicate repo name'))

        yumrepo1 = mock_model_item("yumrepo1", "tenant-yum-repo",
                                   name="yumrepo-name1",
                                   baseurl="http://yumrepo")
        yumrepo2 = mock_model_item("yumrepo2", "tenant-yum-repo",
                                   name="yumrepo-name2",
                                   baseurl="http://yumrepo")
        instance.add_collection('yumrepos')
        instance.add_child_to_collection(yumrepo1, "yumrepos")
        instance.add_child_to_collection(yumrepo2, "yumrepos")
        errors = Heat(self.plugin).validate_model(self.root)
        self.assertEqual(len(errors), 0)

    @patch("openstack_plugin.utils.run_cmd")
    def test_validation_hash_repos(self, mock_run_cmd):
        mock_run_cmd.return_value = 0, "test_stdout", ""
        yumrepo1 = mock_model_item("yumrepo1", "tenant-yum-repo",
                                   name="yumrepo-name1",
                                   baseurl="http://yumrepo")
        query = utils.repoquery(yumrepo1)
        self.assertEqual(query, "test_stdout")
        mock_run_cmd.return_value = 1, "test_stdout", ""
        self.assertRaises(exceptions.OSYumRepoException,
                          utils.repoquery, yumrepo1)
        mock_run_cmd.side_effect = [(0, "", "ERROR"),
                                    (0, "", "ERROR"),
                                    (0, "", "ERROR"),
                                    (0, "pkg1\npkg2\npkg3", "")]
        self.assertEqual(query, "test_stdout")
        mock_run_cmd.side_effect = [(0, "", "ERROR"),
                                    (0, "", "ERROR"),
                                    (0, "", "ERROR"),
                                    (0, "", "ERROR"),
                                    (0, "pkg1\npkg2\npkg3", "")]
        self.assertRaises(exceptions.OSYumRepoException,
                          utils.repoquery, yumrepo1)

    def test__get_template_dump_dir(self):
        expected_dump_dir = "{0}/litp_heat_templates".format(
            tempfile.gettempdir())
        stack = Stack(self.root.query("tenant-stack")[0])
        self.assertEqual(expected_dump_dir, stack._get_template_dump_dir())

    def test__get_template_dump_filepath(self):
        stack = Stack(self.root.query("tenant-stack")[0])
        expected_filepath_prefix = "{0}/cluster_tenant1_stack1_".format(
            stack._get_template_dump_dir())
        filepath = stack._get_template_dump_filepath()
        self.assertTrue(filepath.startswith(expected_filepath_prefix))

    def test_task_description(self):
        heat = Heat(self.plugin)
        name = "stack1"
        self.assertEqual(types.StringType, type(heat._get_task_description(Action.CREATE, name)))
        self.assertEqual(types.StringType, type(heat._get_task_description(Action.UPDATE, name)))
        self.assertEqual(types.StringType, type(heat._get_task_description(Action.REMOVE, name)))
        self.assertRaises(exceptions.ActionException, heat._get_task_description, -1, name)


class TestHeatSerialisable(BaseTest):
    def test_init(self):
        item = mock_model_item("/item")
        heat = HeatSerialisable(item)
        self.assertEqual({"type": ""}, heat.__getstate__())

    def test_init_depends_on(self):
        instance = self.root.query('tenant-instance')[0]
        instance.depends_on = "a"
        stack = self.root.query('tenant-stack')[0]
        instance2 = mock_model_item('a', 'tenant-instance', instance_name="a")
        stack.add_child_to_collection(instance2, "instances")
        heat = HeatSerialisable(instance)
        self.assertItemsEqual(
            {"type": "",
             "depends_on": ['a', 'b', 'c']
             },
            heat.__getstate__())


class TestSerialise(BaseTest):
    def test_serialize(self):
        tasks = Heat(self.plugin).create_configuration(self.root)
        self.assertEqual(len(tasks), 1)
        self.assertEqual(
            {'heat_template_version': '2014-10-16',
             'resources': {
                 'instances_server_multipart_mime':
                     {'properties': {
                         'parts': []},
                         'type': 'OS::Heat::MultipartMime'},
                 'instances_server':
                     {
                         'properties': {
                             'flavor': 'm1.small',
                             'key_name': {'get_resource': 'keypairs_litp_key'},
                             'image': 'image',
                             'user_data': {'get_resource': 'instances_server_multipart_mime'},
                             'user_data_format': 'RAW'},
                         'type': 'OS::Nova::Server'
                     },
                 'keypairs_litp_key':
                     {'type': 'OS::Nova::KeyPair',
                      'properties': {
                          'name': 'litp',
                          'public_key': 'publickey'}
                      }
             }},
            yaml.load(self._get_template_dump()))

    def test_volumes(self):
        instance = self.root.query('tenant-instance')[0]
        volume = mock_model_item("volume", "instance-volume",
                                 size="100",
                                 device_name="vdb",
                                 delete_on_termination="false",
                                 name="")
        instance.add_child_to_collection(volume, 'volumes')
        hostentry = mock_model_item("hostentry", "instance-hostentry",
                                    ip="10.10.11.100", hostentry="ms.hostname",
                                    delete_on_termination="false", name="")
        instance.add_child_to_collection(hostentry, "hostentries")
        tasks = Heat(self.plugin).create_configuration(self.root)
        self.assertEqual(len(tasks), 1)
        self.assertEqual(
            {'heat_template_version': '2014-10-16',
             'resources': {
                 'instances_server_hostentries_multipart_mime': {
                     'type': 'OS::Heat::CloudConfig',
                     'properties': {
                         'cloud_config': {
                             'bootcmd': [
                                 'echo 10.10.11.100 ms.hostname >> /etc/hosts'
                             ]
                         }
                     }
                 },
                 'instances_server_multipart_mime':
                     {
                         'properties': {
                             'parts': [
                                 {'config': {'get_resource': 'instances_server_hostentries_multipart_mime'}}]},
                         'type': 'OS::Heat::MultipartMime'},
                 'instances_server':
                     {
                         'type': 'OS::Nova::Server',
                         'properties': {
                             'user_data_format': 'RAW',
                             'block_device_mapping': [
                                 {
                                     'volume_id': {
                                         'get_resource': 'instances_server_volumes_volume'
                                     },
                                     'device_name': 'vdb'
                                 }
                             ],
                             'key_name': {
                                 'get_resource': 'keypairs_litp_key'
                             },
                             'image': 'image',
                             'user_data': {
                                 'get_resource': 'instances_server_multipart_mime'
                             },
                             'flavor': 'm1.small'
                         }
                     },
                 'keypairs_litp_key':
                     {'type': 'OS::Nova::KeyPair',
                      'properties': {
                          'name': 'litp',
                          'public_key': 'publickey'}
                      },
                 'instances_server_volumes_volume':
                     {'type': 'OS::Cinder::Volume',
                      'properties': {
                          'size': '100'}
                      },
             }},
            yaml.load(self._get_template_dump()))

    def test_packages(self):
        instance = self.root.query('tenant-instance')[0]
        package = mock_model_item("package", "tenant-package",
                                  name="package-name")
        instance.add_child_to_collection(package, 'packages')
        tasks = Heat(self.plugin).create_configuration(self.root)
        self.assertEqual(len(tasks), 1)
        self.assertEqual(
            {'heat_template_version': '2014-10-16',
             'resources': {
                 'instances_server_multipart_mime':
                     {
                         'properties': {
                             'parts': [
                                {'config': {'get_resource': 'instances_server_packages_multipart_mime'}},
                                ]},
                         'type': 'OS::Heat::MultipartMime'},
                 'instances_server_packages_multipart_mime': {
                     'properties': {
                         'cloud_config': {
                             'packages': ['package-name']}},
                     'type': 'OS::Heat::CloudConfig'},
                 'instances_server':
                     {'type': 'OS::Nova::Server',
                      'properties': {
                          'key_name': {'get_resource': 'keypairs_litp_key'},
                          'flavor': 'm1.small',
                          'image': 'image',
                          'user_data': {
                              'get_resource': 'instances_server_multipart_mime'},
                          'user_data_format': 'RAW',
                      }},
                 'keypairs_litp_key':
                     {'type': 'OS::Nova::KeyPair',
                      'properties': {
                          'name': 'litp',
                          'public_key': 'publickey'}
                      }
             }},
            yaml.load(self._get_template_dump())
        )

    def test_repos(self):
        instance = self.root.query('tenant-instance')[0]
        yum_repo = mock_model_item("yumrepo", "tenant-yum-repo",
                                   name="yumrepo-name",
                                   baseurl="http://yumrepo",
                                   checksum="94d762fdce01dad7a986d4ac68c15d")
        instance.add_child_to_collection(yum_repo, 'yumrepos')
        tasks = Heat(self.plugin).create_configuration(self.root)
        template_dump = self._get_template_dump()
        self.assertEqual(len(tasks), 1)
        self.assertEqual(
            {'heat_template_version': '2014-10-16',
             'resources': {
                 'instances_server_multipart_mime': {
                         'properties': {
                             'parts': [{'config': {'get_resource': 'instances_server_yumrepos_multipart_mime'}},
                                       ]},
                         'type': 'OS::Heat::MultipartMime'},
                 'instances_server_yumrepos_multipart_mime': {
                     'properties': {
                         'cloud_config': {
                             'yum_repos': {
                                 'yumrepo-name': {
                                     'baseurl': 'http://yumrepo',
                                     'gpgcheck': False,
                                     'name': 'yumrepo-name',
                                     'checksum': '94d762fdce01dad7a986d4ac68c15d'}}}},
                     'type': 'OS::Heat::CloudConfig'},
                 'instances_server': {
                     'type': 'OS::Nova::Server',
                     'properties': {
                         'key_name': {'get_resource': 'keypairs_litp_key'},
                         'flavor': 'm1.small',
                         'image': 'image',
                         'user_data': {
                             'get_resource': 'instances_server_multipart_mime'},
                         'user_data_format': 'RAW'}},
                 'keypairs_litp_key': {
                     'type': 'OS::Nova::KeyPair',
                     'properties': {
                          'name': 'litp',
                          'public_key': 'publickey'}}
             }},
            yaml.load(self._get_template_dump())
        )

    def test_nfs_mounts(self):
        instance = self.root.query('tenant-instance')[0]
        nfs_mount = mock_model_item("nfsmount", "tenant-network-file-share",
                                    provider="enm1", export_path="/export/data",
                                    mount_point="/mnt/data", read_size="8192",
                                    write_size="8192", timeout="600", options="noexec")
        instance.add_child_to_collection(nfs_mount, 'network_mounts')
        tasks = Heat(self.plugin).create_configuration(self.root)
        self.assertEqual(len(tasks), 1)
        self.assertEqual(
            {'heat_template_version': '2014-10-16',
             'resources': {
                 'instances_server_network_mounts_multipart_mime': {
                     'properties': {
                         'cloud_config': {
                             'mounts': [['enm1:/export/data',
                                         '/mnt/data',
                                         'nfs',
                                         'rsize=8192,wsize=8192,timeo=600,noexec',
                                         '0',
                                         '0']]}},
                     'type': 'OS::Heat::CloudConfig'},
                 'instances_server_multipart_mime':
                     {'properties': {
                         'parts': [
                             {'config': {'get_resource': 'instances_server_network_mounts_multipart_mime'}},
                             ]},
                         'type': 'OS::Heat::MultipartMime'},
                 'instances_server': {
                     'type': 'OS::Nova::Server',
                     'properties': {
                         'key_name': {'get_resource': 'keypairs_litp_key'},
                         'flavor': 'm1.small',
                         'image': 'image',
                         'user_data': {
                             'get_resource': 'instances_server_multipart_mime'},
                         'user_data_format': 'RAW',
                     }},
                 'keypairs_litp_key':
                     {'type': 'OS::Nova::KeyPair',
                      'properties': {
                          'name': 'litp',
                          'public_key': 'publickey'}
                      }
             }},
            yaml.load(self._get_template_dump()))

    def test_keypair(self):
        stack = self.root.query('tenant-stack')[0]
        key = mock_model_item("litp", "tenant-keypair",
                              name="litp", public_key="publickey")
        stack.add_child_to_collection(key, 'keypairs')
        tasks = Heat(self.plugin).create_configuration(self.root)
        self.assertEqual(len(tasks), 1)
        self.assertEqual(
            {'heat_template_version': '2014-10-16',
             'resources': {
                 'instances_server_multipart_mime': {
                     'properties': {
                         'parts': []},
                     'type': 'OS::Heat::MultipartMime'},
                 'instances_server': {
                     'type': 'OS::Nova::Server',
                     'properties': {
                         'key_name': {'get_resource': 'keypairs_litp_key'},
                         'flavor': 'm1.small',
                         'image': 'image',
                         'user_data': {'get_resource': 'instances_server_multipart_mime'},
                         'user_data_format': 'RAW'},
                 },
                 'keypairs_litp_key': {
                     'type': 'OS::Nova::KeyPair',
                     'properties': {
                         'name': 'litp',
                         'public_key': 'publickey',
                     }
                 },
             }},
            yaml.load(self._get_template_dump())
        )


class TestModelParsing(unittest2.TestCase):
    def test_stack_model(self):
        root = mock_model_item("/", "root")
        infra = mock_model_item('infrastructure', 'infrastructure')
        root.add_child(infra)
        provider = mock_model_item('os-provider', 'openstack-provider',
                                   name="os-provider")
        infra.add_child_to_collection(provider, 'providers')
        cluster = mock_model_item("cluster", "tenant-cluster",
                                  provider_name="os-provider")
        tenant = mock_model_item("tenant1", "tenant-tenant")
        stack = mock_model_item("stack1", "tenant-stack")

        network = mock_model_item("network", "tenant-network", name="litp")
        subnet = mock_model_item("subnet", "tenant-network-subnet",
                                 name="litp", cidr="10.10.0.0/24",
                                 ip_version="4", enable_dhcp="true",
                                 disable_gateway="false")
        network.add_child_to_collection(subnet, "subnets")
        router = mock_model_item("router", "tenant-router", name="litp",
                                 network_name="litp", public_network="public")

        server = mock_model_item("server", 'tenant-instance', flavor="m1.small",
                                 key_name='litp', image_name='image',
                                 instance_name="name",
                                 security_group_names="")
        instance_network = mock_model_item("network",
                                           "instance-network",
                                           network_name="litp",
                                           floating_ip_pool="public")

        root.add_child_to_collection(cluster, 'clusters')
        cluster.add_child_to_collection(tenant, 'tenants')
        stack.add_child_to_collection(network, "networks")
        server.add_child_to_collection(instance_network, "networks")
        server.network_mounts = []
        server.packages = []
        server.volumes = []
        server.hostentries = []
        server.yumrepos = []
        stack.add_child_to_collection(router, "routers")
        stack.add_child_to_collection(server, 'instances')
        tenant.add_child_to_collection(stack, 'stacks')
        # LB stuff:
        stack.instance_lb_groups = []
        stack.lb_monitors = []
        stack.security_groups = []

        s = Stack(stack)
        s.create_template()
        r = s.resources

        self.assertItemsEqual(
            [u'networks_network_subnets_subnet',
             u'networks_network',
             u'instances_server_multipart_mime',
             u'routers_router',
             u'instances_server_fip',
             u'instances_server',
             u'routers_router_interface'],
            r.keys())
        self.assertTrue(isinstance(r['instances_server'], Server))
        self.assertTrue(isinstance(r['networks_network'], Network))
        self.assertTrue(isinstance(r['networks_network_subnets_subnet'],
                                   Subnet))
        self.assertTrue(isinstance(r['routers_router'], Router))

        s.create_template()

    def __create_stack(self, create_alarm=False):
        root = mock_model_item("/", "root")
        infra = mock_model_item('infrastructure', 'infrastructure')
        root.add_child(infra)
        provider = mock_model_item('os-provider', 'openstack-provider',
                                   name="os-provider")
        infra.add_child_to_collection(provider, 'providers')
        cluster = mock_model_item("cluster", "tenant-cluster",
                                  provider_name="os-provider")
        tenant = mock_model_item("tenant1", "cloud-tenant")
        stack = mock_model_item("stack1", "tenant-stack")

        network = mock_model_item("network", "tenant-network", name="litp")
        subnet = mock_model_item("subnet", "tenant-network-subnet",
                                 name="litp", cidr="10.10.0.0/24",
                                 ip_version="4", enable_dhcp="true",
                                 disable_gateway="false")
        network.add_child_to_collection(subnet, "subnets")
        router = mock_model_item("router", "tenant-router", name="litp",
                                 network_name="litp", public_network="public")

        instance_lb_group = mock_model_item("lb_group",
                                            "tenant-instance-lb-group",
                                            group_name="group1", max="3",
                                            min="1")
        instance = mock_model_item('instance', "tenant-instance",
                                   flavor="m1.small",
                                   key_name='litp', image_name='image',
                                   instance_name="", security_group_names="")
        instance_lb_group.add_child(instance)
        instance.add_child_to_collection(
            mock_model_item("network",
                            "instance-network",
                            network_name="litp"
                            ),
            "networks")
        instance.packages = []
        instance.yumrepos = []
        instance.volumes = []
        instance.hostentries = []
        instance.network_mounts = []

        lb = mock_model_item(
            "lb", "tenant-lb", vip_floating_ip_pool='PUBLIC',
            monitors='monitor1,monitor2', name='lb1', network_name='litp',
            lb_method='round_robin', member_port='80', vip_port='90',
            protocol='2')
        lb.is_for_removal = False
        instance_lb_group.add_child_to_collection(lb, "loadbalancers")

        if create_alarm:
            health_check = mock_model_item(
                "health_check", "tenant-lb", vip_floating_ip_pool=None,
                monitors='monitor1,monitor2', name='lb2', network_name='litp',
                lb_method='round_robin', member_port='80', vip_port='90',
                protocol='2')
            health_check.is_for_removal = False
            instance_lb_group.add_child_to_collection(health_check,
                                                      "loadbalancers")
            alarm = mock_model_item("alarm", "tenant-alarm",
                                    description="alarm_test", wait_timeout=800,
                                    period=10, evaluation_periods=10)
            alarm.is_for_removal = False
            health_check.add_collection("alarms")
            health_check.alarms = [alarm]

        monitor1 = mock_model_item(
            'monitor1', 'tenant-lb-monitor', name='monitor1', type='ping',
            delay='200', max_retries='1', timeout='18')
        monitor2 = mock_model_item(
            'monitor2', 'tenant-lb-monitor', name='monitor2', type='ping',
            delay='200', max_retries='10', timeout='118')
        stack.add_child_to_collection(monitor1, "lb_monitors")
        stack.add_child_to_collection(monitor2, "lb_monitors")

        root.add_child_to_collection(cluster, 'clusters')
        cluster.add_child_to_collection(tenant, 'tenants')
        stack.add_child_to_collection(network, "networks")
        stack.add_child_to_collection(instance_lb_group, "instance_lb_groups")
        stack.add_child_to_collection(router, "routers")
        tenant.add_child_to_collection(stack, 'stacks')
        stack.instances = []
        stack.volumes = []
        stack.security_groups = []

        return stack

    def test_stack_model_with_lb(self):
        stack = self.__create_stack()

        s = Stack(stack)
        s.create_template()
        r = s.resources
        self.assertItemsEqual([
            'instance_lb_groups_lb_group_loadbalancers_lb_fip',
            'instance_lb_groups_lb_group',
            'instance_lb_groups_lb_group_loadbalancers_lb',
            'instance_lb_groups_lb_group_loadbalancers_lb_pool',
            'lb_monitors_monitor1',
            'lb_monitors_monitor2',
            'networks_network',
            'routers_router',
            'routers_router_interface',
            'networks_network_subnets_subnet',
            'instance_lb_groups_lb_group_instance_multipart_mime'],
            r.keys())
        self.assertTrue(isinstance(r['instance_lb_groups_lb_group_loadbalancers_lb_fip'],
                                   FloatingIPLB))
        self.assertTrue(isinstance(r['instance_lb_groups_lb_group'],
                                   AutoScaleLBGroup))
        self.assertTrue(isinstance(r['instance_lb_groups_lb_group_loadbalancers_lb'],
                                   LoadBalancer))
        self.assertTrue(isinstance(r['instance_lb_groups_lb_group_loadbalancers_lb_pool'],
                                   Pool))
        self.assertTrue(isinstance(r['lb_monitors_monitor1'],
                                   HealthMonitor))
        self.assertTrue(isinstance(r['lb_monitors_monitor2'],
                                   HealthMonitor))

        s.create_template()

    def test_stack_model_with_alarm(self):
        stack = self.__create_stack(True)

        s = Stack(stack)
        template = s.create_template()
        self.assertTrue("LBAlarmedServer" in template)


class TestCallback(unittest2.TestCase):
    @patch('openstack_plugin.heat.Stack')
    @patch('openstack_plugin.heat._wait_for_stack')
    @patch('openstack_plugin.heat.HeatClient')
    @patch('openstack_plugin.heat.KeystoneClient')
    def test_create(self, keystone, heat, wait_for_stack, stack):
        api = Mock()
        api.query.return_value = [Mock()]

        stack_instance = MagicMock()
        stack_instance.create_template.return_value = 'template'
        stack.return_value = stack_instance

        heat_client = Mock()
        heat.return_value = heat_client

        Heat.callback(api, 'stackcreate', 'template', Action.CREATE,
                      "tenant", "/", "/")

        heat_client.stacks.create.assert_called_with(
            stack_name="stackcreate",
            template="template",
            environment=ENVIRONMENT,
            files=FILES)

    @patch('openstack_plugin.heat.Stack')
    @patch('openstack_plugin.heat._wait_for_stack')
    @patch('openstack_plugin.heat.HeatClient')
    @patch('openstack_plugin.heat.KeystoneClient')
    @patch('openstack_plugin.heat._get_stack_id')
    def test_create_stack_exists(self, _get_stack_id, keystone, heat,
                                 wait_for_stack, stack):
        api = Mock()
        api.query.return_value = [Mock()]

        stack_instance = MagicMock()
        stack_instance.create_template.return_value = 'template'
        stack.return_value = stack_instance

        heat_client = Mock()
        heat.return_value = heat_client
        heat_client.stacks.list = lambda name: ['stackcreate']
        _get_stack_id.return_value = 'stackcreate'

        heat_client.stacks.create.side_effect = [HTTPConflict, None]
        wait_for_stack.side_effect = ['FAILED', None, 'COMPLETE']

        Heat.callback(api, 'stackcreate', 'template', Action.CREATE,
                      "tenant", "/", "/")

        heat_client.stacks.create.assert_called_with(
            stack_name="stackcreate",
            template="template",
            environment=ENVIRONMENT,
            files=FILES)
        self.assertEqual(2, heat_client.stacks.create.call_count)
        heat_client.stacks.update.assert_called_with(
            'stackcreate',
            template="template",
            environment=ENVIRONMENT,
            files=FILES)
        heat_client.stacks.delete.assert_called_with('stackcreate')

    @patch('openstack_plugin.heat.Stack')
    @patch('openstack_plugin.heat._wait_for_stack')
    @patch('openstack_plugin.heat.HeatClient')
    @patch('openstack_plugin.heat.KeystoneClient')
    @patch('openstack_plugin.heat._get_stack_id')
    def test_create_stack_exists_update_complete(self, _get_stack_id, keystone,
                                                 heat, wait_for_stack, stack):
        api = Mock()
        api.query.return_value = [Mock()]

        stack_instance = MagicMock()
        stack_instance.create_template.return_value = 'template'
        stack.return_value = stack_instance

        heat_client = Mock()
        heat.return_value = heat_client
        heat_client.stacks.list = lambda name: ['stackcreate']
        _get_stack_id.return_value = 'stackcreate'

        heat_client.stacks.create.side_effect = [HTTPConflict]
        wait_for_stack.side_effect = ['COMPLETE']

        Heat.callback(api, 'stackcreate', 'template', Action.CREATE,
                      "tenant", "/", "/")

        heat_client.stacks.create.assert_called_with(
            stack_name="stackcreate",
            template="template",
            environment=ENVIRONMENT,
            files=FILES)
        self.assertEqual(1, heat_client.stacks.create.call_count)
        heat_client.stacks.update.assert_called_with(
            'stackcreate',
            template="template",
            environment=ENVIRONMENT,
            files=FILES)

    @patch('openstack_plugin.heat.Stack')
    @patch('openstack_plugin.heat._wait_for_stack')
    @patch('openstack_plugin.heat.HeatClient')
    @patch('openstack_plugin.heat.KeystoneClient')
    @patch('openstack_plugin.heat._get_stack_id')
    def test_create_stack_exists_remove_failure(self, _get_stack_id, keystone,
                                                heat, wait_for_stack, stack):
        api = Mock()
        api.query.return_value = [Mock()]

        stack_instance = MagicMock()
        stack_instance.create_template.return_value = 'template'
        stack.return_value = stack_instance

        heat_client = Mock()
        heat.return_value = heat_client
        heat_client.stacks.list = lambda name: ['stackcreate']
        _get_stack_id.return_value = 'stackcreate'

        heat_client.stacks.create.side_effect = [HTTPConflict]
        wait_for_stack.side_effect = ['FAILED', 'FOO']

        self.assertRaises(CallbackExecutionException, Heat.callback, api,
                          'stackcreate', 'template', Action.CREATE, "tenant", "/", "/")

        heat_client.stacks.create.assert_called_with(
            stack_name="stackcreate",
            template="template",
            environment=ENVIRONMENT,
            files=FILES)
        self.assertEqual(1, heat_client.stacks.create.call_count)
        heat_client.stacks.update.assert_called_with(
            'stackcreate',
            template="template",
            environment=ENVIRONMENT,
            files=FILES)
        heat_client.stacks.delete.assert_called_with('stackcreate')

    @patch('openstack_plugin.heat.Stack')
    @patch('openstack_plugin.heat._wait_for_stack')
    @patch('openstack_plugin.heat.HeatClient')
    @patch('openstack_plugin.heat.KeystoneClient')
    def test_remove(self, keystone, heat, wait_for_stack, stack):
        api = Mock()
        api.query.return_value = [Mock()]

        stack_instance = MagicMock()
        stack_instance.create_template.return_value = 'template'
        stack.return_value = stack_instance

        heat_client = Mock()
        heat.return_value = heat_client
        heat_client.stacks.list.return_value = [Mock(id='id')]

        Heat.callback(api, 'stackremove', 'template', Action.REMOVE,
                      "tenant", "/", "/")

        heat_client.stacks.list.assert_called_with(
            name="stackremove")
        heat_client.stacks.delete.assert_called_with(
            "id")

    @patch('openstack_plugin.heat.Stack')
    @patch('openstack_plugin.heat._wait_for_stack')
    @patch('openstack_plugin.heat.HeatClient')
    @patch('openstack_plugin.heat.KeystoneClient')
    def test_update(self, keystone, heat, wait_for_stack, stack):
        api = Mock()
        api.query.return_value = [Mock()]

        heat_client = Mock()
        heat.return_value = heat_client
        stack_instance = MagicMock()
        stack_instance.create_template.return_value = 'template'
        stack.return_value = stack_instance

        heat_client.stacks.list.return_value = [Mock(id="id")]

        Heat.callback(api, 'stackupdate', 'template', Action.UPDATE,
                      "tenant", "/", "/")

        heat_client.stacks.list.assert_called_with(
            name="stackupdate")
        heat_client.stacks.update.assert_called_with(
            "id",
            template="template",
            environment=ENVIRONMENT,
            files=FILES)


class TestWaitForStack(unittest2.TestCase):
    @patch('openstack_plugin.heat.sleep')
    @patch('openstack_plugin.heat._in_status')
    @patch('openstack_plugin.heat._get_stack')
    def test__wait_for_stack_no_wait(self, _get_stack, _in_status, _sleep):
        heat_client = MagicMock()
        callback_api = Mock()
        stack_name = 'stack1'

        _get_stack.return_value = MagicMock(status='FOO')
        _in_status.side_effect = [False, True]

        self.assertEqual('FOO', _wait_for_stack(callback_api,
                                                heat_client,
                                                stack_name,
                                                Action.CREATE,
                                                target_status='FOO'))

        self.assertEqual(2, _in_status.call_count)

    @patch('openstack_plugin.heat.sleep')
    @patch('openstack_plugin.heat._in_status')
    @patch('openstack_plugin.heat._get_stack')
    def test__wait_for_stack_one_loop(self, _get_stack, _in_status, _sleep):
        heat_client = MagicMock()
        callback_api = Mock()
        stack_name = 'stack1'

        _get_stack.side_effect = [MagicMock(status='BAR'),
                                  MagicMock(status='FOO')]
        _in_status.side_effect = [False, False, False, True]

        self.assertEqual('FOO', _wait_for_stack(callback_api,
                                                heat_client,
                                                stack_name,
                                                Action.CREATE,
                                                target_status='FOO'))

        self.assertEqual(4, _in_status.call_count)

    @patch('openstack_plugin.heat.sleep')
    @patch('openstack_plugin.heat._in_status')
    @patch('openstack_plugin.heat._get_stack')
    def test__wait_for_stack_time_out(self, _get_stack, _in_status, _sleep):
        heat_client = MagicMock()
        callback_api = Mock()
        stack_name = 'stack1'

        _get_stack.name = stack_name
        _get_stack.side_effect = [MagicMock(status='BAR'),
                                  MagicMock(status='BAR'),
                                  MagicMock(status='FOO')]
        _in_status.return_value = False

        self.assertRaises(CallbackExecutionException,
                          _wait_for_stack,
                          callback_api, heat_client, stack_name,
                          Action.CREATE, target_status='FOO',
                          timeout=0)

        self.assertEqual(2, _in_status.call_count)

    @patch('openstack_plugin.heat._in_status')
    @patch('openstack_plugin.heat._get_stack')
    def test__wait_for_stack_time_out2(self, _get_stack, _in_status):
        heat_client = MagicMock()
        callback_api = Mock()
        stack_name = 'stack1'

        _in_status.return_value = False

        self.assertRaises(CallbackExecutionException,
                          _wait_for_stack,
                          callback_api, heat_client, stack_name,
                          Action.CREATE, target_status='FOO',
                          timeout=-1)

        self.assertEqual(2, _in_status.call_count)

    @patch('openstack_plugin.heat.sleep')
    @patch('openstack_plugin.heat._in_status')
    @patch('openstack_plugin.heat._get_stack')
    def test__wait_for_stack_return_on_fail(self, _get_stack, _in_status, _sleep):
        heat_client = MagicMock()
        callback_api = Mock()
        stack_name = 'stack1'

        _get_stack.return_value = MagicMock(status='FAIL')
        _in_status.side_effect = [False, True]

        self.assertEqual('FAIL', _wait_for_stack(callback_api,
                                                 heat_client,
                                                 stack_name,
                                                 Action.CREATE,
                                                 target_status='FAIL',
                                                 return_on_fail=True))

        self.assertEqual(2, _in_status.call_count)

    def test__get_stack_log_message(self):
        stack_name = 'stack1'
        actions = [Action.CREATE, Action.UPDATE, Action.REMOVE]
        params = []
        for action in actions:
            params.extend([(action, True), (action, False)])
        action_words = {Action.CREATE: 'creation',
                        Action.UPDATE: 'update',
                        Action.REMOVE: 'removal'}
        for action, start in params:
            stage = 'started' if start else 'in progress'
            expected_msg = 'Stack "{0}" {1} {2}.'.format(stack_name,
                                                         action_words[action], stage)
            self.assertEqual(expected_msg,
                             _get_stack_log_message(stack_name, action, start=start))


class TestModelCollection(BaseTest):
    def test_fip(self):
        instance = self.root.query('tenant-instance')[0]
        instance_network = mock_model_item("instancenet", "instance-network",
                                           network_name="litp",
                                           floating_ip_pool="public")
        instance.add_child_to_collection(instance_network, "networks")

        stack = self.root.query('tenant-stack')[0]
        network = mock_model_item("network", "tenant-network", name="litp")
        subnet = mock_model_item("subnet", "tenant-network-subnet",
                                 name="litp",
                                 cidr="10.10.10.0/24",
                                 ip_version="v4",
                                 enable_dhcp=True,
                                 disable_gateway=False)
        network.add_child_to_collection(subnet, "subnets")

        router = mock_model_item("router", "tenant-router",
                                 name="litp", network_name="litp",
                                 public_network='public')

        stack.add_child_to_collection(network, "networks")
        stack.add_child_to_collection(router, "routers")

        tasks = Heat(self.plugin).create_configuration(self.root)
        self.assertEqual(len(tasks), 1)
        self.assertEqual(
            {
                'heat_template_version': '2014-10-16',
                'resources': {
                    'instances_server_multipart_mime':
                        {'properties': {
                            'parts': []},
                            'type': 'OS::Heat::MultipartMime'},
                    'instances_server': {
                        'depends_on': ['networks_network_subnets_subnet'],
                        'type': 'OS::Nova::Server',
                        'properties': {
                            'key_name': {'get_resource': 'keypairs_litp_key'},
                            'flavor': 'm1.small',
                            'image': 'image',
                            'user_data': {'get_resource': 'instances_server_multipart_mime'},
                            'user_data_format': 'RAW',
                            'networks': [
                                {'network': {
                                    'get_resource': 'networks_network'}}]}},
                    'keypairs_litp_key':
                        {'type': 'OS::Nova::KeyPair',
                         'properties': {
                             'name': 'litp',
                             'public_key': 'publickey'}},
                    'routers_router': {
                        'type': 'OS::Neutron::Router',
                        'properties': {
                            'external_gateway_info': {'network': 'public'}}},
                    'instances_server_fip': {
                        'depends_on': ['routers_router_interface'],
                        'type': 'OS::Neutron::FloatingIP',
                        'properties': {
                            'floating_network': 'public',
                            'port_id': {
                                'get_attr': [
                                    'instances_server',
                                    'addresses',
                                    {'get_attr': [
                                        'networks_network',
                                        'name']},
                                    0,
                                    'port']}}},
                    'networks_network_subnets_subnet': {
                        'type': 'OS::Neutron::Subnet',
                        'properties': {
                            'ip_version': 'v4',
                            'network_id': {
                                'get_resource': 'networks_network'},
                            'cidr': '10.10.10.0/24',
                            'enable_dhcp': True}},
                    'networks_network': {'type': 'OS::Neutron::Net'},
                    'routers_router_interface': {
                        'type': 'OS::Neutron::RouterInterface',
                        'properties': {
                            'router_id': {'get_resource': 'routers_router'},
                            'subnet_id': {
                                'get_resource':
                                    'networks_network_subnets_subnet'}}}}},
            yaml.load(self._get_template_dump())
        )
