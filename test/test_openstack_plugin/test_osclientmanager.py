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

from keystoneclient.v2_0.client import Client as IdentityClient
from glanceclient import Client as ImageClient

from glanceclient.exc import NotFound as ImageNotFound

from openstack_plugin.osclientmanager import OSClientManager
from litp.core.execution_manager import CallbackExecutionException

class TestOSClientManager(unittest.TestCase):

    def setUp(self):
        self.provider = MagicMock()
        self.provider.username = 'foo'
        self.provider.password = 'bar'
        self.provider.tenant = 'baz'
        self.provider.auth_url = 'http://some.where/'

    def test_identity_client(self):
        patch('openstack_plugin.osclientmanager.IdentityClient').start()
        os_manager = OSClientManager(self.provider)
        idc1 = os_manager.identity_client
        idc2 = os_manager.identity_client
        self.assertEqual(idc1, idc2)

    def test_image_client(self):
        patch('openstack_plugin.osclientmanager.ImageClient').start()
        os_manager = OSClientManager(self.provider)
        c1 = os_manager.image_client
        c2 = os_manager.image_client
        self.assertEqual(c1, c2)

    def test_volume_client(self):
        patch('openstack_plugin.osclientmanager.VolumeClient').start()
        os_manager = OSClientManager(self.provider)
        c1 = os_manager.volume_client
        c2 = os_manager.volume_client
        self.assertEqual(c1, c2)
