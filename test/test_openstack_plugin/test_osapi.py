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

from litp.core.execution_manager import CallbackExecutionException


from openstack_plugin.osapi import Image
from openstack_plugin.osapi import Volume


class TestOSAPIImage(unittest.TestCase):

    def setUp(self):
        self.image = Image(Mock(), Mock())
        self._find_image = Mock()
        self.image._find_image = self._find_image

        self.volume = Volume(Mock(), Mock())
        self._find_volume = Mock()
        self.volume._find_volume = self._find_volume

    @patch('openstack_plugin.osapi.os')
    def test__is_local(self, os):
        path = "file:///local/image"
        self.assertTrue(self.image._is_local(path))

        def isfile(path):
            return path == "/local/image"

        #overrides the isfile method in the class and uses the one in the test function instead
        os.path.isfile.side_effect = isfile

        path = "/local/image"
        self.assertTrue(self.image._is_local(path))

        path = "https://some.where/else/"
        self.assertFalse(self.image._is_local(path))

        path = "glance+https://my.buck.et/has/image.img"
        self.assertFalse(self.image._is_local(path))



    def test_volume_check_passed(self):

        self._find_volume.return_value = Mock(status = "available")
        self.assertTrue(self.volume._volume_check(self.volume.volume))

    def test_volume_check_failed(self):

        self._find_volume.return_value = Mock(status="deleting")
        self.assertRaises(CallbackExecutionException, self.volume._volume_check, self.volume.volume)

    def test_volume_null(self):

        self._find_volume.return_value = None
        self.assertRaises(CallbackExecutionException, self.volume._volume_check, self.volume.volume)

    def test_volume_wait(self):

        self._find_volume.return_value = Mock(status="creating")
        self.assertFalse(self.volume._volume_check(self.volume.volume))

    def test__volume_create(self):
        self._find_volume.side_effect = [None, Mock(status="available")]
        self.volume.clients = MagicMock()
        callback_api = Mock()
        self.volume.create(callback_api)

    def test__volume_delete(self):
        self._find_volume.return_value = Mock(status="available")
        callback_api = Mock()
        self.volume.remove(callback_api)

    def test__image_check_failed(self):

        self._find_image.return_value = Mock(status="killed")
        self.assertRaises(CallbackExecutionException, self.image._image_check,
                          self.image.image)

    def test__image_check_passed(self):

        self._find_image.return_value = Mock(status="active")
        self.assertTrue(self.image._image_check(self.image.image))

    def test__image_check_null(self):

        self._find_image.return_value = None
        self.assertRaises(CallbackExecutionException, self.image._image_check,
                          self.image.image)

    def test__image_check_wait(self):

        self._find_image.return_value = Mock()
        self.assertFalse(self.image._image_check(self.image.image))

    def test__image_create(self):
        self._find_image.side_effect = [None, Mock(status="active")]
        self.image.clients = MagicMock()
        self.image.create(Mock(), Mock(status="active", path="http:///image.img"))

    def test__image_delete(self):
        self.image.remove(Mock(), Mock(status="active"))
