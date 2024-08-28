##############################################################################
# COPYRIGHT Ericsson AB 2014
#
# The copyright to the computer program(s) herein is the property of
# Ericsson AB. The programs may be used and/or copied only with written
# permission from Ericsson AB. or in accordance with the terms and
# conditions stipulated in the agreement/contract under which the
# program(s) have been supplied.
##############################################################################

import os
import re
from .utils import wait_on_state, TimeoutParameters


# FIXME(xigomil) glanceclient after juno uses different exception module
try:
    from glanceclient.openstack.common.apiclient.exceptions \
        import NotFound as ImageNotFound
except ImportError:
    from glanceclient.exc import NotFound as ImageNotFound

from cinderclient.exceptions import NotFound as VolumeNotFound
from cinderclient.exceptions import OverLimit

from litp.core.execution_manager import CallbackExecutionException
from litp.core.litp_logging import LitpLogger

from .osclientmanager import OSClientManager

LOG = LitpLogger()

MAX_WAIT_SECONDS = 90


class OSObject(object):
    """
    Object capabale of creating its own callback tasks and
    providing required OpenStack API callbacks
    """
    def __init__(self, provider):
        self.provider = provider
        self.clients = OSClientManager(self.provider)


class Volume(OSObject):
    def __init__(self, provider, volume_item):
        super(Volume, self).__init__(provider)
        self.volume = volume_item

    def create(self, callback_api):
        volume_found = self._find_volume(self.volume)
        if volume_found:
            LOG.trace.info('Volume "%s" already created, skipping'
                           % volume_found.name)
        else:
            try:
                volume = self.clients.volume_client.volumes.create(
                    name=self.volume.name,
                    size=self.volume.size)
            except OverLimit as ex:
                msg = 'Error creating volume: %s' % str(ex)
                LOG.trace.error(msg)
                raise CallbackExecutionException(msg)
        self.volume.uuid = volume.id

        wait_on_state(callback_api,
                      self._volume_check,
                      TimeoutParameters(),
                      volume)

    # pylint: disable=W0613
    def remove(self, callback_api):
        volume = self._find_volume(self.volume)
        if volume:
            volume.delete()

    def _find_volume(self, volume):
        """ Utiliy method taking care of finding an image with
            different openstack image-client versions:"""
        volume_found = None
        try:
            volume_found = self.clients.volume_client.volumes.find(
                name=volume.name)
        except VolumeNotFound:
            pass
        return volume_found

    def _volume_check(self, volume_item):
        volume = self._find_volume(volume_item)
        if volume:
            if volume.status == "available":
                return True
            if volume.status == "error":
                msg = ("An error occurred during volume creation, Name: %s " %
                      str(volume.name))
                raise CallbackExecutionException(msg)
            if volume.status == "creating":

                return False

        msg = "Cannot find volume_item"
        raise CallbackExecutionException(msg)


class Image(OSObject):
    def __init__(self, provider, image_item):
        super(Image, self).__init__(provider)
        self.image = image_item

    def _is_local(self, path):
        pattern = r"^file:///[a-zA-Z0-9./\-_]+$"
        if re.match(pattern, path):
            return True
        if os.path.isfile(path):
            return True
        return False

    def create(self, callback_api, image):
        image_found = self._find_image(image)
        if image_found:
            LOG.trace.info('Image "%s" already created, skipping'
                           % image.name)
            # if image is found, we return happily:
            return

        try:
            # NOTE(xigomil) In case of non-local path,
            # we "copy_from" the remote path
            if self._is_local(image.path):
                # strip protocol prefix
                image_path = re.sub("^file://", "", image.path)
                with open(image_path) as image_file:
                    self.clients.image_client.images.create(
                        name=image.name,
                        disk_format=image.disk_format,
                        container_format='bare',
                        data=image_file)
            else:
                self.clients.image_client.images.create(
                    name=image.name,
                    disk_format=image.disk_format,
                    container_format='bare',
                    copy_from=image.path)

            wait_on_state(callback_api, self._image_check, TimeoutParameters(),
                          image)

        except Exception as ex:
            msg = 'Error creating image: %s' % str(ex)
            LOG.trace.error(msg)
            raise CallbackExecutionException(msg)
        else:
            LOG.trace.info('Imported image "%s" to Image service.' %
                           image.name)

    def _image_check(self, image_item):
        image = self._find_image(image_item)

        if image is not None:
            LOG.trace.info(image.status)
            if image.status == "active":
                return True
            if image.status == "killed":
                msg = ('An error occurred during volume creation, Name: %s' %
                       str(image_item.name))
                LOG.trace.error(msg)
                raise CallbackExecutionException(msg)
            return False

        msg = "No Image Found for name: %s " % str(image_item.name)
        LOG.trace.error(msg)
        raise CallbackExecutionException(msg)

    # pylint: disable=W0613
    def remove(self, callback_api, image):
        image_found = self._find_image(image)
        if not image_found:
            msg = 'Image "%s" not found: %s' % image.name
            raise CallbackExecutionException(msg)

        image_found.delete()
        LOG.trace.info('Removed image "%s" from the Image service.' %
                       image.name)

    def _find_image(self, image):
        """ Utiliy method taking care of finding an image with
            different openstack image-client versions:"""
        image_found = None
        if hasattr(self.clients.image_client.images, 'find'):
            try:
                image_found = self.clients.image_client.images.find(
                    name=image.name)
            except ImageNotFound:
                pass
        else:
            for im in self.clients.image_client.images.list():
                if im.name == image.name:
                    image_found = im
        return image_found
