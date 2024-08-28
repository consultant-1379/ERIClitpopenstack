##############################################################################
# COPYRIGHT Ericsson AB 2014
#
# The copyright to the computer program(s) herein is the property of
# Ericsson AB. The programs may be used and/or copied only with written
# permission from Ericsson AB. or in accordance with the terms and
# conditions stipulated in the agreement/contract under which the
# program(s) have been supplied.
##############################################################################

from keystoneclient.v2_0.client import Client as IdentityClient
from glanceclient import Client as ImageClient
from cinderclient.client import Client as VolumeClient

from litp.core.litp_logging import LitpLogger

LOG = LitpLogger()

GLANCE_VERSION = '1'
CINDER_VERSION = '2'

GLANCE_SERVICE = 'image'
CINDER_SERVICE = 'volumev2'


class OSClientManager(object):
    """
    OpenStack Clients Manager
    """

    def __init__(self, provider):
        self._provider = provider

        self._clients = {
            'identity': None,
            'image': None,
            'volume': None
        }

    @property
    def identity_client(self):
        if not self._clients['identity']:
            LOG.trace.info(self._provider.auth_url)
            self._clients['identity'] = IdentityClient(
                username=self._provider.username,
                password=self._provider.password,
                tenant_name=self._provider.tenant,
                auth_url=self._provider.auth_url)

        return self._clients['identity']

    @property
    def image_client(self):
        if not self._clients['image']:
            glance_endpoint = self.identity_client.service_catalog.url_for(
                service_type=GLANCE_SERVICE, endpoint_type='publicURL')
            self._clients['image'] = ImageClient(
                GLANCE_VERSION,
                glance_endpoint,
                token=self.identity_client.auth_token)

        return self._clients['image']

    @property
    def volume_client(self):
        if not self._clients['volume']:
            cinder_endpoint = self.identity_client.service_catalog.url_for(
                service_type=CINDER_SERVICE, endpoint_type='publicURL')
            LOG.trace.info(cinder_endpoint)
            self._clients['volume'] = VolumeClient(
                CINDER_VERSION,
                self._provider.username,
                self._provider.password,
                self._provider.tenant,
                self._provider.auth_url)
            LOG.trace.info(dir(self._clients['volume']))

        return self._clients['volume']
