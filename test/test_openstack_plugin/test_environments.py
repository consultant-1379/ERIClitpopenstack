import unittest2

from openstack_plugin.environments import ENVIRONMENT, FILES


class TestEnv(unittest2.TestCase):

    maxDiff = None

    def test_environment(self):
        self.assertEqual(
            "resource_registry: {"
                "'LITP::LITP::LBAlarmedServer': 'file:///tmp/lbalarmedserver.yaml',\n  "
                "'LITP::LITP::LBServer': 'file:///tmp/lbserver.yaml'}\n",
            ENVIRONMENT
            )

    def test_files(self):
        self.assertTrue(FILES)
