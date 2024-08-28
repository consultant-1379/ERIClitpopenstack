from litp.core.plugin import Plugin

import openstack_plugin.openstackplugin

def repoquery(repo):
    return ""

try:
    setattr(openstack_plugin.openstackplugin, "repoquery", repoquery)
except:
    import traceback
    traceback.print_exc()

class YumMockPlugin(Plugin):
    pass
