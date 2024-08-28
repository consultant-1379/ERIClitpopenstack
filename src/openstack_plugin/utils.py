##############################################################################
# COPYRIGHT Ericsson AB 2013
#
# The copyright to the computer program(s) herein is the property of
# Ericsson AB. The programs may be used and/or copied only with written
# permission from Ericsson AB. or in accordance with the terms and
# conditions stipulated in the agreement/contract under which the
# program(s) have been supplied.
##############################################################################
'''
Provides decorators for Plugin classes and their helper classes so the helper
classes may use CallbackTasks directly.
CallbackTasks in the helper classes must be created through the
create_callback_task factory method and not instantiated directly.
'''
from collections import namedtuple

import subprocess
import sys
import time
from litp.core.execution_manager import CallbackTask, PlanStoppedException
from litp.core.litp_logging import LitpLogger

from .exceptions import OSYumRepoException

PLAN_STOPPED_MESSAGE = 'Plan execution has been stopped'

LOG = LitpLogger()


def query_by_vpath(api, vpath):
    return api.query('infrastructure')[0].query_by_vpath(vpath)


def get_cluster(item):
    return get_ancestor(item, "tenant-cluster")


def get_stack(item):
    return get_ancestor(item, "tenant-stack")


def get_stack_resource(item, *args, **kwargs):
    '''
    Return queried resource if within the same stack as item
    '''
    return get_stack(item).query(*args, **kwargs)[0]


def get_tenant(item):
    return get_ancestor(item, "cloud-tenant")


def has_changed_dependencies(item):
    return any([item.has_initial_dependencies(),
                item.has_removed_dependencies(),
                item.has_updated_dependencies()])


def get_ancestor(item, item_type_id):
    # XXX Danger here. Core API doesn't provide mechanism for checking extends
    # parents
    # If someone extends an ancestor and replaces it in the model.
    # This code will no longer work. Discussed with core, and I'll be having
    # a look at the query method in core to see about either introducing a
    # reverse flag. But for the mean time this is what I can do with the
    # existing core APIs
    if item.item_type_id == item_type_id:
        return item
    return get_ancestor(item.get_parent(), item_type_id)


def patch_plugin_callback(clazz):
    '''
    Adds __callback__ utility function to plugin to allow callbacks
    from helper classes to be called directly
    '''
    # Possibly change to base class + mixin
    def __callback__(self, callback_api, *args,
                     **kwargs):  # pylint: disable=W0613
        module_name = kwargs["__module_name__"]
        class_name = kwargs["__class_name__"]
        function_name = kwargs["__function_name__"]
        del kwargs["__function_name__"]
        del kwargs["__module_name__"]
        del kwargs["__class_name__"]
        current_module = sys.modules[module_name]
        clazz = getattr(current_module, class_name)
        getattr(clazz, function_name)(callback_api, *args, **kwargs)
    clazz.__callback__ = __callback__
    return clazz


def patch_helper_callback(clazz):
    '''
    Adds _create_callback_task method that produces a CallbackTask that uses
    the __callback__ method as a proxy to the passed helper function
    '''
    # Possibly change to base class
    def _create_callback_task(self, plugin, model_item, description, function,
                              *cargs, **kwargs):
        kwargs["__module_name__"] = self.__module__
        kwargs["__class_name__"] = self.__class__.__name__
        kwargs["__function_name__"] = function.__name__
        cargs = (model_item,
                 description,
                 plugin.__callback__) + cargs
        return CallbackTask(*cargs, **kwargs)
    clazz.create_callback_task = _create_callback_task
    return clazz

TimeoutParameters = namedtuple('TimeoutParameters',
                               'max_wait sleep_function sleep_time')
TimeoutParameters.__new__.__defaults__ = (60 * 3,
                                          time.sleep,
                                          1)


def wait_on_state(callback_api, callback_function, timing_parameters,
                  *callback_args, **callback_kwargs):
    """
    Blocking method that returns True when a state is reached or
    if the timeout is exceeded returns False.
    """
    start_time = int(time.time())

    while not callback_function(*callback_args, **callback_kwargs):
        diff_time = int(time.time()) - start_time

        if diff_time > timing_parameters.max_wait:
            return False
        if not callback_api.is_running():
            raise PlanStoppedException(PLAN_STOPPED_MESSAGE)
        timing_parameters.sleep_function(timing_parameters.sleep_time)
    return True


def run_cmd(cmd):
    """ Run a shell command piping stdout and sterr"""
    assert cmd is not None

    p = subprocess.Popen(cmd,
                         stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE,
                         shell=True)

    outs, errs = p.communicate()

    if outs == '':
        return (0, 'no_response', '')

    return (p.returncode, outs, errs)


def repoquery(repo):
    """ This runs repoquery commands on the
    repo_list passed as parameter. The repo_list
    contains tenant-yum-repo objects.
    """
    # intermittent failure of reqoquery has been seen before (LITPCDS-10800)
    repoquery_cmd = ('repoquery --repoid=a '
            '--repofrompath=a,%s -a --queryformat '
            '"%%{NAME} %%{VERSION} %%{RELEASE} %%{ARCH}"')

    retries = 4
    while True:
        result, stdout, stderr = run_cmd(repoquery_cmd % repo.baseurl)
        if result == 0 and not stderr:
            return stdout
        else:
            if result != 0:
                msg = ('Error executing repoquery command: "{0}", result:'
                    ' {1}, stderr {2}'.format(repoquery_cmd, result, stderr))
                LOG.event.error(msg)
                raise OSYumRepoException(msg)
            retries -= 1
            if retries == 0:
                msg = ('Error executing repoquery command: "{0}", result:'
                    ' {1}, stderr {2}'.format(repoquery_cmd, result, stderr))
                LOG.event.error(msg)
                raise OSYumRepoException(msg)
            else:
                LOG.event.error("repoquery failure, will retry, return code:"
                        " {0}, stderr: {1}".format(result, stderr))
