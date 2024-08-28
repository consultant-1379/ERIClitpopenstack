import yaml

ENVIRONMENT = yaml.dump({
    'resource_registry': {
        "LITP::LITP::LBServer": 'file:///tmp/lbserver.yaml',
        "LITP::LITP::LBAlarmedServer": 'file:///tmp/lbalarmedserver.yaml'
    }
})

FILES = {
    'userdata.txt': """#!/bin/bash -ex
wc_notify --data-binary '{"status": "SUCCESS"}'
""",
    'file:///tmp/lbserver.yaml':
    yaml.dump(
        {'heat_template_version': '2013-05-23',
         'parameters': {
             'image': {'type': 'string'},
             'key_name': {'type': 'string'},
             'flavor': {'type': 'string'},
             'network': {'type': 'string'},
             'networks': {'type': 'comma_delimited_list'},
             'lb_pool_id': {'type': 'string', 'default': ''},
             'lb_member_port': {'type': 'string'},
             'user_data_format': {'default': 'RAW', 'type': 'string'},
             'user_data': {'type': 'string'}},
         'resources': {
             'server': {
                 'properties': {
                     'flavor': {'get_param': 'flavor'},
                     'image': {'get_param': 'image'},
                     'key_name': {'get_param': 'key_name'},
                     'networks': [{'network': {'get_param': 'network'}}],
                     'user_data': {'get_param': 'user_data'},
                     'user_data_format': {'get_param': 'user_data_format'}},
                 'type': 'OS::Nova::Server'},

             'member': {
                 'properties': {
                     'pool_id': {'get_param': 'lb_pool_id'},
                     'address': {'get_attr': ['server', 'first_address']},
                     'protocol_port': {'get_param': 'lb_member_port'}},
                 'type': 'OS::Neutron::PoolMember'}
             }
         }
    ),
    'file:///tmp/lbalarmedserver.yaml':  # 2 member 1 alarm
    yaml.dump({
        'heat_template_version': '2013-05-23',
        'description': 'A load-balancer server',
        'parameters': {
            'image': {'type': 'string'},
            'key_name': {'type': 'string'},
            'flavor': {'type': 'string'},
            'lb_pool_id': {'type': 'string'},
            'health_check_pool_id': {'type': 'string'},
            'lb_member_port': {'type': 'number'},
            'health_check_member_port': {'type': 'number'},
            'network': {'type': 'string'},
            'networks': {'type': 'comma_delimited_list'},
            'wait_timeout': {'type': 'number'},
            'period': {'type': 'number'},
            'evaluation_periods': {'type': 'number'},
            'user_data_format': {'default': 'RAW', 'type': 'string'},
            'user_data': {'type': 'string'}
        },
        'resources': {
            'startup_wait': {
                'type': 'OS::Heat::WaitCondition',
                'properties': {
                    'handle': {'get_resource': 'wait_handle'},
                    'timeout': {'get_param': 'wait_timeout'},
                    'count': 1
                },
                'depends_on': 'server'
            },
            'wait_handle': {'type': 'OS::Heat::WaitConditionHandle'},
            'server_user_data': {
                'type': 'OS::Heat::SoftwareConfig',
                'properties': {
                    'group': 'ungrouped',
                    'config': {
                        'str_replace': {'template': {'get_file':
                                                     'userdata.txt'},
                                        'params': {
                                            'wc_notify': {'get_attr':
                                                          ['wait_handle',
                                                           'curl_cli']}
                                        }
                        }
                    }
                }
            },
            'server_config': {
                'type': 'OS::Heat::MultipartMime',
                'properties': {
                    'parts': [{'config': {'get_resource': 'server_user_data'}},
                              {'config': {'get_param': 'user_data'},
                               'type': 'multipart'}]
                }
            },
            'server': {
                'type': 'OS::Nova::Server',
                'properties': {
                    'flavor': {'get_param': 'flavor'},
                    'image': {'get_param': 'image'},
                    'key_name': {'get_param': 'key_name'},
                    'networks': [{'network': {'get_param': 'network'}}],
                    'user_data_format': {'get_param': 'user_data_format'},
                    'user_data': {'get_resource': 'server_config'}
                }
            },
            'lb_member': {
                'type': 'OS::Neutron::PoolMember',
                'properties': {
                    'pool_id': {'get_param': 'lb_pool_id'},
                    'address': {'get_attr': ['server', 'first_address']},
                    'protocol_port': {'get_param': 'lb_member_port'}
                },
            },
            'health_check_member': {
                'type': 'OS::Neutron::PoolMember',
                'properties': {
                    'pool_id': {'get_param': 'health_check_pool_id'},
                    'address': {'get_attr': ['server', 'first_address']},
                    'protocol_port': {'get_param': 'health_check_member_port'}
                },
            },
            'restarter': {
                'type': 'OS::Heat::HARestarter',
                'properties': {
                    'InstanceId': {'get_resource': 'server'}
                },
            },
            'member_alarm': {
                'type': 'OS::Ceilometer::Alarm',
                'properties': {
                    'description': 'Detect server being unresponsive',
                    'meter_name': 'network.services.lb.member',
                    'statistic': 'avg',
                    'period': {'get_param': 'period'},
                    'evaluation_periods': {'get_param':
                                           'evaluation_periods'},
                    'threshold': 0,
                    'comparison_operator': 'eq',
                    'alarm_actions': [{'get_attr': ['restarter', 'AlarmUrl']}],
                    'insufficient_data_actions': [],
                    'repeat_actions': False,
                    'query': [{
                        'field': 'resource_id',
                        'op': 'eq',
                        'value': {'get_resource': 'lb_member'}
                        }]
                    },
                'depends_on': 'startup_wait'
            }
        }
    })
}
