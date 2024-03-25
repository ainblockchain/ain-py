# -*- coding: utf-8 -*-
# snapshottest: v1 - https://goo.gl/zC4yUc
from __future__ import unicode_literals

from snapshottest import Snapshot


snapshots = Snapshot()

snapshots['TestDatabase::test01Get 1'] = [
    {
        '.rule': {
            'write': 'true'
        },
        'can': {
            'write': {
                '.rule': {
                    'write': 'true'
                }
            }
        },
        'cannot': {
            'write': {
                '.rule': {
                    'write': 'false'
                }
            }
        }
    },
    {
        'can': {
            'write': -5
        },
        'username': 'test_user'
    },
    None
]

snapshots['TestDatabase::test01GetFunction 1'] = {
    '.function': {
        '0xFUNCTION_HASH': {
            'function_id': '0xFUNCTION_HASH',
            'function_type': 'REST',
            'function_url': 'https://events.ainetwork.ai/trigger'
        }
    }
}

snapshots['TestDatabase::test01GetOwner 1'] = {
    '.owner': {
        'owners': {
            '*': {
                'branch_owner': True,
                'write_function': True,
                'write_owner': True,
                'write_rule': True
            },
            '0x09A0d53FDf1c36A131938eb379b98910e55EEfe1': {
                'branch_owner': True,
                'write_function': True,
                'write_owner': True,
                'write_rule': True
            }
        }
    }
}

snapshots['TestDatabase::test01GetRule 1'] = {
    '.rule': {
        'write': 'true'
    },
    'can': {
        'write': {
            '.rule': {
                'write': 'true'
            }
        }
    },
    'cannot': {
        'write': {
            '.rule': {
                'write': 'false'
            }
        }
    }
}

snapshots['TestDatabase::test01GetValue 1'] = {
    'can': {
        'write': -5
    },
    'username': 'test_user'
}

snapshots['TestDatabase::test01GetWithOptions 1'] = None

snapshots['TestDatabase::test01GetWithOptions 2'] = {
    'can': {
        'write': -5
    },
    'username': 'test_user'
}

snapshots['TestDatabase::test01GetWithOptions 3'] = {
    'can': {
        '#state_ph': '0xaf1e44f55da6d7e1aa784dd38372c2c2939570254c6b3f36f80b4878590a9efa'
    },
    'username': 'test_user'
}

snapshots['TestDatabase::test01GetWithOptions 4'] = {
    '#state_ph': '0x3c067fd41205e87fcead2107a0f346881ea7d95249cdbe34d3d72e28e7c9ecd5',
    '#state_ph:username': '0xe9acb84e18d9ec64c66358f53c4fec3945eb065a3e98de907d8d80dc1361c82f',
    'can': {
        '#state_ph': '0xaf1e44f55da6d7e1aa784dd38372c2c2939570254c6b3f36f80b4878590a9efa',
        '#state_ph:write': '0x60ae6f7084539f2137ca3b45aa2e0e3b6d786a17c8de32110a884e285ea6a00c',
        'write': -5
    },
    'username': 'test_user'
}

snapshots['TestDatabase::test01GetWithOptions 5'] = {
    '#num_children': 2,
    '#num_children:username': 0,
    '#num_parents': 1,
    '#num_parents:username': 1,
    '#tree_bytes': 698,
    '#tree_bytes:username': 178,
    '#tree_height': 2,
    '#tree_height:username': 0,
    '#tree_max_siblings': 2,
    '#tree_max_siblings:username': 1,
    '#tree_size': 4,
    '#tree_size:username': 1,
    'can': {
        '#num_children': 1,
        '#num_children:write': 0,
        '#num_parents': 1,
        '#num_parents:write': 1,
        '#tree_bytes': 338,
        '#tree_bytes:write': 168,
        '#tree_height': 1,
        '#tree_height:write': 0,
        '#tree_max_siblings': 1,
        '#tree_max_siblings:write': 1,
        '#tree_size': 2,
        '#tree_size:write': 1,
        'write': -5
    },
    'username': 'test_user'
}

snapshots['TestDatabase::test03EvalOwner 1'] = {
    'code': 0,
    'matched': {
        'closestOwner': {
            'config': {
                'owners': {
                    '*': {
                        'branch_owner': True,
                        'write_function': True,
                        'write_owner': True,
                        'write_rule': True
                    },
                    '0x09A0d53FDf1c36A131938eb379b98910e55EEfe1': {
                        'branch_owner': True,
                        'write_function': True,
                        'write_owner': True,
                        'write_rule': True
                    }
                }
            },
            'path': [
                'apps',
                'bfan',
                'users',
                '0x09A0d53FDf1c36A131938eb379b98910e55EEfe1'
            ]
        },
        'matchedOwnerPath': [
            'apps',
            'bfan',
            'users',
            '0x09A0d53FDf1c36A131938eb379b98910e55EEfe1'
        ],
        'subtreeOwners': [
        ]
    }
}

snapshots['TestDatabase::test03EvalRuleTrue 1'] = {
    'code': 0,
    'matched': {
        'state': {
            'closestRule': {
                'config': None,
                'path': [
                ]
            },
            'matchedRulePath': [
                'apps',
                'bfan',
                'users',
                '0x09A0d53FDf1c36A131938eb379b98910e55EEfe1',
                'can',
                'write'
            ],
            'matchedValuePath': [
                'apps',
                'bfan',
                'users',
                '0x09A0d53FDf1c36A131938eb379b98910e55EEfe1',
                'can',
                'write'
            ],
            'pathVars': {
            }
        },
        'write': {
            'closestRule': {
                'config': {
                    'write': 'true'
                },
                'path': [
                    'apps',
                    'bfan',
                    'users',
                    '0x09A0d53FDf1c36A131938eb379b98910e55EEfe1',
                    'can',
                    'write'
                ]
            },
            'matchedRulePath': [
                'apps',
                'bfan',
                'users',
                '0x09A0d53FDf1c36A131938eb379b98910e55EEfe1',
                'can',
                'write'
            ],
            'matchedValuePath': [
                'apps',
                'bfan',
                'users',
                '0x09A0d53FDf1c36A131938eb379b98910e55EEfe1',
                'can',
                'write'
            ],
            'pathVars': {
            },
            'subtreeRules': [
            ]
        }
    }
}

snapshots['TestDatabase::test03GetProofHash 1'] = '0x88496dfee3566db91f487aa4cbf69a0c42a3e2a5d0a65bfd4897d699e8734785'

snapshots['TestDatabase::test03MatchFunction 1'] = {
    'matched_config': {
        'config': {
            '0xFUNCTION_HASH': {
                'function_id': '0xFUNCTION_HASH',
                'function_type': 'REST',
                'function_url': 'https://events.ainetwork.ai/trigger'
            }
        },
        'path': '/apps/bfan/users/0x09A0d53FDf1c36A131938eb379b98910e55EEfe1'
    },
    'matched_path': {
        'path_vars': {
        },
        'ref_path': '/apps/bfan/users/0x09A0d53FDf1c36A131938eb379b98910e55EEfe1',
        'target_path': '/apps/bfan/users/0x09A0d53FDf1c36A131938eb379b98910e55EEfe1'
    },
    'subtree_configs': [
    ]
}

snapshots['TestDatabase::test03MatchOwner 1'] = {
    'matched_config': {
        'config': {
            'owners': {
                '*': {
                    'branch_owner': True,
                    'write_function': True,
                    'write_owner': True,
                    'write_rule': True
                },
                '0x09A0d53FDf1c36A131938eb379b98910e55EEfe1': {
                    'branch_owner': True,
                    'write_function': True,
                    'write_owner': True,
                    'write_rule': True
                }
            }
        },
        'path': '/apps/bfan/users/0x09A0d53FDf1c36A131938eb379b98910e55EEfe1'
    },
    'matched_path': {
        'target_path': '/apps/bfan/users/0x09A0d53FDf1c36A131938eb379b98910e55EEfe1'
    },
    'subtree_configs': [
    ]
}

snapshots['TestDatabase::test03MatchRule 1'] = {
    'state': {
        'matched_config': {
            'config': None,
            'path': '/'
        },
        'matched_path': {
            'path_vars': {
            },
            'ref_path': '/apps/bfan/users/0x09A0d53FDf1c36A131938eb379b98910e55EEfe1',
            'target_path': '/apps/bfan/users/0x09A0d53FDf1c36A131938eb379b98910e55EEfe1'
        }
    },
    'write': {
        'matched_config': {
            'config': {
                'write': 'true'
            },
            'path': '/apps/bfan/users/0x09A0d53FDf1c36A131938eb379b98910e55EEfe1'
        },
        'matched_path': {
            'path_vars': {
            },
            'ref_path': '/apps/bfan/users/0x09A0d53FDf1c36A131938eb379b98910e55EEfe1',
            'target_path': '/apps/bfan/users/0x09A0d53FDf1c36A131938eb379b98910e55EEfe1'
        },
        'subtree_configs': [
            {
                'config': {
                    'write': 'true'
                },
                'path': '/can/write'
            },
            {
                'config': {
                    'write': 'false'
                },
                'path': '/cannot/write'
            }
        ]
    }
}
