# -*- coding: utf-8 -*-
# snapshottest: v1 - https://goo.gl/zC4yUc
from __future__ import unicode_literals

from snapshottest import Snapshot


snapshots = Snapshot()

snapshots['TestDatabaseRaw::test01Get 1'] = {
    'protoVer': 'erased',
    'result': [
        {
            '.rule': {
                'write': 'auth.addr === "0x09A0d53FDf1c36A131938eb379b98910e55EEfe1"'
            }
        },
        False,
        None
    ]
}

snapshots['TestDatabaseRaw::test01GetValue 1'] = {
    'protoVer': 'erased',
    'result': False
}

snapshots['TestDatabaseRaw::test01GetWithEmptyList 1'] = {
    'code': 30006,
    'message': 'Invalid op_list given',
    'protoVer': 'erased',
    'result': None
}
