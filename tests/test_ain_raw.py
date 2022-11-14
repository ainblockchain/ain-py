import json
import platform
import re
from unittest import TestCase
from snapshottest import TestCase as SnapshotTestCase
from ain.ain import Ain
from ain.provider import JSON_RPC_ENDPOINT
from ain.utils import *
from ain.utils.v3keystore import *
from ain.errors import *
from ain.types import *
from .data import (
    testNode,
    accountSk,
)
from .util import (
    asyncTest,
    getRequest,
    postRequest,
    waitUntilTxFinalized,
    eraseProtoVer,
)

TX_PATTERN = re.compile("0x[0-9a-fA-F]{64}")
PY_VERSION = platform.python_version().replace(".", "")
APP_NAME = "bfan_raw"

class TestCoreRaw(TestCase):
    ain: Ain
    defaultAddr: str
    addr1: str
    addr2: str
    
    @classmethod
    @asyncTest
    async def setUpClass(cls):
        cls.ain = Ain(testNode, 0, AinOptions(rawResultMode=True))
        cls.ain.wallet.addAndSetDefaultAccount(accountSk)
        newAccounts = cls.ain.wallet.create(2)
        cls.defaultAddr = cls.ain.wallet.defaultAccount.address
        cls.addr1 = newAccounts[0]
        cls.addr2 = newAccounts[1]
        getAddr = await getRequest(f"{testNode}/get_address")
        nodeAddr = getAddr["result"]
        stakeForApps = await postRequest(f"{testNode}/set", {
            "op_list": [
                {
                    "type": "SET_VALUE",
                    "ref": f"/staking/test_raw{PY_VERSION}/{nodeAddr}/0/stake/{getTimestamp()}/value",
                    "value": 1
                },
                {
                    "type": "SET_VALUE",
                    "ref": f"/staking/{APP_NAME}{PY_VERSION}/{nodeAddr}/0/stake/{getTimestamp()}/value",
                    "value": 1
                }
            ],
            "nonce": -1
        })
        await waitUntilTxFinalized(testNode, stakeForApps["result"]["tx_hash"])

        createApps = await postRequest(f"{testNode}/set", {
            "op_list": [
                {
                    "type": "SET_VALUE",
                    "ref": f"/manage_app/test_raw{PY_VERSION}/create/{getTimestamp()}",
                    "value": { "admin": { cls.defaultAddr: True } }
                },
                {
                    "type": "SET_VALUE",
                    "ref": f"/manage_app/{APP_NAME}{PY_VERSION}/create/{getTimestamp()}",
                    "value": { "admin": { cls.defaultAddr: True } }
                }
            ],
            "nonce": -1
        })
        await waitUntilTxFinalized(testNode, createApps["result"]["tx_hash"])
    
    @asyncTest
    async def test00ValidateAppNameTrueRaw(self):
        res = await self.ain.validateAppName("test_new")
        self.assertEqual(res["is_valid"], True)
        self.assertEqual(res["result"], True)
        self.assertEqual(res["code"], 0)
        self.assertTrue("protoVer" in res)

    @asyncTest
    async def test00ValidateAppNameFalseRaw(self):
        res = await self.ain.validateAppName("app/path")
        self.assertEqual(res["is_valid"], False)
        self.assertEqual(res["result"], False)
        self.assertEqual(res["code"], 30601)
        self.assertEqual(res["message"], "Invalid app name for state label: app/path")
        self.assertTrue("protoVer" in res)

    @asyncTest
    async def test00SendSignedTransactionRaw(self):
        tx = TransactionBody(
            nonce=-1,
            gas_price=500,
            timestamp=getTimestamp(),
            operation=SetOperation(
                type="SET_OWNER",
                ref=f"/apps/{APP_NAME}{PY_VERSION}",
                value={
                    ".owner": {
                        "owners": {
                            "*": {
                                "write_owner": True,
                                "write_rule": True,
                                "write_function": True,
                                "branch_owner": True
                            }
                        }
                    }
                }
            )
        )

        sig = self.ain.wallet.signTransaction(tx)
        res = await self.ain.sendSignedTransaction(sig, tx)
        targetTxHash = res["result"]["tx_hash"]
        self.assertFalse("code" in res)
        self.assertTrue(TX_PATTERN.fullmatch(targetTxHash) is not None)
        self.assertEqual(res["result"]["result"]["code"], 0)

    @asyncTest
    async def test00SendSignedTransactionInvalidSignatureRaw(self):
        tx = TransactionBody(
            nonce=-1,
            gas_price=500,
            timestamp=getTimestamp(),
            operation=SetOperation(
                type="SET_OWNER",
                ref=f"/apps/{APP_NAME}{PY_VERSION}",
                value={
                    ".owner": {
                        "owners": {
                            "*": {
                                "write_owner": True,
                                "write_rule": True,
                                "write_function": True,
                                "branch_owner": True
                            }
                        }
                    }
                }
            )
        )

        sig = ""
        res = await self.ain.sendSignedTransaction(sig, tx)
        self.assertEqual(res["result"], None)
        self.assertEqual(res["code"], 30302)
        self.assertEqual(res["message"], "Missing properties.")
        self.assertTrue("protoVer" in res)

    @asyncTest
    async def test01SendTransactionBatchRaw(self):
        tx1 = TransactionInput(
            operation=SetOperation(
                type="SET_VALUE",
                ref=f"/apps/{APP_NAME}{PY_VERSION}/users",
                value={ self.defaultAddr: True }
            ),
            address=self.addr1
        )

        tx2 = TransactionInput(
            operation=SetMultiOperation(
                type="SET",
                op_list=[
                    SetOperation(
                        type="SET_OWNER",
                        ref=f"/apps/{APP_NAME}{PY_VERSION}/users",
                        value={
                            ".owner": {
                                "owners": {
                                    "*": {
                                        "write_owner": False,
                                        "write_rule": False,
                                        "write_function": True,
                                        "branch_owner": True
                                    }
                                }
                            }
                        }
                    ),
                    SetOperation(
                        type="SET_OWNER",
                        ref=f"/apps/{APP_NAME}{PY_VERSION}/users/{self.defaultAddr}",
                        value={
                            ".owner": {
                                "owners": {
                                    self.defaultAddr: {
                                        "write_owner": True,
                                        "write_rule": True,
                                        "write_function": True,
                                        "branch_owner": True
                                    }
                                }
                            }
                        }
                    )
                ]
            ),
            address=self.addr2
        )

        tx3 = TransactionInput(
            operation=SetOperation(
                type="SET_RULE",
                ref=f"/apps/{APP_NAME}{PY_VERSION}/users/{self.defaultAddr}",
                value={ ".rule": { "write": f'auth.addr === "{self.defaultAddr}"' } }
            )
        )

        tx4 = TransactionInput(
            operation=SetOperation(
                type="SET_VALUE",
                ref=f"/apps/{APP_NAME}{PY_VERSION}/users/{self.defaultAddr}",
                value=False
            )
        )

        tx5 = TransactionInput(
            operation=SetOperation(
                type="SET_VALUE",
                ref=f"/apps/{APP_NAME}{PY_VERSION}/users/{self.defaultAddr}",
                value=True
            ),
            address=self.addr1
        )

        tx6 = TransactionInput(
            operation=SetOperation(
                type="SET_RULE",
                ref=f"/apps/{APP_NAME}{PY_VERSION}/users/{self.defaultAddr}",
                value={ ".rule": { "write": "true" } }
            ),
            address=self.addr2
        )

        raw = await self.ain.sendTransactionBatch([tx1, tx2, tx3, tx4, tx5, tx6])
        resps = raw["result"]
        for res in resps:
            self.assertTrue(TX_PATTERN.fullmatch(res["tx_hash"]) is not None)
        self.assertEqual(resps[0]["result"]["code"], 12103)
        self.assertEqual(resps[1]["result"]["result_list"]["0"]["code"], 0)
        self.assertEqual(resps[1]["result"]["result_list"]["1"]["code"], 0)
        self.assertEqual(resps[2]["result"]["code"], 0)
        self.assertEqual(resps[3]["result"]["code"], 0)
        self.assertEqual(resps[4]["result"]["code"], 12103)
        self.assertEqual(resps[5]["result"]["code"], 12302)

    @asyncTest
    async def test01SendTransactionBatchWithEmptyListRaw(self):
        res = await self.ain.sendTransactionBatch([])
        self.assertEqual(res["result"], None)
        self.assertEqual(res["code"], 30401)
        self.assertEqual(res["message"], "Invalid batch transaction format.")
        self.assertTrue("protoVer" in res)

class TestDatabaseRaw(SnapshotTestCase):
    ain: Ain
    defaultAddr: str
    allowedPath: str

    @classmethod
    def setUpClass(cls):
        cls.ain = Ain(testNode, 0, AinOptions(rawResultMode=True))
        cls.ain.wallet.addAndSetDefaultAccount(accountSk)
        cls.defaultAddr = cls.ain.wallet.defaultAccount.address
        cls.allowedPath = f"apps/{APP_NAME}{PY_VERSION}/users/{cls.defaultAddr}"
        super(TestDatabaseRaw, cls).setUpClass()

    def matchSnapshot(self, value):
        dump = json.dumps(
            value,
            default=lambda o: o.__dict__,
            separators=(",", ":"),
            sort_keys=True
        ).replace(f'{APP_NAME}{PY_VERSION}', APP_NAME)
        self.assertMatchSnapshot(json.loads(dump))

    def testRef(self):
        self.assertEqual(self.ain.db.ref().path, "/")
        self.assertEqual(self.ain.db.ref(self.allowedPath).path, "/" + self.allowedPath)
    
    @asyncTest
    async def test01GetValue(self):
        res = eraseProtoVer(await self.ain.db.ref(self.allowedPath).getValue())
        self.matchSnapshot(res)
    
    @asyncTest
    async def test01Get(self):
        res = eraseProtoVer(await self.ain.db.ref(self.allowedPath).get([
            GetOperation(
                type="GET_RULE",
                ref=""
            ),
            GetOperation(
                type="GET_VALUE"
            ),
            GetOperation(
                type="GET_VALUE",
                ref="deeper/path"
            )
        ]))
        self.matchSnapshot(res)

    @asyncTest
    async def test01GetWithEmptyList(self):
        res = eraseProtoVer(await self.ain.db.ref(self.allowedPath).get([]))
        self.matchSnapshot(res)
