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
    mnemonic,
    message,
    v3KeystorePassword,
    v3KeystoreJSONList,
    tx,
    testNode,
    accountAddress,
    accountSk,
    transferAddress,
)
from .util import (
    asyncTest,
    getRequest,
    postRequest,
    waitUntilTxFinalized,
)

TX_PATTERN = re.compile("0x[0-9a-fA-F]{64}")
PY_VERSION = platform.python_version().replace(".", "")
APP_NAME = "bfan"

class TestNetwork(TestCase):
    def testChainId(self):
        ain = Ain(testNode)
        self.assertEqual(ain.chainId, 0)
        self.assertEqual(ain.wallet.chainId, 0)
        ain.setProvider(testNode, 2)
        self.assertEqual(ain.chainId, 2)
        self.assertEqual(ain.wallet.chainId, 2)

    def testSanitizeProviderURL(self):
        ain = Ain(testNode)
        with self.assertRaises(ValueError):
            ain.setProvider("")
        with self.assertRaises(ValueError):
            ain.setProvider("localhost:3000")
        noTrailingSlash = "http://localhost:3000"
        ain.setProvider(noTrailingSlash)
        self.assertEqual(ain.provider.apiEndPoint, noTrailingSlash + "/" + JSON_RPC_ENDPOINT)
        ain.setProvider(noTrailingSlash + "/")
        self.assertEqual(ain.provider.apiEndPoint, noTrailingSlash + "/" + JSON_RPC_ENDPOINT)

    @asyncTest
    async def testGetProtocolVersion(self):
        ain = Ain(testNode)
        self.assertNotEqual(await ain.net.getProtocolVersion(), None)
    
    @asyncTest
    async def testCheckProtocolVersion(self):
        ain = Ain(testNode)
        res = await ain.net.checkProtocolVersion()
        self.assertEqual(res["code"], 0)
        self.assertEqual(res["result"], True)

class TestWallet(TestCase):
    def testCreateAccount(self):
        ain = Ain(testNode)
        ain.wallet.create(2)
        self.assertEqual(ain.wallet.length, 2)

    def testAddFromV3Keystore(self):
        ain = Ain(testNode)
        keystoreAddress = ain.wallet.addFromV3Keystore(v3KeystoreJSONList[0], v3KeystorePassword)
        self.assertEqual(ain.wallet.length, 1)
        convertedV3Keystore = ain.wallet.accountToV3Keystore(keystoreAddress, v3KeystorePassword)
        derivedAddress = privateToAddress(convertedV3Keystore.toPrivateKey(v3KeystorePassword))
        self.assertEqual(derivedAddress, keystoreAddress)

    def testAddAccount(self):
        ain = Ain(testNode)
        ain.wallet.add(accountSk)
        self.assertEqual(ain.wallet.length, 1)
        with self.assertRaises(ValueError):
            ain.wallet.add("")
        self.assertEqual(ain.wallet.length, 1)

    def testAddAndSetDefaultAccount(self):
        ain = Ain(testNode)
        ain.wallet.addAndSetDefaultAccount(accountSk)
        self.assertEqual(ain.wallet.defaultAccount.private_key, accountSk)

    def testAddFromHDWallet(self):
        ain = Ain(testNode)
        ain.wallet.addFromHDWallet(mnemonic)
        self.assertEqual(ain.wallet.length, 1)

    def testRemoveAccount(self):
        ain = Ain(testNode)
        ain.wallet.add(accountSk)
        self.assertEqual(ain.wallet.length, 1)
        ain.wallet.remove(accountAddress)
        self.assertEqual(ain.wallet.length, 0)

    def testClearAccount(self):
        ain = Ain(testNode)
        ain.wallet.add(accountSk)
        ain.wallet.addFromHDWallet(mnemonic)
        self.assertEqual(ain.wallet.length, 2)
        ain.wallet.clear()
        self.assertEqual(ain.wallet.length, 0)

    def testSetDefaultAccount(self):
        ain = Ain(testNode)
        with self.assertRaises(ValueError):
            ain.wallet.setDefaultAccount(accountAddress)
        ain.wallet.add(accountSk)
        ain.wallet.setDefaultAccount(accountAddress.lower())
        self.assertEqual(ain.wallet.defaultAccount.address, accountAddress)
        ain.wallet.setDefaultAccount(accountAddress)
        self.assertEqual(ain.wallet.defaultAccount.address, accountAddress)
    
    def testRemoveDefaultAccount(self):
        ain = Ain(testNode)
        ain.wallet.addAndSetDefaultAccount(accountSk)
        self.assertEqual(ain.wallet.defaultAccount.private_key, accountSk)
        ain.wallet.removeDefaultAccount()
        self.assertEqual(ain.wallet.defaultAccount, None)

    def testSign(self):
        ain = Ain(testNode)
        with self.assertRaises(ValueError):
            ain.wallet.sign(message)
        ain.wallet.addAndSetDefaultAccount(accountSk)
        sig = ain.wallet.sign(message)
        self.assertEqual(ecVerifySig(message, sig, accountAddress), True)

    def testSignTransaction(self):
        ain = Ain(testNode)
        ain.wallet.addAndSetDefaultAccount(accountSk)
        sig = ain.wallet.signTransaction(tx)
        self.assertEqual(ain.wallet.verifySignature(tx, sig, accountAddress), True)
        self.assertEqual(ain.wallet.recover(sig), accountAddress)

    @asyncTest
    async def testGetBalance(self):
        ain = Ain(testNode)
        ain.wallet.addAndSetDefaultAccount(accountSk)
        self.assertGreaterEqual(await ain.wallet.getBalance(), 0)

    @asyncTest
    async def testTransfer(self):
        ain = Ain(testNode)
        ain.wallet.addAndSetDefaultAccount(accountSk)
        balanceBefore = await ain.wallet.getBalance()
        await ain.wallet.transfer(transferAddress, 100, nonce=-1)
        balanceAfter = await ain.wallet.getBalance()
        self.assertEqual(balanceBefore - 100, balanceAfter)

    def testChainId(self):
        ain = Ain(testNode, 0)
        ain.wallet.addAndSetDefaultAccount(accountSk)

        sig = ain.wallet.signTransaction(tx)
        self.assertEqual(ain.wallet.verifySignature(tx, sig, accountAddress), True)
        self.assertEqual(ecVerifySig(tx, sig, accountAddress, 2), False)
        self.assertEqual(ain.wallet.recover(sig), accountAddress)

        ain.setProvider(testNode, 2)
        sig = ain.wallet.signTransaction(tx)
        self.assertEqual(ain.wallet.verifySignature(tx, sig, accountAddress), True)
        self.assertEqual(ecVerifySig(tx, sig, accountAddress, 0), False)
        self.assertEqual(ain.wallet.recover(sig), accountAddress)
            
class TestCore(TestCase):
    ain: Ain
    defaultAddr: str
    addr1: str
    addr2: str
    
    @classmethod
    @asyncTest
    async def setUpClass(cls):
        cls.ain = Ain(testNode, 0)
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
                    "ref": f"/staking/test{PY_VERSION}/{nodeAddr}/0/stake/{getTimestamp()}/value",
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
                    "ref": f"/manage_app/test{PY_VERSION}/create/{getTimestamp()}",
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
    async def test00GetBlock(self):
        block = await self.ain.getBlock(3)
        hash = block.get("hash", "")
        self.assertDictEqual(await self.ain.getBlock(hash), block)

    @asyncTest
    async def test00GetProposer(self):
        proposer = await self.ain.getProposer(1)
        block = await self.ain.getBlock(1)
        hash = block.get("hash", "")
        self.assertEqual(await self.ain.getProposer(hash), proposer)

    @asyncTest
    async def test00GetValidators(self):
        validators = await self.ain.getValidators(4)
        block = await self.ain.getBlock(4)
        hash = block.get("hash", "")
        self.assertDictEqual(await self.ain.getValidators(hash), validators)

    @asyncTest
    async def test00ValidateAppNameTrue(self):
        res = await self.ain.validateAppName("test_new")
        self.assertEqual(res["is_valid"], True)
        self.assertEqual(res["result"], True)
        self.assertEqual(res["code"], 0)
        self.assertTrue("protoVer" in res)

    @asyncTest
    async def test00ValidateAppNameFalse(self):
        raised = False
        try:
            await self.ain.validateAppName("app/path")
        except BlockchainError as e:
            self.assertEqual(e.code, 30601)
            self.assertEqual(e.message, "Invalid app name for state label: app/path")
            raised = True
        self.assertTrue(raised)

    @asyncTest
    async def test00SendTransaction(self):
        op = SetOperation(
            type="SET_OWNER",
            ref=f"/apps/test{PY_VERSION}",
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
        res = await self.ain.sendTransaction(TransactionInput(operation=op))
        self.assertEqual(res["result"]["code"], 0)
        targetTxHash = res["tx_hash"]
        self.assertTrue(TX_PATTERN.fullmatch(targetTxHash) is not None)

        tx = await self.ain.getTransaction(targetTxHash)
        self.assertDictEqual(tx["transaction"]["tx_body"]["operation"], op.__dict__)

    @asyncTest
    async def test00SendSignedTransaction(self):
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
        targetTxHash = res["tx_hash"]
        self.assertFalse("code" in res)
        self.assertTrue(TX_PATTERN.fullmatch(targetTxHash) is not None)
        self.assertEqual(res["result"]["code"], 0)

    @asyncTest
    async def test00SendSignedTransactionInvalidSignature(self):
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
        raised = False
        try:
            await self.ain.sendSignedTransaction(sig, tx)
        except BlockchainError as e:
            self.assertEqual(e.code, 30302)
            self.assertEqual(e.message, "Missing properties.")
            raised = True
        self.assertTrue(raised)

    @asyncTest
    async def test01SendTransactionBatch(self):
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

        resps = await self.ain.sendTransactionBatch([tx1, tx2, tx3, tx4, tx5, tx6])
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
    async def test01SendTransactionBatchWithEmptyList(self):
        raised = False
        try:
            await self.ain.sendTransactionBatch([])
        except BlockchainError as e:
            self.assertEqual(e.code, 30401)
            self.assertEqual(e.message, "Invalid batch transaction format.")
            raised = True
        self.assertTrue(raised)

class TestDatabase(SnapshotTestCase):
    ain: Ain
    defaultAddr: str
    allowedPath: str

    @classmethod
    def setUpClass(cls):
        cls.ain = Ain(testNode, 0)
        cls.ain.wallet.addAndSetDefaultAccount(accountSk)
        cls.defaultAddr = cls.ain.wallet.defaultAccount.address
        cls.allowedPath = f"apps/{APP_NAME}{PY_VERSION}/users/{cls.defaultAddr}"
        super(TestDatabase, cls).setUpClass()

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
    async def test00SetOwner(self):
        res = await self.ain.db.ref(self.allowedPath).setOwner(ValueOnlyTransactionInput(
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
        ))
        self.assertEqual(res["result"]["code"], 0)

        fail = await self.ain.db.ref("/consensus").setOwner(ValueOnlyTransactionInput(
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
        ))
        self.assertEqual(fail["result"]["code"], 12501)

    @asyncTest
    async def test00SetRule(self):
        res = await self.ain.db.ref(self.allowedPath).setRule(ValueOnlyTransactionInput(
            value={ ".rule": { "write": "true" } }
        ))
        self.assertEqual(res["result"]["code"], 0)

    @asyncTest
    async def test00SetValue(self):
        res = await self.ain.db.ref(f"{self.allowedPath}/username").setValue(ValueOnlyTransactionInput(
            value="test_user"
        ))
        self.assertEqual(res["result"]["code"], 0)

    @asyncTest
    async def test00SetFunction(self):
        res = await self.ain.db.ref(self.allowedPath).setFunction(ValueOnlyTransactionInput(
            value={
                ".function": {
                    "0xFUNCTION_HASH": {
                        "function_url": "https://events.ainetwork.ai/trigger",
                        "function_id": "0xFUNCTION_HASH",
                        "function_type": "REST"
                    }
                }
            }
        ))
        self.assertEqual(res["result"]["code"], 0)

    @asyncTest
    async def test00Set(self):
        res = await self.ain.db.ref(self.allowedPath).set(SetMultiTransactionInput(
            op_list=[
                SetOperation(
                    type="SET_RULE",
                    ref="can/write/",
                    value={ ".rule": { "write": "true" } }
                ),
                SetOperation(
                    type="SET_RULE",
                    ref="cannot/write",
                    value={ ".rule": { "write": "false" } }
                ),
                SetOperation(
                    type="INC_VALUE",
                    ref="can/write/",
                    value=5
                ),
                SetOperation(
                    type="DEC_VALUE",
                    ref="can/write",
                    value=10
                )
            ],
            nonce=-1
        ))
        self.assertEqual(len(res["result"]["result_list"].keys()), 4)

    @asyncTest
    async def test01GetValue(self):
        self.matchSnapshot(await self.ain.db.ref(self.allowedPath).getValue())
    
    @asyncTest
    async def test01GetRule(self):
        self.matchSnapshot(await self.ain.db.ref(self.allowedPath).getRule())
    
    @asyncTest
    async def test01GetOwner(self):
        self.matchSnapshot(await self.ain.db.ref(self.allowedPath).getOwner())
    
    @asyncTest
    async def test01GetFunction(self):
        self.matchSnapshot(await self.ain.db.ref(self.allowedPath).getFunction())

    @asyncTest
    async def test01Get(self):
        self.matchSnapshot(await self.ain.db.ref(self.allowedPath).get([
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

    @asyncTest
    async def test01GetWithEmptyList(self):
        raised = False
        try:
            await self.ain.db.ref(self.allowedPath).get([])
        except BlockchainError as e:
            self.assertEqual(e.code, 30006)
            self.assertEqual(e.message, "Invalid op_list given")
            raised = True
        self.assertTrue(raised)

    @asyncTest
    async def test01GetWithOptions(self):
        self.matchSnapshot(await self.ain.db.ref().getValue(self.allowedPath, GetOptions(is_final=True)))
        self.matchSnapshot(await self.ain.db.ref().getValue(self.allowedPath, GetOptions(is_global=True)))
        self.matchSnapshot(await self.ain.db.ref().getValue(self.allowedPath, GetOptions(is_shallow=True)))
        self.matchSnapshot(await self.ain.db.ref().getValue(self.allowedPath, GetOptions(include_proof=True)))
        self.matchSnapshot(await self.ain.db.ref().getValue(self.allowedPath, GetOptions(include_tree_info=True)))
        getWithVersion = await self.ain.db.ref().getValue(self.allowedPath, GetOptions(include_version=True))
        self.assertTrue("#version" in getWithVersion)

    @asyncTest
    async def test02DeleteValue(self):
        res = await self.ain.db.ref(f"{self.allowedPath}/can/write").deleteValue()
        self.assertEqual(res["result"]["code"], 0)

    @asyncTest
    async def test03EvalRuleTrue(self):
        res = await self.ain.db.ref(self.allowedPath).evalRule(EvalRuleInput(
            ref="/can/write",
            value="hi"
        ))
        self.assertEqual(res["code"], 0)
        self.matchSnapshot(res)

    @asyncTest
    async def test03EvalRuleFalse(self):
        res = await self.ain.db.ref(self.allowedPath).evalRule(EvalRuleInput(
            ref="/cannot/write",
            value="hi"
        ))
        self.assertEqual(res["code"], 12103)

    @asyncTest
    async def test03EvalOwner(self):
        self.matchSnapshot(await self.ain.db.ref(self.allowedPath).evalOwner(EvalOwnerInput(
            permission="branch_owner"
        )))

    @asyncTest
    async def test03MatchFunction(self):
        self.matchSnapshot(await self.ain.db.ref(self.allowedPath).matchFunction())
    
    @asyncTest
    async def test03MatchRule(self):
        self.matchSnapshot(await self.ain.db.ref(self.allowedPath).matchRule())
    
    @asyncTest
    async def test03MatchOwner(self):
        self.matchSnapshot(await self.ain.db.ref(self.allowedPath).matchOwner())
    
