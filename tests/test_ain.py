import json
import platform
import re
from unittest import TestCase
from snapshottest import TestCase as SnapshotTestCase
from ain.ain import Ain
from ain.ain import Wallet
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
    eraseProtoVer,
    eraseStateVersion,
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
    async def testGetNetworkId(self):
        ain = Ain(testNode)
        self.assertEqual(await ain.net.getNetworkId(), 0)
    
    @asyncTest
    async def testGetChainId(self):
        ain = Ain(testNode)
        self.assertEqual(await ain.net.getChainId(), 0)
    
    @asyncTest
    async def testIsListening(self):
        ain = Ain(testNode)
        self.assertEqual(await ain.net.isListening(), True)
    
    @asyncTest
    async def testIsSyncing(self):
        ain = Ain(testNode)
        self.assertEqual(await ain.net.isSyncing(), False)
    
    @asyncTest
    async def testGetPeerCount(self):
        ain = Ain(testNode)
        self.assertGreater(await ain.net.getPeerCount(), 0)
    
    @asyncTest
    async def testGetConsensusStatus(self):
        ain = Ain(testNode)
        status = await ain.net.getConsensusStatus()
        self.assertIsNotNone(status)
        self.assertEqual(status["state"], "RUNNING")
    
    @asyncTest
    async def testGetRawConsensusStatus(self):
        ain = Ain(testNode)
        status = await ain.net.getRawConsensusStatus()
        self.assertIsNotNone(status)
        self.assertIsNotNone(status["consensus"])
        self.assertEqual(status["consensus"]["state"], "RUNNING")
    
    @asyncTest
    async def testGetPeerCandidateInfo(self):
        ain = Ain(testNode)
        info = await ain.net.getPeerCandidateInfo()
        self.assertIsNotNone(info)
        self.assertIsNotNone(info["address"])
        self.assertEqual(info["isAvailableForConnection"], True)
        self.assertIsNotNone(info["peerCandidateJsonRpcUrlList"])
    
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

class TestProvider(TestCase):
    @asyncTest
    async def testGetAddress(self):
        ain = Ain(testNode)
        res = await ain.provider.getAddress()
        self.assertIsNotNone(res)

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
    async def testGetNonce(self):
        ain = Ain(testNode)
        ain.wallet.addAndSetDefaultAccount(accountSk)
        self.assertEqual(await ain.wallet.getNonce(), 0)

    @asyncTest
    async def testGetTimestamp(self):
        ain = Ain(testNode)
        ain.wallet.addAndSetDefaultAccount(accountSk)
        self.assertEqual(await ain.wallet.getTimestamp(), 0)

    @asyncTest
    async def testTransferIsDryrunTrue(self):
        ain = Ain(testNode)
        ain.wallet.addAndSetDefaultAccount(accountSk)
        balanceBefore = await ain.wallet.getBalance()
        await ain.wallet.transfer(transferAddress, 100, nonce=-1, isDryrun=True)  # isDryrun = True
        balanceAfter = await ain.wallet.getBalance()
        self.assertEqual(balanceBefore, balanceAfter)  # NOT changed!

    @asyncTest
    async def testTransfer(self):
        ain = Ain(testNode)
        ain.wallet.addAndSetDefaultAccount(accountSk)
        balanceBefore = await ain.wallet.getBalance()
        await ain.wallet.transfer(transferAddress, 100, nonce=-1)
        balanceAfter = await ain.wallet.getBalance()
        self.assertEqual(balanceBefore - 100, balanceAfter)

    @asyncTest
    async def testTransferWithAZeroValue(self):
        ain = Ain(testNode)
        ain.wallet.addAndSetDefaultAccount(accountSk)
        balanceBefore = await ain.wallet.getBalance()
        try:
            await ain.wallet.transfer(transferAddress, 0, nonce=-1)  # zero value
            self.fail('should not happen')
        except ValueError as e:
            self.assertEqual(str(e), 'Non-positive transfer value.')
        balanceAfter = await ain.wallet.getBalance()
        self.assertEqual(balanceBefore, balanceAfter)  # NOT changed!

    @asyncTest
    async def testTransferWithANegativeValue(self):
        ain = Ain(testNode)
        ain.wallet.addAndSetDefaultAccount(accountSk)
        balanceBefore = await ain.wallet.getBalance()
        try:
            await ain.wallet.transfer(transferAddress, -0.1, nonce=-1)  # negative value
            self.fail('should not happen')
        except ValueError as e:
            self.assertEqual(str(e), 'Non-positive transfer value.')
        balanceAfter = await ain.wallet.getBalance()
        self.assertEqual(balanceBefore, balanceAfter)  # NOT changed!

    @asyncTest
    async def testTransferWithAValueOfUpTo6Decimals(self):
        ain = Ain(testNode)
        ain.wallet.addAndSetDefaultAccount(accountSk)
        balanceBefore = await ain.wallet.getBalance()
        await ain.wallet.transfer(transferAddress, 0.000001, nonce=-1)  # of 6 decimals
        balanceAfter = await ain.wallet.getBalance()
        self.assertEqual(balanceBefore - 0.000001, balanceAfter)

    @asyncTest
    async def testTransferWithAValueOfMoreThan6Decimals(self):
        ain = Ain(testNode)
        ain.wallet.addAndSetDefaultAccount(accountSk)
        balanceBefore = await ain.wallet.getBalance()
        try:
            await ain.wallet.transfer(transferAddress, 0.0000001, nonce=-1)  # of 7 decimals
            self.fail('should not happen')
        except ValueError as e:
            self.assertEqual(str(e), 'Transfer value of more than 6 decimals.')
        balanceAfter = await ain.wallet.getBalance()
        self.assertEqual(balanceBefore, balanceAfter)  # NOT changed!

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
    async def test00GetLastBlock(self):
        block = await self.ain.getLastBlock()
        self.assertIsNotNone(block)
        hash = block.get("hash", "")
        self.assertIsNotNone(hash)
        number = block.get("number", 0)
        self.assertGreater(number, 0)

    @asyncTest
    async def test00GetLastBlockNumber(self):
        number = await self.ain.getLastBlockNumber()
        self.assertGreater(number, 0)

    @asyncTest
    async def test00GetBlockByNumber(self):
        lastBlock = await self.ain.getLastBlock()
        self.assertIsNotNone(lastBlock)
        self.assertIsNotNone(lastBlock["number"])
        block = await self.ain.getBlockByNumber(lastBlock["number"])
        self.assertIsNotNone(block)
        self.assertEqual(block["number"], lastBlock["number"])
        self.assertEqual(block["hash"], lastBlock["hash"])

    @asyncTest
    async def test00GetBlockByHash(self):
        lastBlock = await self.ain.getLastBlock()
        self.assertIsNotNone(lastBlock)
        self.assertIsNotNone(lastBlock["hash"])
        block = await self.ain.getBlockByHash(lastBlock["hash"])
        self.assertIsNotNone(block)
        self.assertEqual(block["number"], lastBlock["number"])
        self.assertEqual(block["hash"], lastBlock["hash"])

    @asyncTest
    async def test00GetBlockList(self):
        lastBlockNumber = await self.ain.getLastBlockNumber()
        self.assertIsNotNone(lastBlockNumber)
        self.assertGreaterEqual(lastBlockNumber, 0)
        blockList = await self.ain.getBlockList(lastBlockNumber - 1, lastBlockNumber + 1)
        self.assertIsNotNone(blockList)
        self.assertEqual(len(blockList), 2)
        self.assertEqual(blockList[0]["number"], lastBlockNumber - 1)
        self.assertEqual(blockList[1]["number"], lastBlockNumber)

    @asyncTest
    async def test00GetBlockHeadersList(self):
        lastBlockNumber = await self.ain.getLastBlockNumber()
        self.assertIsNotNone(lastBlockNumber)
        self.assertGreaterEqual(lastBlockNumber, 0)
        blockList = await self.ain.getBlockHeadersList(lastBlockNumber - 1, lastBlockNumber + 1)
        self.assertIsNotNone(blockList)
        self.assertEqual(len(blockList), 2)
        self.assertEqual(blockList[0]["number"], lastBlockNumber - 1)
        self.assertEqual(blockList[1]["number"], lastBlockNumber)

    @asyncTest
    async def test00GetBlockTransactionCountByNumber(self):
        lastBlockNumber = await self.ain.getLastBlockNumber()
        self.assertIsNotNone(lastBlockNumber)
        self.assertGreaterEqual(lastBlockNumber, 0)
        txCount = await self.ain.getBlockTransactionCountByNumber(lastBlockNumber)
        self.assertIsNotNone(txCount)

    @asyncTest
    async def test00GetBlockTransactionCountByHash(self):
        lastBlock= await self.ain.getLastBlock()
        self.assertIsNotNone(lastBlock)
        self.assertIsNotNone(lastBlock["hash"])
        txCount = await self.ain.getBlockTransactionCountByHash(lastBlock["hash"])
        self.assertIsNotNone(txCount)

    @asyncTest
    async def test00GetValidatorInfo(self):
        lastBlock= await self.ain.getLastBlock()
        self.assertIsNotNone(lastBlock)
        self.assertIsNotNone(lastBlock["proposer"])
        validatorInfo = await self.ain.getValidatorInfo(lastBlock["proposer"])
        self.assertIsNotNone(validatorInfo)

    @asyncTest
    async def test00GetValidatorsByNumber(self):
        lastBlock= await self.ain.getLastBlock()
        self.assertIsNotNone(lastBlock)
        self.assertIsNotNone(lastBlock["number"])
        validators = await self.ain.getValidatorsByNumber(lastBlock["number"])
        self.assertDictEqual(validators, lastBlock["validators"])
    
    @asyncTest
    async def test00GetValidatorsByHash(self):
        lastBlock= await self.ain.getLastBlock()
        self.assertIsNotNone(lastBlock)
        self.assertIsNotNone(lastBlock["hash"])
        validators = await self.ain.getValidatorsByHash(lastBlock["hash"])
        self.assertDictEqual(validators, lastBlock["validators"])
    
    @asyncTest
    async def test00GetProposerByNumber(self):
        lastBlock= await self.ain.getLastBlock()
        self.assertIsNotNone(lastBlock)
        self.assertIsNotNone(lastBlock["number"])
        proposer = await self.ain.getProposerByNumber(lastBlock["number"])
        self.assertEqual(proposer, lastBlock["proposer"])
    
    @asyncTest
    async def test00GetProposerByHash(self):
        lastBlock= await self.ain.getLastBlock()
        self.assertIsNotNone(lastBlock)
        self.assertIsNotNone(lastBlock["hash"])
        proposer = await self.ain.getProposerByHash(lastBlock["hash"])
        self.assertEqual(proposer, lastBlock["proposer"])

    @asyncTest
    async def test00GetStateUsage(self):
        # with an app that does not exist yet
        erased = eraseProtoVer(await self.ain.getStateUsage("test_new"))
        self.assertIsNotNone(erased["available"])
        self.assertIsNotNone(erased["usage"])
        self.assertIsNotNone(erased["staking"])

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
    async def test00SendTransactionIsDryrunTrue(self):
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
        res = await self.ain.sendTransaction(TransactionInput(operation=op), True)  # isDryrun = True
        self.assertEqual(res["result"]["code"], 0)
        targetTxHash = res["tx_hash"]
        self.assertTrue(TX_PATTERN.fullmatch(targetTxHash) is not None)

        tx = await self.ain.getTransactionByHash(targetTxHash)
        self.assertIsNone(tx)  # should be None

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

        tx = await self.ain.getTransactionByHash(targetTxHash)
        self.assertDictEqual(tx["transaction"]["tx_body"]["operation"], op.__dict__)

    @asyncTest
    async def test00SendSignedTransactionIsDryrunTrue(self):
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
        res = await self.ain.sendSignedTransaction(sig, tx, True)  # isDryrun = True
        targetTxHash = res["tx_hash"]
        self.assertFalse("code" in res)
        self.assertTrue(TX_PATTERN.fullmatch(targetTxHash) is not None)
        self.assertEqual(res["result"]["code"], 0)

        tx = await self.ain.getTransactionByHash(targetTxHash)
        self.assertIsNone(tx)  # should be None

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

    @asyncTest
    async def test01GetPendingTransactions(self):
        res = await self.ain.getPendingTransactions()
        self.assertIsNotNone(res)

    @asyncTest
    async def test01GetTransactionPoolSizeUtilization(self):
        res = await self.ain.getTransactionPoolSizeUtilization()
        self.assertIsNotNone(res)

    @asyncTest
    async def test01GetTransactionByBlockHashAndIndex(self):
        genesisBlockNumber = 0
        genesisBlock = await self.ain.getBlockByNumber(genesisBlockNumber)
        res = await self.ain.getTransactionByBlockHashAndIndex(genesisBlock["hash"], 0)
        self.assertIsNotNone(res)

    @asyncTest
    async def test01GetTransactionByBlockNumberAndIndex(self):
        genesisBlockNumber = 0
        res = await self.ain.getTransactionByBlockNumberAndIndex(genesisBlockNumber, 0)
        self.assertIsNotNone(res)

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
    async def test00SetOwnerIsDryrunTrue(self):
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
        ),
        True)
        self.assertEqual(res["result"]["code"], 0)
        self.assertEqual(res["result"]["is_dryrun"], True)

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
        ),
        True)
        self.assertEqual(fail["result"]["code"], 12501)
        self.assertEqual(fail["result"]["is_dryrun"], True)

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
    async def test00SetRuleIsDryrunTrue(self):
        res = await self.ain.db.ref(self.allowedPath).setRule(ValueOnlyTransactionInput(
            value={ ".rule": { "write": "true" } }
        ),
        True)
        self.assertEqual(res["result"]["code"], 0)
        self.assertEqual(res["result"]["is_dryrun"], True)

    @asyncTest
    async def test00SetRuleIsDryrunTrue(self):
        res = await self.ain.db.ref(self.allowedPath).setRule(ValueOnlyTransactionInput(
            value={ ".rule": { "write": "true" } }
        ),
        True)
        self.assertEqual(res["result"]["code"], 0)
        self.assertEqual(res["result"]["is_dryrun"], True)

    @asyncTest
    async def test00SetRule(self):
        res = await self.ain.db.ref(self.allowedPath).setRule(ValueOnlyTransactionInput(
            value={ ".rule": { "write": "true" } }
        ))
        self.assertEqual(res["result"]["code"], 0)

    @asyncTest
    async def test00SetValueIsDryrunTrue(self):
        res = await self.ain.db.ref(f"{self.allowedPath}/username").setValue(ValueOnlyTransactionInput(
            value="test_user"
        ),
        True)
        self.assertEqual(res["result"]["code"], 0)
        self.assertEqual(res["result"]["is_dryrun"], True)

    @asyncTest
    async def test00SetValue(self):
        res = await self.ain.db.ref(f"{self.allowedPath}/username").setValue(ValueOnlyTransactionInput(
            value="test_user"
        ))
        self.assertEqual(res["result"]["code"], 0)

    @asyncTest
    async def test00SetFunctionIsDryrunTrue(self):
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
        ),
        True)
        self.assertEqual(res["result"]["code"], 0)
        self.assertEqual(res["result"]["is_dryrun"], True)

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
    async def test00SetIsDryrunTrue(self):
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
        ),
        True)
        self.assertEqual(len(res["result"]["result_list"].keys()), 4)
        self.assertEqual(res["result"]["is_dryrun"], True)

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
    async def test02DeleteValueIsDryrunTrue(self):
        res = await self.ain.db.ref(f"{self.allowedPath}/can/write").deleteValue(isDryrun=True)
        self.assertEqual(res["result"]["code"], 0)
        self.assertEqual(res["result"]["is_dryrun"], True)

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
    
    @asyncTest
    async def test03GetStateProof(self):
        self.assertIsNotNone(await self.ain.db.ref('/values/blockchain_params').getStateProof())
    
    @asyncTest
    async def test03GetStateProofWithInput(self):
        self.assertIsNotNone(await self.ain.db.ref('/values/blockchain_params').getStateProof(StateInfoInput(
            ref="resource"
        )))

    @asyncTest
    async def test03GetProofHash(self):
        self.matchSnapshot(await self.ain.db.ref('/values/blockchain_params').getProofHash())

    @asyncTest
    async def test03GetStateInfo(self):
        self.matchSnapshot(eraseStateVersion(await self.ain.db.ref('/rules/transfer/$from/$to/$key/value').getStateInfo()))

