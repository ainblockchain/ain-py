from typing import Union
from ain.provider import Provider
from ain.net import Network
from ain.wallet import Wallet
from ain.types import TransactionInput, TransactionBody
from ain.ain_db.db import Database
from ain.utils import getTimestamp, toChecksumAddress

class Ain:
    provider: Provider
    chainId: int
    db: Database
    net: Network
    wallet: Wallet

    def __init__(self, providerUrl: str, chainId: int = 0):
        self.provider = Provider(self, providerUrl)
        self.chainId = chainId
        self.net = Network(self.provider)
        self.wallet = Wallet(self, self.chainId)
        self.db = Database(self, self.provider)

    def setProvider(self, providerUrl: str, chainId: int = 0):
        """
        Sets a new provider
        """
        self.provider = Provider(self, providerUrl)
        self.chainId = chainId
        self.net = Network(self.provider)
        self.wallet = Wallet(self, self.chainId)
        self.db = Database(self, self.provider)

    # TODO(kriii): Return objects typing.

    async def getBlock(
        self,
        blockHashOrBlockNumber: Union[str, int],
        returnTransactionObjects: bool = False,
    ):
        """
        A coroutine returns a block with the given hash or block number.

        args:
            blockHashOrBlockNumber (Union[str, int]):
                Block hash or block number
            returnTransactionObjects (bool):
                If true, returns the full transaction objects;
                otherwise, returns only the transaction hashes
        """
        if type(blockHashOrBlockNumber) is str:
            return await self.provider.send(
                "ain_getBlockByHash",
                {
                    "getFullTransactions": returnTransactionObjects,
                    "hash": blockHashOrBlockNumber,
                },
            )
        elif type(blockHashOrBlockNumber) is int:
            return await self.provider.send(
                "ain_getBlockByNumber",
                {
                    "getFullTransactions": returnTransactionObjects,
                    "number": blockHashOrBlockNumber,
                },
            )
        else:
            raise TypeError("blockHashOrBlockNumber has invalid type")

    async def getProposer(
        self,
        blockHashOrBlockNumber: Union[str, int],
    ) -> str:
        """
        A coroutine returns the address of the forger of given block
        """
        if type(blockHashOrBlockNumber) is str:
            return await self.provider.send(
                "ain_getProposerByHash", {"hash": blockHashOrBlockNumber}
            )
        elif type(blockHashOrBlockNumber) is int:
            return await self.provider.send(
                "ain_getProposerByNumber", {"number": blockHashOrBlockNumber}
            )
        else:
            raise TypeError("blockHashOrBlockNumber has invalid type")

    async def getValidators(
        self,
        blockHashOrBlockNumber: Union[str, int],
    ):
        """
        A coroutine returns the list of validators for a given block
        """
        if type(blockHashOrBlockNumber) is str:
            return await self.provider.send(
                "ain_getValidatorsByHash", {"hash": blockHashOrBlockNumber}
            )
        elif type(blockHashOrBlockNumber) is int:
            return await self.provider.send(
                "ain_getValidatorsByNumber", {"number": blockHashOrBlockNumber}
            )
        else:
            raise TypeError("blockHashOrBlockNumber has invalid type")

    async def getTransaction(self, transactionHash: str):
        """
        Returns the transaction with the given transaction hash.
        """
        return await self.provider.send(
            "ain_getTransactionByHash", {"hash": transactionHash}
        )

    async def getStateUsage(self, appName: str):
        """
        Returns the transaction with the given transaction hash.
        """
        return await self.provider.send(
            "ain_getStateUsage", {"app_name": appName}
        )

    async def sendTransaction(self, transactionObject: TransactionInput):
        """
        Signs and sends a transaction to the network
        """
        txBody = await self.buildTransactionBody(transactionObject)
        signature = self.wallet.signTransaction(
            txBody, getattr(transactionObject, "address", None)
        )
        return await self.sendSignedTransaction(signature, txBody)

    async def sendSignedTransaction(self, signature: str, txBody: TransactionBody):
        """
        Sends a signed transaction to the network
        """
        return await self.provider.send(
            "ain_sendSignedTransaction", {"signature": signature, "tx_body": txBody}
        )

    # TODO(kriii): implement this function.
    async def sendTransactionBatch(self):
        """
        Sends signed transactions to the network.
        """
        pass

    # TODO(kriii): implement this function.
    def depositConsensusStake(self):
        """
        Sends a transaction that deposits AIN for consensus staking.
        """
        pass

    # TODO(kriii): implement this function.
    def withdrawConsensusStake(self):
        """
        Sends a transaction that withdraws AIN for consensus staking.
        """
        pass

    async def getConsensusStakeAmount(self, account: str = None) -> int:
        """
        Gets the amount of AIN currently staked for participating in consensus protocol.
        """
        if account is None:
            address = self.wallet.getImpliedAddress()
        else:
            address = toChecksumAddress(account)
        return await self.db.ref(f"/deposit_accounts/consensus/{address}").getValue()

    async def getNonce(self, args: dict) -> int:
        """
        Returns the current transaction count of account, which is the nonce of the account.

        Args:
            args: May contain a string 'address' and a string 'from' values.
                The 'address' indicates the address of the account to get the
                nonce of, and the 'from' indicates where to get the nonce from.
                It could be either the pending transaction pool ("pending") or
                the committed blocks ("committed"). The default value is "committed".
        """
        params = dict(args)
        if "address" in args:
            params["address"] = toChecksumAddress(args["address"])
        else:
            params["address"] = self.wallet.getImpliedAddress()

        if "from" in args:
            if args["from"] != "pending" and args["from"] != "committed":
                raise ValueError("'from' should be either 'pending' or 'committed'")

        ret = await self.provider.send("ain_getNonce", params)
        return ret

    async def buildTransactionBody(
        self, transactionInput: TransactionInput
    ) -> TransactionBody:
        """
        Builds a transaction body from transaction input.
        """
        address = self.wallet.getImpliedAddress(
            getattr(transactionInput, "address", None)
        )
        operation = transactionInput.operation
        parent_tx_hash = getattr(transactionInput, "parent_tx_hash", None)
        nonce = getattr(transactionInput, "nonce", None)
        if nonce is None:
            nonce = await self.getNonce({"address": address, "from": "pending"})
        timestamp = getattr(transactionInput, "timestamp", getTimestamp())
        gas_price = getattr(transactionInput, "gas_price", 0)
        billing = getattr(transactionInput, "billing", None)

        return TransactionBody(
            operation=operation,
            parent_tx_hash=parent_tx_hash,
            nonce=nonce,
            timestamp=timestamp,
            gas_price=gas_price,
            billing=billing,
        )

    # TODO(kriii): implement this function.
    def __stakeFunction(self):
        """
        A base function for all staking related database changes. It builds a
        deposit/withdraw transaction and sends the transaction by calling sendTransaction().
        """
        pass