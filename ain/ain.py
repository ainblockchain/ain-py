from typing import List, Any, Union
from ain.provider import Provider
from ain.net import Network
from ain.wallet import Wallet
from ain.types import AinOptions, TransactionInput, TransactionBody, ValueOnlyTransactionInput
from ain.db import Database
from ain.signer import Signer
from ain.signer.default_signer import DefaultSigner
from ain.utils import getTimestamp, toChecksumAddress

class Ain:
    """Class for the `Ain` instance, the interactor for the AIN Blockchain.

    Args:
        providerUrl (str): The URL of the provider, the listening blockchain node.
        chainId (int): The chain ID of the provider. Defaults to 0.
        ainOptions (AinOptions): The options for this `Ain` instance. Defaults to no options.
    """
    
    provider: Provider
    """The `Provider` instance."""
    chainId: int
    """The chain ID of the provider."""
    rawResultMode: bool
    """The flag of the raw result mode."""
    db: Database
    """The `Database` instance."""
    net: Network
    """The `Network` instance."""
    wallet: Wallet
    """The `Wallet` instance."""
    signer: Signer
    """The `Signer` instance."""

    def __init__(self, providerUrl: str, chainId: int = 0, ainOptions: AinOptions = AinOptions()):
        self.provider = Provider(self, providerUrl)
        self.chainId = chainId
        self.rawResultMode = getattr(ainOptions, "rawResultMode", False)
        self.net = Network(self.provider)
        self.wallet = Wallet(self, self.chainId)
        self.db = Database(self, self.provider)
        self.signer = DefaultSigner(self.wallet, self.provider)

    def setProvider(self, providerUrl: str, chainId: int = 0):
        """Sets a new provider

        Args:
            providerUrl (str): The URL of the new provider.
            chainId (int): The chain ID of the new provider. Defaults to 0.
        """
        self.provider = Provider(self, providerUrl)
        self.chainId = chainId
        self.net = Network(self.provider)
        self.wallet.chainId = chainId
        self.db = Database(self, self.provider)

    def setSigner(self, signer: Signer):
        """Sets a new signer

        Args:
            signer (Signer): The signer to set.
        """
        self.signer = signer

    # TODO(kriii): Return objects typing.

    async def getLastBlock(self) -> Any:
        """Fetches the last block.

        Args:

        Returns:
            The last block.
        """
        return await self.provider.send(
            "ain_getLastBlock", {}
        )

    async def getLastBlockNumber(self) -> int:
        """Fetches the last block number.

        Args:

        Returns:
            The last block number.
        """
        return await self.provider.send(
            "ain_getLastBlockNumber", {}
        )

    async def getBlockByNumber(
        self,
        blockNumber: int,
        returnTransactionObjects: bool = False,
    ) -> Any:
        """Gets a block with the given block number.

        Args:
            blockNumber (int): The block number.
            returnTransactionObjects (bool): If `True`, returns the full transaction objects.
                If `False`, returns only the transaction hashes. Default to `False`.
        
        Returns:
            The block with the given block number.
        """
        return await self.provider.send(
            "ain_getBlockByNumber",
            {
                "getFullTransactions": returnTransactionObjects,
                "number": blockNumber,
            },
        )

    async def getBlockByHash(
        self,
        blockHash: str,
        returnTransactionObjects: bool = False,
    ) -> Any:
        """Gets a block with the given block hash.

        Args:
            blockHash (str): The block hash.
            returnTransactionObjects (bool): If `True`, returns the full transaction objects.
                If `False`, returns only the transaction hashes. Default to `False`.
        
        Returns:
            The block with the given block hash.
        """
        return await self.provider.send(
            "ain_getBlockByHash",
            {
                "getFullTransactions": returnTransactionObjects,
                "hash": blockHash,
            },
        )

    async def getBlockList(
        self,
        begin: int,
        end: int,
    ) -> List[Any]:
        """"Fetches blocks with a block number range.

        Args:
            begin (int): The begining block number (inclusive).
            end (int): The ending block number (exclusive).
        
        Returns:
            The block list.
        """
        return await self.provider.send(
            "ain_getBlockList",
            {
                "from": begin,
                "to": end,
            },
        )

    async def getBlockHeadersList(
        self,
        begin: int,
        end: int,
    ) -> List[Any]:
        """Fetches block headers with a block number range.

        Args:
            begin (int): The begining block number (inclusive).
            end (int): The ending block number (exclusive).
        
        Returns:
            The block headers list.
        """
        return await self.provider.send(
            "ain_getBlockHeadersList",
            {
                "from": begin,
                "to": end,
            },
        )

    async def getBlockTransactionCountByNumber(
        self,
        blockNumber: int,
    ) -> int:
        """Fetches block transaction count with a block number.

        Args:
            blockNumber (int): The block number.
        
        Returns:
            The block transaction count.
        """
        return await self.provider.send(
            "ain_getBlockTransactionCountByNumber",
            {
                "number": blockNumber,
            },
        )

    async def getBlockTransactionCountByHash(
        self,
        blockHash: str,
    ) -> int:
        """Fetches block transaction count with a block hash.

        Args:
            blockHash (str): The block hash.
        
        Returns:
            The block transaction count.
        """
        return await self.provider.send(
            "ain_getBlockTransactionCountByHash",
            {
                "hash": blockHash,
            },
        )

    async def getValidatorInfo(
        self,
        address: str,
    ) -> Any:
        """Fetches the information of the given validator address.

        Args:
            address (str): The block number.
        
        Returns:
            The validator information.
        """
        return await self.provider.send(
            "ain_getValidatorInfo",
            {
                "address": address,
            },
        )

    async def getValidatorsByNumber(
        self,
        blockNumber: int,
    ) -> Any:
        """Fetches the validator list of a block with a block number.

        Args:
            blockNumber (int): The block number.
            
        Returns:
            The list of validators of the given block.
        """
        return await self.provider.send(
            "ain_getValidatorsByNumber", {"number": blockNumber}
        )

    async def getValidatorsByHash(
        self,
        blockHash: str,
    ) -> Any:
        """Fetches the validator list of a block with a block hash.

        Args:
            blockHash (str): The block hash.
            
        Returns:
            The list of validators of the given block.
        """
        return await self.provider.send(
            "ain_getValidatorsByHash", {"hash": blockHash}
        )

    async def getProposerByNumber(
        self,
        blockNumber: int,
    ) -> str:
        """Fetches the block proproser's address of a block with a block number.

        Args:
            blockNumber (int): The block number.

        Returns:
            The address of the proposer of the given block.
        """
        return await self.provider.send(
            "ain_getProposerByNumber", {"number": blockNumber}
        )

    async def getProposerByHash(
        self,
        blockHash: str,
    ) -> str:
        """Fetches the block proproser's address of a block with a block hash.

        Args:
            blockHash (str): The block hash.

        Returns:
            The address of the proposer of the given block.
        """
        return await self.provider.send(
            "ain_getProposerByHash", {"hash": blockHash}
        )

    async def getPendingTransactions(self) -> Any:
        """Fetches pending transactions.

        Args:

        Returns:
            The pending transactions.
        """
        return await self.provider.send("ain_getPendingTransactions", {})

    async def getTransactionPoolSizeUtilization(self) -> Any:
        """Fetches transaction pool size utilization.

        Args:

        Returns:
            The transaction pool size utilization.
        """
        return await self.provider.send("ain_getTransactionPoolSizeUtilization", {})

    async def getTransactionByHash(self, transactionHash: str) -> Any:
        """Gets a transaction with the given transaction hash.

        Args:
            transactionHash (str): The transaction hash.

        Returns:
            The transaction with the given transaction hash.
        """
        return await self.provider.send("ain_getTransactionByHash", {"hash": transactionHash})

    async def getTransactionByBlockHashAndIndex(self, blockHash: str, index: int) -> Any:
        """Fetches a transaction's information with a block hash and an index.

        Args:
            blockHash (str): The block hash.
            index (int): The transaction index in the block

        Returns:
            The transaction with the given parameter values.
        """
        return await self.provider.send(
            "ain_getTransactionByBlockHashAndIndex",
            {
                "block_hash": blockHash,
                "index": index
            })

    async def getTransactionByBlockNumberAndIndex(self, blockNumber: int, index: int) -> Any:
        """Fetches a transaction's information with a block number and an index.

        Args:
            blockHash (int): The block number.
            index (int): The transaction index in the block

        Returns:
            The transaction with the given parameter values.
        """
        return await self.provider.send(
            "ain_getTransactionByBlockNumberAndIndex",
            {
                "block_number": blockNumber,
                "index": index
            })

    async def getStateUsage(self, appName: str) -> Any:
        """Gets a state usage with the given app name.

        Args:
            appName (str): The app name;

        Returns:
            The state usage with the given app name.
        """
        return await self.provider.send("ain_getStateUsage", {"app_name": appName})

    async def validateAppName(self, appName: str) -> Any:
        """Validate a given app name.

        Args:
            appName (str): The app name;

        Returns:
            The validity of the given app name.
        """
        return await self.provider.send("ain_validateAppName", {"app_name": appName})

    async def sendTransaction(self, transactionObject: TransactionInput, isDryrun = False) -> Any:
        """Signs and sends a transaction to the network.

        Args:
            transactionObject (TransactionInput): The transaction input object.
            isDryrun (bool): The dryrun option.

        Returns:
            The return value of the blockchain API.
        """
        return await self.signer.sendTransaction(transactionObject, isDryrun)

    async def sendSignedTransaction(self, signature: str, txBody: TransactionBody, isDryrun = False) -> Any:
        """Sends a signed transaction to the network.

        Args:
            signature (str): The signature.
            txBody (TransactionBody): The transaction body.
            isDryrun (bool): The dryrun option.

        Returns:
            The return value of the blockchain API.
        """
        return await self.signer.sendSignedTransaction(signature, txBody, isDryrun)

    async def sendTransactionBatch(self, transactionObjects: List[TransactionInput]) -> List[Any]:
        """Signs and sends multiple transactions in a batch to the network.

        Args:
            transactionObjects (List[TransactionInput]): The list of the transaction input objects.
        
        Returns:
            The return value of the blockchain API.
        """
        return await self.signer.sendTransactionBatch(transactionObjects)
        
    def depositConsensusStake(self, input: ValueOnlyTransactionInput) -> Any:
        """Sends a transaction that deposits AIN for consensus staking.

        Args:
            input (ValueOnlyTransactionInput): The value only transaction input to deposit AIN value.
            
        Returns:
            The transaction results.
        """
        return self.__stakeFunction("/deposit/consensus", input)

    def withdrawConsensusStake(self, input: ValueOnlyTransactionInput) -> Any:
        """
        Sends a transaction that withdraws AIN for consensus staking.

        Args:
            input (ValueOnlyTransactionInput): The value only transaction input to withdraw AIN value.
            
        Returns:
            The transaction results.
        """
        return self.__stakeFunction("/withdraw/consensus", input)

    async def getConsensusStakeAmount(self, account: str = None) -> Any:
        """Gets an amount of the AIN currently staked for participating in consensus protocol.

        Args:
            Account (str, Optional): The address of the consensus participant.

        Returns:
            The amount of the AIN of that address.
        """
        if account is None:
            address = self.signer.getAddress()
        else:
            address = toChecksumAddress(account)
        return await self.db.ref(f"/deposit_accounts/consensus/{address}").getValue()

    def __stakeFunction(self, path: str, input: ValueOnlyTransactionInput) -> Any:
        """A base function for all staking related database changes. It builds a
        deposit/withdraw transaction and sends the transaction by calling sendTransaction().
        """
        if not hasattr(input, "value"):
            raise ValueError("a value should be specified.")
        if type(input.value) is not int:
            raise ValueError("value has to be a int.")
        input.address = self.signer.getAddress(getattr(input, "address", None))
        ref = self.db.ref(f'{path}/{input.address}').push()
        input.ref = "value"
        return ref.setValue(input)
