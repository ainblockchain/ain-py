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

    async def getBlock(
        self,
        blockHashOrBlockNumber: Union[str, int],
        returnTransactionObjects: bool = False,
    ) -> Any:
        """Gets a block with the given hash or block number.

        Args:
            blockHashOrBlockNumber (Union[str, int]): The block hash or the block number.
            returnTransactionObjects (bool): If `True`, returns the full transaction objects.
                If `False`, returns only the transaction hashes. Default to `False`.
        
        Returns:
            The block with the given hash or block number.
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
    ) -> Any:
        """Gets an address of the proposer of the given block.

        Args:
            blockHashOrBlockNumber (Union[str, int]): The block hash or the block number.

        Returns:
            The address of the proposer of the given block.
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
    ) -> Any:
        """Gets the list of validators for a given block

        Args:
            blockHashOrBlockNumber (Union[str, int]): The block hash or the block number.
            
        Returns:
            The list of validators for a given block.
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

    async def getTransaction(self, transactionHash: str) -> Any:
        """Gets a transaction with the given transaction hash.

        Args:
            transactionHash (str): The transaction hash.

        Returns:
            The transaction with the given transaction hash.
        """
        return await self.provider.send("ain_getTransactionByHash", {"hash": transactionHash})

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
