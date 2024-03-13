from abc import *
from typing import List, Any
from ain.types import TransactionInput, TransactionBody

class Signer(metaclass = ABCMeta):
    """An abstract class for signing messages and transactions.
    """
    
    @abstractmethod
    def getAddress(self, address: str = None) -> str:
        """Gets an account's checksum address.
           If the address is not given, the default account of the signer is used.

        Args:
            address (str, Optional): The address of the account.

        Returns:
            str: The checksum address.
        """
        pass

    @abstractmethod
    async def signMessage(self, message: Any, address: str = None) -> str:
        """Signs a message using an account.
           If an address is not given, the default account of the signer is used.

        Args:
            message (Any): The message to sign.
            address (str, Optional): The address of the account.

        Returns:
            str: The signature.
        """
        pass

    @abstractmethod
    async def sendTransaction(self, transactionObject: TransactionInput, isDryrun = False) -> Any:
        """Signs and sends a transaction to the network.

        Args:
            transactionObject (TransactionInput): The transaction input object.
            isDryrun (bool): The dryrun option.

        Returns:
            The return value of the blockchain API.
        """
        pass

    @abstractmethod
    async def sendTransactionBatch(self, transactionObjects: List[TransactionInput]) -> List[Any]:
        """Signs and sends multiple transactions in a batch to the network.

        Args:
            transactionObjects (List[TransactionInput]): The list of the transaction input objects.
        
        Returns:
            The return value of the blockchain API.
        """
        pass

    @abstractmethod
    async def sendSignedTransaction(self, signature: str, txBody: TransactionBody, isDryrun = False) -> Any:
        """Sends a signed transaction to the network.

        Args:
            signature (str): The signature.
            txBody (TransactionBody): The transaction body.
            isDryrun (bool): The dryrun option.

        Returns:
            The return value of the blockchain API.
        """
        pass
