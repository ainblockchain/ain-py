from abc import *
import asyncio
from typing import List, Any
from ain.wallet import Wallet
from ain.provider import Provider
from ain.signer import Signer
from ain.types import TransactionInput, TransactionBody
from ain.utils import getTimestamp, toChecksumAddress

class DefaultSigner(Signer):
    """The default concrete class of Signer abstract class implemented using Wallet class.
       When Ain class is initialized, DefaultSigner is set as its signer.

    Args:
        wallet (Wallet): The wallet to initialize with.
        provider (Provider): The network provider to initialize with.
    """
    
    wallet: Wallet
    """The `Wallet` instance."""
    provider: Provider
    """The `Provider` instance."""

    def __init__(self, wallet: Wallet, provider: Provider):
        self.wallet = wallet
        self.provider = provider

    def getAddress(self, address: str = None) -> str:
        """Gets an account's checksum address.
           If the address is not given, the default account of the signer is used.

        Args:
            address (str, Optional): The address of the account.

        Returns:
            str: The checksum address.
        """
        return self.wallet.getImpliedAddress(address)

    async def signMessage(self, message: Any, address: str = None) -> str:
        """Signs a message using an account.
           If an address is not given, the default account of the signer is used.

        Args:
            message (Any): The message to sign.
            address (str, Optional): The address of the account.

        Returns:
            str: The signature.
        """
        return self.wallet.sign(message, address)

    async def sendTransaction(self, transactionObject: TransactionInput, isDryrun = False) -> Any:
        """Signs and sends a transaction to the network.

        Args:
            transactionObject (TransactionInput): The transaction input object.
            isDryrun (bool): The dryrun option.

        Returns:
            The return value of the blockchain API.
        """
        txBody = await self.buildTransactionBody(transactionObject)
        signature = self.wallet.signTransaction(txBody, getattr(transactionObject, "address", None))
        return await self.sendSignedTransaction(signature, txBody, isDryrun)

    async def sendTransactionBatch(self, transactionObjects: List[TransactionInput]) -> List[Any]:
        """Signs and sends multiple transactions in a batch to the network.

        Args:
            transactionObjects (List[TransactionInput]): The list of the transaction input objects.
        
        Returns:
            The return value of the blockchain API.
        """
        txListCoroutines = []
        for txInput in transactionObjects:
            txListCoroutines.append(self.buildTransactionBodyAndSignature(txInput))
        
        txList = await asyncio.gather(*txListCoroutines)
        return await self.provider.send("ain_sendSignedTransactionBatch", {"tx_list": txList})

    async def sendSignedTransaction(self, signature: str, txBody: TransactionBody, isDryrun = False) -> Any:
        """Sends a signed transaction to the network.

        Args:
            signature (str): The signature.
            txBody (TransactionBody): The transaction body.
            isDryrun (bool): The dryrun option.

        Returns:
            The return value of the blockchain API.
        """
        method = "ain_sendSignedTransactionDryrun" if isDryrun == True else "ain_sendSignedTransaction"
        return await self.provider.send(method, {"signature": signature, "tx_body": txBody})

    async def buildTransactionBody(self, transactionInput: TransactionInput) -> TransactionBody:
        """Builds a transaction body object from a transaction input object.

        Args:
            transactionInput (TransactionInput): The transaction input object.
        
        Returns:
            The TransactionBody object.
        """
        address = self.getAddress(
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

    async def buildTransactionBodyAndSignature(self, transactionObject: TransactionInput) -> dict:
        """Builds a transaction body object and a signature from a transaction input object.

        Args:
            transactionInput (TransactionInput): The transaction input object.
        
        Returns:
            The TransactionBody object and the signature.
        """
        txBody = await self.buildTransactionBody(transactionObject)
        if not hasattr(transactionObject, "nonce"):
            # Batch transactions' nonces should be specified.
            # If they're not, they default to un-nonced (nonce = -1).
            txBody.nonce = -1
            
        signature = self.wallet.signTransaction(txBody, getattr(transactionObject, "address", None))
        return {"signature": signature, "tx_body": txBody}

    async def getNonce(self, args: dict) -> Any:
        """Fetches an account's nonce value, which is the current transaction count of the account.

        Args:
            args (dict): The ferch options.
                It may contain a string 'address' value and a string 'from' value.
                The 'address' is the address of the account to get the nonce of,
                and the 'from' is the source of the data.
                It could be either the pending transaction pool ("pending") or
                the committed blocks ("committed"). The default value is "committed".
        
        Returns:
            The nonce value.
        """
        params = dict(args)
        if "address" in args:
            params["address"] = toChecksumAddress(args["address"])
        else:
            params["address"] = self.getAddress()

        if "from" in args:
            if args["from"] != "pending" and args["from"] != "committed":
                raise ValueError("'from' should be either 'pending' or 'committed'")

        return await self.provider.send("ain_getNonce", params)
    