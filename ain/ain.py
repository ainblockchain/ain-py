from ain.provider import Provider
from ain.net import Network
from ain.wallet import Wallet
from ain.db import Database
from ain.utils import ecSignTransaction, getTimestamp


class Ain:
    def __init__(self, providerUrl: str, chainId: int = 0):
        self.provider = Provider(self, providerUrl)
        self.chainId = chainId
        self.net = Network(self.provider)
        self.wallet = Wallet(self, self.chainId)
        self.db = Database(self, self.provider)

    # TODO : specify type `TransactionInput`

    async def buildTransactionBody(self, transactionInput):
        txBody = {"operation": transactionInput["operation"]}

        if "parent_tx_hash" in transactionInput:
            txBody["parent_tx_hash"] = transactionInput.parent_tx_hash

        if "nonce" in transactionInput:
            txBody["nonce"] = transactionInput["nonce"]
            """
            TODO : implement `getNonce`
        else:
            txBody['nonce'] = await getNonce({'address': a.address, 'from': 'pending'})
            """

        txBody["timestamp"] = transactionInput.get("timestamp", getTimestamp())

        return txBody

    async def sendTransaction(self, transactionObject):
        txBody = await self.buildTransactionBody(transactionObject)
        signature = ecSignTransaction(txBody, self.wallet.defaultAccount.privateKey)
        result = await self.provider.send("ain_sendSignedTransaction", {"signature": signature, "tx_body": txBody})
        return result
