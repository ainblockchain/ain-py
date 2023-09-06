from abc import *
from typing import Any
from ain.wallet import Wallet

class Signer(metaclass = ABCMeta):
    """An abstract class for signing messages and transactions.
    """
    
    @abstractmethod
    def getAddress(self, address: str = None) -> str:
        """Return the checksum address to sign messages with.
           If the address is not given, the default address of the signer is used.

        Args:
            address (str, Optional): The address of the account to sign messages with.

        Returns:
            str: The checksum address.
        """
        pass

    @abstractmethod
    async def signMessage(self, message: Any, address: str = None) -> str:
        """Signs a message with the private key of the given address.
           If the address is not given, the default address of the signer is used.

        Args:
            message (Any): The message to sign.
            address (str, Optional): The address of the account to sign the message with.

        Returns:
            str: The signature of the message.
        """
        pass


class DefaultSigner(Signer):
    """The default concrete class of Signer abstract class implemented using Wallet class.
       When Ain class is initialized, DefaultSigner is set as its signer.

    Args:
        wallet (Wallet): The wallet to initialize with.
    """
    
    wallet: Wallet

    def __init__(self, wallet: Wallet):
        self.wallet = wallet

    def getAddress(self, address: str = None) -> str:
        """Return the checksum address to sign messages with.
           If the address is not given, the default address of the wallet is used.

        Args:
            address (str, Optional): The address of the account to sign messages with.

        Returns:
            str: The checksum address.
        """
        return self.wallet.getImpliedAddress(address)

    async def signMessage(self, message: Any, address: str = None) -> str:
        """Signs a message with the private key of the given address.
           If the address is not given, the default address of the wallet is used.

        Args:
            message (Any): The message to sign.
            address (str, Optional): The address of the account to sign the message with.

        Returns:
            str: The signature of the message.
        """
        if type(message) is str:
            return self.wallet.sign(message, address)
        else:
            return self.wallet.signTransaction(message, address)
