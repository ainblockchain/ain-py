from typing import Optional, Union, Dict

from coincurve import PrivateKey

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ain.ain import Ain
from ain.utils import toChecksumAddress, bufferToHex, pubToAddress


class Account:
    def __init__(self, privateKey: Union[bytes, str] = None):
        privateKeyBytes: Optional[bytes] = None
        if type(privateKey) is bytes:
            privateKeyBytes = privateKey
        elif type(privateKey) is str:
            privateKeyBytes = bytes.fromhex(privateKey)

        self.privateKey = PrivateKey(privateKeyBytes)
        self.publicKey = self.privateKey.public_key
        self.address = toChecksumAddress(bufferToHex(pubToAddress(self.publicKey.format(False)[1:])))

    def __str__(self):
        return "\n".join(
            (
                f"address: {self.address}",
                f"private: {self.privateKey.to_hex()}",
                f"public: {self.publicKey.format(False)[1:].hex()}",
            )
        )


Accounts = Dict[str, Account]


class Wallet:
    def __init__(self, ain: "Ain", chainId: int):
        self.defaultAccount: Optional[Account] = None
        self.accounts: Accounts = {}
        self._length = 0
        self.ain = ain
        self.chainId = chainId

    def isAdded(self, address: str) -> bool:
        """
        Returns whether the address has already been added to the wallet.
        """
        return address in self.accounts

    def add(self, privateKey: str) -> str:
        """
        Adds a new account from the given private key.
        """
        newAccount = Account(privateKey)
        self.accounts[newAccount.address] = newAccount
        self._length += 1
        return newAccount.address

    def addAndSetDefaultAccount(self, privateKey: str) -> str:
        """
        Adds a new account from the given private key and sets the new account as the default account.
        """
        address = self.add(privateKey)
        self.setDefaultAccount(address)
        return address

    def setDefaultAccount(self, address: str):
        """
        Sets the default account as {address}. The account should be already added
        in the wallet.
        """
        checksumed = toChecksumAddress(address)
        if checksumed not in self.accounts:
            raise ValueError("ain.wallet.setDefaultAccount] Add the account first before setting it to defaultAccount.")
        self.defaultAccount = self.accounts(checksumed)
