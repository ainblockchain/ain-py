from typing import Dict, Union
from secrets import token_bytes
from ain.utils import (
    privateToPublic,
    privateToAddress,
    mnemonicToPrivatekey,
    keccak
)

class Account:
    """Class for the account on the AIN Blockchain.
    
    Args:
        privateKey (Union[bytes, str]): The private key of the account.
    """

    private_key: str
    """The private key of the account."""
    public_key: str
    """The public key of the account."""
    address: str
    """The address of the account on the AIN Blockchain"""
    
    def __init__(self, privateKey: Union[bytes, str] = None):
        if type(privateKey) is bytes:
            privateKeyBytes = privateKey
        elif type(privateKey) is str:
            privateKeyBytes = bytes.fromhex(privateKey)
        else:
            raise TypeError('privateKey has invalid type')

        self.private_key = privateKeyBytes.hex()
        self.public_key = privateToPublic(privateKeyBytes).hex()
        self.address = privateToAddress(privateKeyBytes)

    @classmethod
    def fromMnemonic(cls, mnemonic: str, index: int = 0):
        """Inits an `Account` with the given mnemonic.

        Args:
            mnemonic (str): The mnemonic of account.
            index (int): The index of account. Defaults to 0.
        """
        return cls(mnemonicToPrivatekey(mnemonic, index))

    @classmethod
    def create(cls, entropy: str = None):
        """Inits an `Account` with the given entropy.

        Args:
            entropy (str): The entropy of account. Defaults to None.
        """
        entropyBytes = token_bytes(32)
        if entropy is not None:
            entropyBytes = bytes(entropy, "utf-8")

        innerHex = keccak(token_bytes(32) + entropyBytes)
        middleHex = token_bytes(32) + innerHex + token_bytes(32)
        return cls(keccak(middleHex))

    def __str__(self):
        return "\n".join(
            (
                "{",
                f"  address: '{self.address}'",
                f"  private: '{self.private_key}'",
                f"  public: '{self.public_key}'",
                "}",
            )
        )

Accounts = Dict[str, Account]
