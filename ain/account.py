from typing import Dict, Union
from secrets import token_bytes
from ain.utils import (
    privateToPublic,
    privateToAddress,
    mnemonicToPrivatekey,
    keccak
)

class Account:
    private_key: str
    public_key: str
    address: str
    
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
        """
        Returns an Account with the given mnemonic.
        """
        return cls(mnemonicToPrivatekey(mnemonic, index))

    @classmethod
    def create(cls, entropy: str = None):
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
