from typing import Dict, Union
from ain.utils import (
    privateToPublic,
    privateToAddress,
    mnemonicToPrivatekey,
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
