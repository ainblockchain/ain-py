from typing import TYPE_CHECKING, Any, List, Optional
from ain.account import Account, Accounts
from ain.types import (
    TransactionBody,
    ValueOnlyTransactionInput,
    ECDSASignature,
)
from ain.utils import (
    toBytes,
    toChecksumAddress,
    bytesToHex,
    pubToAddress,
    ecSignMessage,
    ecSignTransaction,
    ecRecoverPub,
    ecVerifySig,
)

if TYPE_CHECKING:
    from ain.ain import Ain

class Wallet:
    defaultAccount: Optional[Account]
    accounts: Accounts
    ain: "Ain"
    chainId: int

    def __init__(self, ain: "Ain", chainId: int):
        self.defaultAccount = None
        self.accounts: Accounts = {}
        self.ain = ain
        self.chainId = chainId

    @property
    def length(self) -> int:
        return len(self.accounts)

    def getPublicKey(self, address: str) -> str:
        """
        Returns the full public key of the given address.
        """
        checksummed = toChecksumAddress(address)
        if checksummed not in self.accounts:
            return ''
        return self.accounts[checksummed].public_key

    def create(self, numberOfAccounts: int):
        """
        Creates {numberOfAccounts} new accounts and add them to the wallet.
        """
        if numberOfAccounts <= 0:
            raise ValueError("numberOfAccounts should be greater than 0.")
        
        newAccounts: List[str] = []
        for i in range(numberOfAccounts):
            account = Account.create()
            self.accounts[account.address] = account
            newAccounts.append(account.address)

        return newAccounts
    
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
        return newAccount.address

    def addAndSetDefaultAccount(self, privateKey: str) -> str:
        """
        Adds a new account from the given private key and sets the new account as the default account.
        """
        address = self.add(privateKey)
        self.setDefaultAccount(address)
        return address

    def addFromHDWallet(self, mnemonic: str, index: int = 0):
        """
        Adds an account from a seed phrase. Only the account at the given
        index (default = 0) will be added.
        """
        account = Account.fromMnemonic(mnemonic, index)
        self.accounts[account.address] = account
        return account.address

    # TODO(kriii): implement this function.
    def addFromV3Keystore(self):
        """
        Adds an account from a V3 Keystore.
        """
        pass
    
    def remove(self, address: str):
        """
        Removes an account
        """
        addressToRemove = toChecksumAddress(address)
        if addressToRemove not in self.accounts:
            raise ValueError("Can't find account to remove")
        del self.accounts[addressToRemove]
        if self.defaultAccount is not None and self.defaultAccount.address == addressToRemove:
            self.removeDefaultAccount()

    def setDefaultAccount(self, address: str):
        """
        Sets the default account as {address}. The account should be already added
        in the wallet.
        """
        checksumed = toChecksumAddress(address)
        if checksumed not in self.accounts:
            raise ValueError("Add the account first before setting it to defaultAccount.")
        self.defaultAccount = self.accounts[checksumed]

    def removeDefaultAccount(self):
        """
        Removes a default account (sets it to None).
        """
        self.defaultAccount = None

    def clear(self):
        """
        Clears the wallet (remove all account information).
        """
        self.accounts.clear()
        self.removeDefaultAccount()

    def getImpliedAddress(self, inputAddress= None) -> str:
        """
        Returns the "implied" address. If address is not given,
        it returns the defaultAccount. It throws an error if
        an address is not given and defaultAccount is not set, or
        the specified address is not added to the wallet.
        """
        if inputAddress is not None:
            address = inputAddress
        elif self.defaultAccount is not None:
            address = self.defaultAccount.address
        else:
            raise ValueError("You need to specify the address or set defaultAccount.")
        checksummed = toChecksumAddress(address)
        if checksummed not in self.accounts:
            raise ValueError("The address you specified is not added in your wallet. Try adding it first.")
        return checksummed

    async def getBalance(self, address: str = None) -> int:
        """
        Returns the AIN balance of the address.
        """
        if address is None:
            addr = self.getImpliedAddress()
        else:
            addr = toChecksumAddress(address)
        return await self.ain.db.ref(f"/accounts/{addr}/balance").getValue()

    async def transfer(self, toAddress: str, value: int, fromAddress: str = None, nonce: int = None, gas_price: int = None):
        """
        Sends a transfer transaction to the network.
        """
        fromAddr = self.getImpliedAddress(fromAddress)
        toAddr = toChecksumAddress(toAddress)
        transferRef = self.ain.db.ref(f"/transfer/{fromAddr}/{toAddr}").push()
        return transferRef.setValue(
            ValueOnlyTransactionInput(
                ref="/value",
                address=fromAddress,
                value=value,
                nonce=nonce,
                gas_price=gas_price,
            )
        )

    def sign(self, data: str, address: str = None) -> str:
        """
        Signs a string data with the private key of the given address. It will use
        the defaultAccount if an address is not provided.
        """
        addr = self.getImpliedAddress(address)
        privateKeyBytes = bytes.fromhex(self.accounts[addr].private_key)
        return ecSignMessage(data, privateKeyBytes, self.chainId)
    
    def signTransaction(self, tx: TransactionBody, address: str = None) -> str:
        """
        Signs a transaction data with the private key of the given address. It will use
        the defaultAccount if an address is not provided.
        """
        addr = self.getImpliedAddress(address)
        privateKeyBytes = bytes.fromhex(self.accounts[addr].private_key)
        return ecSignTransaction(tx, privateKeyBytes, self.chainId)

    def getHashStrFromSig(self, signature: str) -> str:
        """
        Gets the hash from the signature.
        """
        sigBytes = toBytes(signature)
        lenHash = len(sigBytes) - 65
        hashedData = sigBytes[0:lenHash]
        return "0x" + hashedData.hex()

    def recover(self, signature: str) -> str:
        """
        Recovers an address of the account that was used to create the signature.
        """
        sigBytes = toBytes(signature)
        lenHash = len(sigBytes) - 65
        hashedData = sigBytes[0:lenHash]
        sig = ECDSASignature.fromSignature(sigBytes[lenHash:])
        return toChecksumAddress(bytesToHex(pubToAddress(ecRecoverPub(hashedData, sig, self.chainId)[1:])))

    def verifySignature(self, data: Any, signature: str, address: str) -> bool:
        return ecVerifySig(data, signature, address, self.chainId)

    # TODO(kriii): implement this function.
    def toV3Keystore(self):
        """
        Save the accounts in the wallet as V3 Keystores, locking them with the password.
        """
        pass
    
    # TODO(kriii): implement this function.
    def accountToV3Keystore(self):
        """
        Converts an account into a V3 Keystore and encrypts it with a password.
        """
        pass