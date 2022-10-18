from typing import TYPE_CHECKING, Any, List, Optional, Union
from ain.account import Account, Accounts
from ain.types import (
    TransactionBody,
    ValueOnlyTransactionInput,
    ECDSASignature,
)
from ain.utils import (
    privateToAddress,
    toBytes,
    toChecksumAddress,
    bytesToHex,
    pubToAddress,
    ecSignMessage,
    ecSignTransaction,
    ecRecoverPub,
    ecVerifySig,
)
from ain.utils.v3keystore import V3Keystore, V3KeystoreOptions

if TYPE_CHECKING:
    from ain.ain import Ain

class Wallet:
    """Class for the AIN Blockchain wallet."""

    defaultAccount: Optional[Account]
    """The default account of the wallet."""
    accounts: Accounts
    """The set of the accounts. Keys are the addresses of the accounts."""
    ain: "Ain"
    """The `Ain` instance."""
    chainId: int
    """The chain ID of the provider."""

    def __init__(self, ain: "Ain", chainId: int):
        self.defaultAccount = None
        self.accounts: Accounts = {}
        self.ain = ain
        self.chainId = chainId

    @property
    def length(self) -> int:
        return len(self.accounts)

    def getPublicKey(self, address: str) -> str:
        """Gets a full public key of the given address.

        Args:
            address(str): The address of the account.

        Returns:
            str: The full public key of the given address.
                If such address is not in the wallet, returns empty string.
        """
        checksummed = toChecksumAddress(address)
        if checksummed not in self.accounts:
            return ''
        return self.accounts[checksummed].public_key

    def create(self, numberOfAccounts: int):
        """Creates `numberOfAccounts` new accounts, and adds them to the wallet.

        Args:
            numberOfAccounts(int): The number of account that you want to create.
                If this is not positive, raises `ValueError`.
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
        """Returns whether the address has already been added to the wallet.

        Args:
            address (str): The address of the account.

        Returns:
            bool: `True`, if the address has already been added to the wallet,
                `False`, if not.
        """
        return address in self.accounts

    def add(self, privateKey: Union[str, bytes]) -> str:
        """Adds a new account to the wallet, from the given private key.

        Args:
            privateKey (Union[str, bytes]): The private key of the new account.
        
        Returns:
            str: The address of the new account.
        """
        newAccount = Account(privateKey)
        self.accounts[newAccount.address] = newAccount
        return newAccount.address

    def addAndSetDefaultAccount(self, privateKey: Union[str, bytes]) -> str:
        """Adds a new account to the wallet, from the given private key.
        Then, sets the new account as the default account.

        Args:
            privateKey (Union[str, bytes]): The private key of the new account.
        
        Returns:
            str: The address of the new account.
        """
        address = self.add(privateKey)
        self.setDefaultAccount(address)
        return address

    def addFromHDWallet(self, mnemonic: str, index: int = 0) -> str:
        """Adds an account to the wallet, from a seed phrase.
        Only the account at the given index will be added.

        Args:
            mnemonic (str): The mnemonic of account.
            index (int): The index of account. Defaults to 0.
        
        Returns:
            str: The address of the new account.
        """
        account = Account.fromMnemonic(mnemonic, index)
        self.accounts[account.address] = account
        return account.address

    def addFromV3Keystore(self, v3Keystore: Union[V3Keystore, str], password: str) -> str:
        """Adds an account to the wallet, from the v3 keystore.

        Args:
            mnemonic (Union[V3Keystore, str]): The v3 keystore of account.
            index (int): The password of your v3 keystore.
        
        Returns:
            str: The address of the new account.
        """
        if type(v3Keystore) is V3Keystore:
            privateKey = v3Keystore.toPrivateKey(password)
        elif type(v3Keystore) is str:
            privateKey = V3Keystore.fromJSON(v3Keystore).toPrivateKey(password)
        else:
            raise TypeError("v3Keystore has invalid type")
        self.add(privateKey)
        return privateToAddress(privateKey)
    
    def remove(self, address: str):
        """Removes the account from the wallet.
        If such account doesn't exist, raises `ValueError`.

        Args:
            address (str): The address of the account.
        """
        addressToRemove = toChecksumAddress(address)
        if addressToRemove not in self.accounts:
            raise ValueError("Can't find account to remove")
        del self.accounts[addressToRemove]
        if self.defaultAccount is not None and self.defaultAccount.address == addressToRemove:
            self.removeDefaultAccount()

    def setDefaultAccount(self, address: str):
        """Sets the default AIN Blockchain account address as `address`.
        If such `address` is not added to the wallet, raises `ValueError`.

        Args:
            address (str): The address of the account.
        """
        checksumed = toChecksumAddress(address)
        if checksumed not in self.accounts:
            raise ValueError("Add the account first before setting it to defaultAccount.")
        self.defaultAccount = self.accounts[checksumed]

    def removeDefaultAccount(self):
        """Removes a default account from the wallet, and sets it to `None`."""
        self.defaultAccount = None

    def clear(self):
        """Clears the wallet, remove all account information."""
        self.accounts.clear()
        self.removeDefaultAccount()

    def getImpliedAddress(self, address: str = None) -> str:
        """Gets an implied address.

        Args:
            address (str, Optional): The address of the account.
                If `address` is not given, returns the default account address. Defaults to `None`.
                If `address` is not given and default account is not set, raises `ValueError`.
                If such `address` is not added to the wallet, raises `ValueError`.

        Returns:
            str: The implied address.
        """
        if address is not None:
            filteredAddress = address
        elif self.defaultAccount is not None:
            filteredAddress = self.defaultAccount.address
        else:
            raise ValueError("You need to specify the address or set defaultAccount.")
        checksummed = toChecksumAddress(filteredAddress)
        if checksummed not in self.accounts:
            raise ValueError("The address you specified is not added in your wallet. Try adding it first.")
        return checksummed

    async def getBalance(self, address: str = None) -> int:
        """Gets an AIN balance of the given account.

        Args:
            address (str, Optional): The address of the account.
                If `address` is `None`, returns the balance of the default account address. Defaults to `None`.
                If `address` is `None` and default account is not set, raises `ValueError`.

        Returns:
            str: The AIN balance of the given account.
        """
        if address is None:
            addr = self.getImpliedAddress()
        else:
            addr = toChecksumAddress(address)
        return await self.ain.db.ref(f"/accounts/{addr}/balance").getValue()

    async def transfer(self, toAddress: str, value: int, fromAddress: str = None, nonce: int = None, gas_price: int = None):
        """Sends a transfer transaction to the network.

        Args:
            toAddress (str): The AIN blockchain address that wants to transfer AIN to.
            value (int): The amount of the transferring AIN.
            fromAddress (str, Optional): The AIN blockchain address that wants to transfer AIN from.
                Defaults to `None`, transfer from the default account of the current wallet.
            nonce (int, Optional): The nonce of the transfer transaction.
                Defaults to `None`.
            gas_price (int, Optional): The gas price of the transfer transaction.
                Defaults to `None`.
        
        Returns:
            The transaction result.
        """
        fromAddr = self.getImpliedAddress(fromAddress)
        toAddr = toChecksumAddress(toAddress)
        transferRef = self.ain.db.ref(f"/transfer/{fromAddr}/{toAddr}").push()
        return await transferRef.setValue(
            ValueOnlyTransactionInput(
                ref="/value",
                address=fromAddress,
                value=value,
                nonce=nonce,
                gas_price=gas_price,
            )
        )

    def sign(self, data: str, address: str = None) -> str:
        """Signs a string data with the private key of the given address.

        Args:
            data (str): The string data.
            address (str, Optional): The AIN blockchain address that wants to use for signing.
                Defaults to `None`, use the default account of the current wallet.
        
        Returns:
            str: The signature of the data.
        """
        addr = self.getImpliedAddress(address)
        privateKeyBytes = bytes.fromhex(self.accounts[addr].private_key)
        return ecSignMessage(data, privateKeyBytes, self.chainId)
    
    def signTransaction(self, tx: TransactionBody, address: str = None) -> str:
        """Signs a transaction data with the private key of the given address.

        Args:
            tx (TransactionBody): The transaction data.
            address (str, Optional): The AIN blockchain address that wants to use for signing.
                Defaults to `None`, use the default account of the current wallet.
        
        Returns:
            str: The signature of the transaction.
        """
        addr = self.getImpliedAddress(address)
        privateKeyBytes = bytes.fromhex(self.accounts[addr].private_key)
        return ecSignTransaction(tx, privateKeyBytes, self.chainId)

    def getHashStrFromSig(self, signature: str) -> str:
        """Gets a hash from the signature.

        Args:
            signature (str): The signature.

        Returns:
            The hex prefixed hash from the signature.
        """
        sigBytes = toBytes(signature)
        lenHash = len(sigBytes) - 65
        hashedData = sigBytes[0:lenHash]
        return "0x" + hashedData.hex()

    def recover(self, signature: str) -> str:
        """Recovers an address of the account that was used to create the signature.

        Args:
            signature (str): The signature.
        
        Returns:
            The address of the account that was used to create the signature.
        """
        sigBytes = toBytes(signature)
        lenHash = len(sigBytes) - 65
        hashedData = sigBytes[0:lenHash]
        sig = ECDSASignature.fromSignature(sigBytes[lenHash:])
        return toChecksumAddress(bytesToHex(pubToAddress(ecRecoverPub(hashedData, sig, self.chainId)[1:])))

    def verifySignature(self, data: Any, signature: str, address: str) -> bool:
        """Verifies the given signature.
        
        Args:
            data: The data that has made the signature.
            signature (str): The signature of the given data.
            address (str): The address of who created the signature.
        
        Returns:
            bool: `True`, if the signature is valid.
                `False`, if not.
        """
        return ecVerifySig(data, signature, address, self.chainId)

    def toV3Keystore(
        self,
        password: str,
        options: V3KeystoreOptions = V3KeystoreOptions()
    ) -> List[V3Keystore]:
        """Saves the accounts in the wallet as v3 Keystores, locking them with the password.

        Args:
            password (str): The password of the v3 keystores.
            options (V3KeystoreOptions): The options for the v3 keystores.
                Defaults to no options.
        
        Returns:
            List[V3Keystore]: The list of the v3 Keystores.
        """
        ret = []
        for address in self.accounts:
            ret.append(self.accountToV3Keystore(address, password, options))
        return ret
    
    def accountToV3Keystore(
        self,
        address: str,
        password: str,
        options: V3KeystoreOptions = V3KeystoreOptions()
    ) -> V3Keystore:
        """Converts an account into a v3 Keystore and encrypts it with a password.

        Args:
            address: The AIN blockchain address.
            password: The password of the v3 keystore.
            options (V3KeystoreOptions): The options for the v3 keystore.
                Defaults to no options.
                
        Returns:
            V3Keystore: The v3 Keystore of the account.
        """
        if not self.isAdded(address):
            raise ValueError("No such address exists in the wallet")
        privateKey = self.accounts[address].private_key
        return V3Keystore.fromPrivateKey(privateKey, password, options)