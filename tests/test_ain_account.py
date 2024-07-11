from unittest import TestCase
from ain.account import Account
from ain.utils import *
from .data import (
    mnemonic,
    mnemonicPrivateKeyAin,
    mnemonicPublicKeyAin,
    mnemonicAddressAin,
    mnemonicPrivateKeyEth,
    mnemonicPublicKeyEth,
    mnemonicAddressEth,
)

class TestAccount(TestCase):
    def testAccountFromMnemonicAin(self):
        account = Account.fromMnemonic(mnemonic)
        self.assertEqual(account.private_key, mnemonicPrivateKeyAin.hex())
        self.assertEqual(account.public_key, mnemonicPublicKeyAin.hex())
        self.assertEqual(account.address, mnemonicAddressAin)
    
    def testAccountFromMnemonicEth(self):
        account = Account.fromMnemonic(mnemonic, 0, "ETH")
        self.assertEqual(account.private_key, mnemonicPrivateKeyEth.hex())
        self.assertEqual(account.public_key, mnemonicPublicKeyEth.hex())
        self.assertEqual(account.address, mnemonicAddressEth)
    
    def testAccountCreateFromEntropyNone(self):
        account = Account.create()
        publicKey = privateToPublic(bytes.fromhex(account.private_key)).hex()
        self.assertEqual(account.public_key, publicKey)

    def testAccountCreateFromEntropy(self):
        account = Account.create("Test")
        publicKey = privateToPublic(bytes.fromhex(account.private_key)).hex()
        self.assertEqual(account.public_key, publicKey)