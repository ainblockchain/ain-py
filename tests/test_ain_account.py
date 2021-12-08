from unittest import TestCase
from ain.account import Account
from ain.utils import *
from .data import (
    mnemonic,
    mnemonicPrivateKey,
    mnemonicPublicKey,
    mnemonicAddress,
)

class TestAccount(TestCase):
    def testAccountFromMnemonic(self):
        account = Account.fromMnemonic(mnemonic)
        self.assertEqual(account.private_key, mnemonicPrivateKey.hex())
        self.assertEqual(account.public_key, mnemonicPublicKey.hex())
        self.assertEqual(account.address, mnemonicAddress)
    
    def testAccountCreateFromEntropyNone(self):
        account = Account.create()
        publicKey = privateToPublic(bytes.fromhex(account.private_key)).hex()
        self.assertEqual(account.public_key, publicKey)

    def testAccountCreateFromEntropy(self):
        account = Account.create("Test")
        publicKey = privateToPublic(bytes.fromhex(account.private_key)).hex()
        self.assertEqual(account.public_key, publicKey)