from unittest import TestCase
from ain.utils import *
from ain.utils.v3keystore import *
from ain.types import SetOperation, TransactionBody
from .data import (
    address,
    pk,
    sk,
    mnemonic,
    mnemonicPrivateKey,
    checksumAddresses,
    message,
    correctSignature,
    tx,
    txDifferent,
    v3KeystoreKDFList,
    v3KeystoreCipherList,
    v3KeystorePassword,
    v3KeystoreJSONList,
    v3KeystoreFixedUUID,
    v3KeystoreFixedIV,
    v3KeystoreFixedSalt,
    v3KeystoreFixedJSON,
    encrypted,
)

class TestKeccak(TestCase):
    def testKeccak(self):
        msg = "0x3c9229289a6125f7fdf1885a77bb12c37a8d3b4962d936f7e3084dece32a3ca1"
        r = "82ff40c0a986c6a5cfad4ddf4c3aa6996f1a7837f9c398e17e5de5cbd5a12b28"
        hash = keccak(msg)
        self.assertEqual(hash.hex(), r)

    def testKeccakWithoutHexprefix(self):
        msg = "3c9229289a6125f7fdf1885a77bb12c37a8d3b4962d936f7e3084dece32a3ca1"
        r = "22ae1937ff93ec72c4d46ff3e854661e3363440acd6f6e4adf8f1a8978382251"
        hash = keccak(msg)
        self.assertEqual(hash.hex(), r)

class TestCountDecimals(TestCase):
    def testCountDecimals(self):
        self.assertEqual(countDecimals(0), 0)  # '0'
        self.assertEqual(countDecimals(1), 0)  # '1'
        self.assertEqual(countDecimals(10), 0)  # '10'
        self.assertEqual(countDecimals(100), 0)  # '100'
        self.assertEqual(countDecimals(1000), 0)  # '1000'
        self.assertEqual(countDecimals(10000), 0)  # '10000'
        self.assertEqual(countDecimals(100000), 0)  # '100000'
        self.assertEqual(countDecimals(1000000), 0)  # '1000000'
        self.assertEqual(countDecimals(10000000), 0)  # '10000000'
        self.assertEqual(countDecimals(100000000), 0)  # '100000000'
        self.assertEqual(countDecimals(1000000000), 0)  # '1000000000'
        self.assertEqual(countDecimals(1234567890), 0)  # '1234567890'
        self.assertEqual(countDecimals(-1), 0)  # '-1'
        self.assertEqual(countDecimals(-1000000000), 0)  # '-1000000000'
        self.assertEqual(countDecimals(11), 0)  # '11'
        self.assertEqual(countDecimals(101), 0)  # '101'
        self.assertEqual(countDecimals(1001), 0)  # '1001'
        self.assertEqual(countDecimals(10001), 0)  # '10001'
        self.assertEqual(countDecimals(100001), 0)  # '100001'
        self.assertEqual(countDecimals(1000001), 0)  # '1000001'
        self.assertEqual(countDecimals(10000001), 0)  # '10000001'
        self.assertEqual(countDecimals(100000001), 0)  # '100000001'
        self.assertEqual(countDecimals(1000000001), 0)  # '1000000001'
        self.assertEqual(countDecimals(-11), 0)  # '-11'
        self.assertEqual(countDecimals(-1000000001), 0)  # '-1000000001'
        self.assertEqual(countDecimals(0.1), 1)  # '0.1'
        self.assertEqual(countDecimals(0.01), 2)  # '0.01'
        self.assertEqual(countDecimals(0.001), 3)  # '0.001'
        self.assertEqual(countDecimals(0.0001), 4)  # '0.0001'
        self.assertEqual(countDecimals(0.00001), 5)  # '1e-05'
        self.assertEqual(countDecimals(0.000001), 6)  # '1e-06'
        self.assertEqual(countDecimals(0.0000001), 7)  # '1e-07'
        self.assertEqual(countDecimals(0.00000001), 8)  # '1e-08'
        self.assertEqual(countDecimals(0.000000001), 9)  # '1e-09'
        self.assertEqual(countDecimals(0.0000000001), 10)  # '1e-10'
        self.assertEqual(countDecimals(-0.1), 1)  # '-0.1'
        self.assertEqual(countDecimals(-0.0000000001), 10)  # '-1e-10'
        self.assertEqual(countDecimals(1.2), 1)  # '1.2'
        self.assertEqual(countDecimals(0.12), 2)  # '0.12'
        self.assertEqual(countDecimals(0.012), 3)  # '0.012'
        self.assertEqual(countDecimals(0.0012), 4)  # '0.0012'
        self.assertEqual(countDecimals(0.00012), 5)  # '0.00012'
        self.assertEqual(countDecimals(0.000012), 6)  # '1.2e-05'
        self.assertEqual(countDecimals(0.0000012), 7)  # '1.2e-06'
        self.assertEqual(countDecimals(0.00000012), 8)  # '1.2e-07'
        self.assertEqual(countDecimals(0.000000012), 9)  # '1.2e-08'
        self.assertEqual(countDecimals(0.0000000012), 10)  # '1.2e-09'
        self.assertEqual(countDecimals(0.00000000012), 11)  # '1.2e-10'
        self.assertEqual(countDecimals(-1.2), 1)  # '-1.2'
        self.assertEqual(countDecimals(-0.00000000012), 11)  # '-1.2e-10'
        self.assertEqual(countDecimals(1.03), 2)  # '1.03'
        self.assertEqual(countDecimals(1.003), 3)  # '1.003'
        self.assertEqual(countDecimals(1.0003), 4)  # '1.0003'
        self.assertEqual(countDecimals(1.00003), 5)  # '1.00003'
        self.assertEqual(countDecimals(1.000003), 6)  # '1.000003'
        self.assertEqual(countDecimals(1.0000003), 7)  # '1.0000003'
        self.assertEqual(countDecimals(1.00000003), 8)  # '1.00000003'
        self.assertEqual(countDecimals(1.000000003), 9)  # '1.000000003'
        self.assertEqual(countDecimals(1.0000000003), 10)  # '1.0000000003'
        self.assertEqual(countDecimals(-1.03), 2)  # '-1.03'
        self.assertEqual(countDecimals(-1.0000000003), 10)  # '-1.0000000003'

class TestToJsLikeFloats(TestCase):
    def testToJsLikeFloats(self):
        self.assertEqual(
            toJsLikeFloats('{"nonce":10,"operation":{"ref":"/afan","type":"SET_VALUE","value":0.0001},"timestamp":123}'),
            '{"nonce":10,"operation":{"ref":"/afan","type":"SET_VALUE","value":0.0001},"timestamp":123}')
        self.assertEqual(
            toJsLikeFloats('{"nonce":10,"operation":{"ref":"/afan","type":"SET_VALUE","value":1e-05},"timestamp":123}'),
            '{"nonce":10,"operation":{"ref":"/afan","type":"SET_VALUE","value":0.00001},"timestamp":123}')
        self.assertEqual(
            toJsLikeFloats('{"nonce":10,"operation":{"ref":"/afan","type":"SET_VALUE","value":1e-06},"timestamp":123}'),
            '{"nonce":10,"operation":{"ref":"/afan","type":"SET_VALUE","value":0.000001},"timestamp":123}')
        self.assertEqual(
            toJsLikeFloats('{"nonce":10,"operation":{"ref":"/afan","type":"SET_VALUE","value":1e-07},"timestamp":123}'),
            '{"nonce":10,"operation":{"ref":"/afan","type":"SET_VALUE","value":1e-07},"timestamp":123}')
        self.assertEqual(
            toJsLikeFloats('{"nonce":10,"operation":{"ref":"/afan","type":"SET_VALUE","value":0.00012},"timestamp":123}'),
            '{"nonce":10,"operation":{"ref":"/afan","type":"SET_VALUE","value":0.00012},"timestamp":123}')
        self.assertEqual(
            toJsLikeFloats('{"nonce":10,"operation":{"ref":"/afan","type":"SET_VALUE","value":1.2e-05},"timestamp":123}'),
            '{"nonce":10,"operation":{"ref":"/afan","type":"SET_VALUE","value":0.000012},"timestamp":123}')
        self.assertEqual(
            toJsLikeFloats('{"nonce":10,"operation":{"ref":"/afan","type":"SET_VALUE","value":1.2e-06},"timestamp":123}'),
            '{"nonce":10,"operation":{"ref":"/afan","type":"SET_VALUE","value":0.0000012},"timestamp":123}')
        self.assertEqual(
            toJsLikeFloats('{"nonce":10,"operation":{"ref":"/afan","type":"SET_VALUE","value":1.2e-07},"timestamp":123}'),
            '{"nonce":10,"operation":{"ref":"/afan","type":"SET_VALUE","value":1.2e-07},"timestamp":123}')
        self.assertEqual(
            toJsLikeFloats('{"nonce":10,"operation":{"ref":"/afan","type":"SET_VALUE","value":-0.0001},"timestamp":123}'),
            '{"nonce":10,"operation":{"ref":"/afan","type":"SET_VALUE","value":-0.0001},"timestamp":123}')
        self.assertEqual(
            toJsLikeFloats('{"nonce":10,"operation":{"ref":"/afan","type":"SET_VALUE","value":-1e-05},"timestamp":123}'),
            '{"nonce":10,"operation":{"ref":"/afan","type":"SET_VALUE","value":-0.00001},"timestamp":123}')
        self.assertEqual(
            toJsLikeFloats('{"nonce":10,"operation":{"ref":"/afan","type":"SET_VALUE","value":-1e-06},"timestamp":123}'),
            '{"nonce":10,"operation":{"ref":"/afan","type":"SET_VALUE","value":-0.000001},"timestamp":123}')
        self.assertEqual(
            toJsLikeFloats('{"nonce":10,"operation":{"ref":"/afan","type":"SET_VALUE","value":-1e-07},"timestamp":123}'),
            '{"nonce":10,"operation":{"ref":"/afan","type":"SET_VALUE","value":-1e-07},"timestamp":123}')
        self.assertEqual(
            toJsLikeFloats('{"nonce":10,"operation":{"ref":"/afan","type":"SET_VALUE","value":-0.00012},"timestamp":123}'),
            '{"nonce":10,"operation":{"ref":"/afan","type":"SET_VALUE","value":-0.00012},"timestamp":123}')
        self.assertEqual(
            toJsLikeFloats('{"nonce":10,"operation":{"ref":"/afan","type":"SET_VALUE","value":-1.2e-05},"timestamp":123}'),
            '{"nonce":10,"operation":{"ref":"/afan","type":"SET_VALUE","value":-0.000012},"timestamp":123}')
        self.assertEqual(
            toJsLikeFloats('{"nonce":10,"operation":{"ref":"/afan","type":"SET_VALUE","value":-1.2e-06},"timestamp":123}'),
            '{"nonce":10,"operation":{"ref":"/afan","type":"SET_VALUE","value":-0.0000012},"timestamp":123}')
        self.assertEqual(
            toJsLikeFloats('{"nonce":10,"operation":{"ref":"/afan","type":"SET_VALUE","value":-1.2e-07},"timestamp":123}'),
            '{"nonce":10,"operation":{"ref":"/afan","type":"SET_VALUE","value":-1.2e-07},"timestamp":123}')

class TestToJsonString(TestCase):
    def testToJsonString(self):
        txBody = TransactionBody(
            operation=SetOperation(
                ref="/afan",
                value=100,
                type="SET_VALUE",
            ),
            nonce=10,
            timestamp=123,
        )
        self.assertEqual(
            toJsonString(txBody),
            '{"nonce":10,"operation":{"ref":"/afan","type":"SET_VALUE","value":100},"timestamp":123}')

    def testToJsonStringWithFloatValueWithoutExponent(self):
        txBody = TransactionBody(
            operation=SetOperation(
                ref="/afan",
                value=1.000003,  # '1.000003'
                type="SET_VALUE",
            ),
            nonce=10,
            timestamp=123,
        )
        self.assertEqual(
            toJsonString(txBody),
            '{"nonce":10,"operation":{"ref":"/afan","type":"SET_VALUE","value":1.000003},"timestamp":123}')

    def testToJsonStringWithFloatValueWithExponent4(self):
        txBody = TransactionBody(
            operation=SetOperation(
                ref="/afan",
                value=0.00012,  # '0.00012'
                type="SET_VALUE",
            ),
            nonce=10,
            timestamp=123,
        )
        self.assertEqual(
            toJsonString(txBody),
            '{"nonce":10,"operation":{"ref":"/afan","type":"SET_VALUE","value":0.00012},"timestamp":123}')  # 0.00012

    def testToJsonStringWithFloatValueWithExponent5(self):
        txBody = TransactionBody(
            operation=SetOperation(
                ref="/afan",
                value=0.000012,  # '1.2e-05'
                type="SET_VALUE",
            ),
            nonce=10,
            timestamp=123,
        )
        self.assertEqual(
            toJsonString(txBody),
            '{"nonce":10,"operation":{"ref":"/afan","type":"SET_VALUE","value":0.000012},"timestamp":123}')  # 0.000012

    def testToJsonStringWithFloatValueWithExponent6(self):
        txBody = TransactionBody(
            operation=SetOperation(
                ref="/afan",
                value=0.0000012,  # '1.2e-06'
                type="SET_VALUE",
            ),
            nonce=10,
            timestamp=123,
        )
        self.assertEqual(
            toJsonString(txBody),
            '{"nonce":10,"operation":{"ref":"/afan","type":"SET_VALUE","value":0.0000012},"timestamp":123}')  # 0.0000012

    def testToJsonStringWithFloatValueWithExponent7(self):
        txBody = TransactionBody(
            operation=SetOperation(
                ref="/afan",
                value=0.00000012,  # '1.2e-07'
                type="SET_VALUE",
            ),
            nonce=10,
            timestamp=123,
        )
        self.assertEqual(
            toJsonString(txBody),
            '{"nonce":10,"operation":{"ref":"/afan","type":"SET_VALUE","value":1.2e-07},"timestamp":123}')  # 1.2e-07

    def testToJsonStringWithNegativeFloatValueWithExponent5(self):
        txBody = TransactionBody(
            operation=SetOperation(
                ref="/afan",
                value=-0.000012,  # '-1.2e-05'
                type="SET_VALUE",
            ),
            nonce=10,
            timestamp=123,
        )
        self.assertEqual(
            toJsonString(txBody),
            '{"nonce":10,"operation":{"ref":"/afan","type":"SET_VALUE","value":-0.000012},"timestamp":123}')  # -0.000012

    def testToJsonStringWithNegativeFloatValueWithExponent6(self):
        txBody = TransactionBody(
            operation=SetOperation(
                ref="/afan",
                value=-0.0000012,  # '-1.2e-06'
                type="SET_VALUE",
            ),
            nonce=10,
            timestamp=123,
        )
        self.assertEqual(
            toJsonString(txBody),
            '{"nonce":10,"operation":{"ref":"/afan","type":"SET_VALUE","value":-0.0000012},"timestamp":123}')  # -0.0000012

    def testToJsonStringWithNegativeFloatValueWithExponent7(self):
        txBody = TransactionBody(
            operation=SetOperation(
                ref="/afan",
                value=-0.00000012,  # '-1.2e-07'
                type="SET_VALUE",
            ),
            nonce=10,
            timestamp=123,
        )
        self.assertEqual(
            toJsonString(txBody),
            '{"nonce":10,"operation":{"ref":"/afan","type":"SET_VALUE","value":-1.2e-07},"timestamp":123}')  # -1.2e-07

class TestByteToHex(TestCase):
    def testByteToHex(self):
        byt = bytes.fromhex("5b9ac8")
        hex = bytesToHex(byt)
        self.assertEqual(hex, "0x5b9ac8")

    def testByteToHexEmptyBytes(self):
        byt = bytes(0)
        hex = bytesToHex(byt)
        self.assertEqual(hex, "0x")

class TestIsValidPrivate(TestCase):
    SECP256K1_N: int = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141

    def testIsValidPrivateShortInput(self):
        tmp = "0011223344"
        self.assertFalse(isValidPrivate(bytes.fromhex(tmp)))

    def testIsValidPrivateTooBigInput(self):
        tmp = "3a443d8381a6798a70c6ff9304bdc8cb0163c23211d11628fae52ef9e0dca11a001cf066d56a8156fc201cd5df8a36ef694eecd258903fca7086c1fae7441e1d"
        self.assertFalse(isValidPrivate(bytes.fromhex(tmp)))
    
    def testIsValidPrivateInvalidCurveZero(self):
        tmp = "0000000000000000000000000000000000000000000000000000000000000000"
        self.assertFalse(isValidPrivate(bytes.fromhex(tmp)))

    def testIsValidPrivateInvalidCurveEqN(self):
        self.assertFalse(isValidPrivate(self.SECP256K1_N.to_bytes(32, "big")))
    
    def testIsValidPrivateInvalidCurveGtN(self):
        self.assertFalse(isValidPrivate((self.SECP256K1_N + 1).to_bytes(32, "big")))

    def testIsValidPrivateWork(self):
        self.assertTrue(isValidPrivate((self.SECP256K1_N - 1).to_bytes(32, "big")))

class TestIsValidPublic(TestCase):
    def testIsValid(self):
        pubKey = "3a443d8381a6798a70c6ff9304bdc8cb0163c23211d11628fae52ef9e0dca11a001cf066d56a8156fc201cd5df8a36ef694eecd258903fca7086c1fae7441e1d"
        self.assertTrue(isValidPublic(bytes.fromhex(pubKey)))

    def testIsValidPublicShortInput(self):
        pubKey = "3a443d8381a6798a70c6ff9304bdc8cb0163c23211d11628fae52ef9e0dca11a001cf066d56a8156fc201cd5df8a36ef694eecd258903fca7086c1fae744"
        self.assertFalse(isValidPublic(bytes.fromhex(pubKey)))
    
    def testIsValidPublicBigInput(self):
        pubKey = "3a443d8381a6798a70c6ff9304bdc8cb0163c23211d11628fae52ef9e0dca11a001cf066d56a8156fc201cd5df8a36ef694eecd258903fca7086c1fae7441e1d00"
        self.assertFalse(isValidPublic(bytes.fromhex(pubKey)))

    def testIsValidPublicSEC1Key(self):
        pubKey = "043a443d8381a6798a70c6ff9304bdc8cb0163c23211d11628fae52ef9e0dca11a001cf066d56a8156fc201cd5df8a36ef694eecd258903fca7086c1fae7441e1d"
        self.assertFalse(isValidPublic(bytes.fromhex(pubKey)))
        self.assertTrue(isValidPublic(bytes.fromhex(pubKey), True))

    def testIsValidPublicInvalidSEC1Key(self):
        pubKey = "023a443d8381a6798a70c6ff9304bdc8cb0163c23211d11628fae52ef9e0dca11a001cf066d56a8156fc201cd5df8a36ef694eecd258903fca7086c1fae7441e1d"
        self.assertFalse(isValidPublic(bytes.fromhex(pubKey), True))

    def testIsValidPublicCompressedSEC1Key(self):
        pubKey = "033a443d8381a6798a70c6ff9304bdc8cb0163c23211d11628fae52ef9e0dca11a"
        self.assertTrue(isValidPublic(bytes.fromhex(pubKey), True))

class TestIsValidAddress(TestCase):
    def testIsValidAddress(self):
        self.assertTrue(isValidAddress(address))
        self.assertFalse(isValidAddress(address[1:]))

    def testIsValidAddressNonChecksummed(self):
        self.assertTrue(isValidAddress("0x" + address[2:].upper()))
        self.assertTrue(isValidAddress(address.lower()))

class TestAreSameAddress(TestCase):
    def testAreSameAddress(self):
        self.assertTrue(address, "0x" + address[2:].upper())
        self.assertTrue(address, address.lower())

class TestPubToAddress(TestCase):
    def testPubToAddress(self):
        pubKey = "3a443d8381a6798a70c6ff9304bdc8cb0163c23211d11628fae52ef9e0dca11a001cf066d56a8156fc201cd5df8a36ef694eecd258903fca7086c1fae7441e1d"
        address = "2f015c60e0be116b1f0cd534704db9c92118fb6a"
        self.assertEqual(pubToAddress(bytes.fromhex(pubKey)).hex(), address)

    def testPubToAddressSEC1(self):
        pubKey = "043a443d8381a6798a70c6ff9304bdc8cb0163c23211d11628fae52ef9e0dca11a001cf066d56a8156fc201cd5df8a36ef694eecd258903fca7086c1fae7441e1d"
        address = "2f015c60e0be116b1f0cd534704db9c92118fb6a"
        self.assertEqual(pubToAddress(bytes.fromhex(pubKey), True).hex(), address)

    def testPubToAddressInvalid(self):
        pubKey = "3a443d8381a6798a70c6ff9304bdc8cb0163c23211d11628fae52ef9e0dca11a001cf066d56a8156fc201cd5df8a36ef694eecd258903fca7086c1fae744"
        with self.assertRaises(ValueError):
            pubToAddress(bytes.fromhex(pubKey))
        
    def testPubToAddress0x(self):
        pubKey = "0x3a443d8381a6798a70c6ff9304bdc8cb0163c23211d11628fae52ef9e0dca11a001cf066d56a8156fc201cd5df8a36ef694eecd258903fca7086c1fae7441e1d"
        address = "2f015c60e0be116b1f0cd534704db9c92118fb6a"
        self.assertEqual(pubToAddress(pubKey).hex(), address)

class TestAddHexPrefix(TestCase):
    string = "d658a4b8247c14868f3c512fa5cbb6e458e4a989"
    def testAddHexPrefix(self):
        self.assertEqual(addHexPrefix(self.string), "0x" + self.string)
        with self.assertRaises(AttributeError):
            addHexPrefix(1)

class TestPrivateToPublic(TestCase):
    def testPrivateToPublic(self):
        self.assertEqual(privateToPublic(sk), pk)

class TestPrivateToAddress(TestCase):
    def testPrivateToAddress(self):
        self.assertEqual(privateToAddress(sk), address)

class TestV3KeyStore(TestCase):
    def testV3KeyStore(self):
        v3keystore = V3Keystore.fromPrivateKey(sk, v3KeystorePassword)
        self.assertEqual(v3keystore.toPrivateKey(v3KeystorePassword), sk)
    
    def testV3KeyStoreKDF(self):
        for kdf in v3KeystoreKDFList:
            v3keystore = V3Keystore.fromPrivateKey(sk, v3KeystorePassword, V3KeystoreOptions(kdf=kdf))
            self.assertEqual(v3keystore.toPrivateKey(v3KeystorePassword), sk, msg=json)

    def testV3KeyStoreCipher(self):
        for cipher in v3KeystoreCipherList:
            v3keystore = V3Keystore.fromPrivateKey(sk, v3KeystorePassword, V3KeystoreOptions(cipher=cipher))
            self.assertEqual(v3keystore.toPrivateKey(v3KeystorePassword), sk, msg=json)

    def testV3KeyStoreFromJSON(self):
        for json in v3KeystoreJSONList:
            v3keystoreFromJSON = V3Keystore.fromJSON(json)
            self.assertEqual(v3keystoreFromJSON.toPrivateKey(v3KeystorePassword), sk, msg=json)

    def testV3KeyStoreFromFixed(self):
        v3keystore = V3Keystore.fromPrivateKey(
            sk, v3KeystorePassword,
            V3KeystoreOptions(uuid=v3KeystoreFixedUUID, iv=v3KeystoreFixedIV, salt=v3KeystoreFixedSalt)
        )
        self.assertEqual(str(v3keystore), v3KeystoreFixedJSON)
        
class TestToBytes(TestCase):
    def testToBytes(self):
        # bytes
        self.assertEqual(toBytes(bytes(0)), bytes(0))
        # array
        self.assertEqual(toBytes([]), bytes(0))
        # str
        self.assertEqual(toBytes("11"), bytes([49, 49]))
        self.assertEqual(toBytes("0x11"), bytes([17]))
        self.assertEqual(toBytes("1234").hex(), "31323334")
        self.assertEqual(toBytes("0x1234").hex(), "1234")
        # int
        self.assertEqual(toBytes(1), bytes([1]))
        # None
        self.assertEqual(toBytes(None), bytes(0))
    
    def testToBytesFail(self):
        with self.assertRaises(TypeError):
            toBytes({"test": 1})

class TestHashTransaction(TestCase):
    def testHashTransaction(self):
        txHash = hashTransaction(tx)
        differentHash = hashTransaction(txDifferent)
        self.assertNotEqual(txHash, differentHash)

class TestHashMessage(TestCase):
    def testHashMessage(self):
        hash = hashMessage(message)
        self.assertEqual(hash, bytes.fromhex("14894951ffca216088cba18b434a31fe88cd706886c5f64e0582711d57757ed6"))

class TestToChecksumAddress(TestCase):
    def testToChecksumAddress(self):
        for address in checksumAddresses:
            self.assertEqual(toChecksumAddress(address.lower()), address)

class TestEcSignTransaction(TestCase):
    def testEcSignTransaction(self):
        signature = ecSignTransaction(tx, sk)
        self.assertTrue(ecVerifySig(tx, signature, address))

class TestEcSignMessage(TestCase):
    def testEcSignMessage(self):
        signature = ecSignMessage(message, sk)
        self.assertTrue(ecVerifySig(message, signature, address))

class TestEcVerifySig(TestCase):
    def testEcVerifySig(self):
        self.assertTrue(ecVerifySig(message, correctSignature, address))
    
    def testEcVerifySigCorruptSignature(self):
        corruptSignature = "0x2" + correctSignature[3:]
        self.assertFalse(ecVerifySig(message, corruptSignature, address))
    
    def testEcVerifySigIncorrectAddress(self):
        self.assertFalse(ecVerifySig(message, correctSignature, "0x1D982a9bb0A224618Ac369Ff0a6B8B1c51E5c472"))

    def testEcVerifySigDifferentMessage(self):
        self.assertFalse(ecVerifySig("Hello World", correctSignature, address))

class TestMnemonicToPrivatekey(TestCase):
    def testMnemonicToPrivatekey(self):
        self.assertEqual(mnemonicToPrivatekey(mnemonic), mnemonicPrivateKey)

class TestEncryption(TestCase):
    def testEncryptToDecrypt(self):
        tmpEncrypted = encryptWithPublicKey(pk, message)
        decrypted = decryptWithPrivateKey(sk, tmpEncrypted)
        self.assertEqual(message, decrypted)

    def testDecryptEncrypted(self):
        decrypted = decryptWithPrivateKey(sk, encrypted)
        self.assertEqual(message, decrypted)

# TODO(kriii): Add tests after implement `encode`.
# class TestEncode(TestCase):

# TODO(kriii): Add tests after implement `decode`.
# class TestDecode(TestCase):

