import re
import json
import time
from typing import Any, Union
from secrets import token_bytes
from Crypto import Cipher
from Crypto.Cipher import AES
from Crypto.Hash import keccak as _keccak
from Crypto.Hash import HMAC, SHA256, SHA512
from Crypto.Util.Padding import pad, unpad
from coincurve import PrivateKey, PublicKey
from coincurve.ecdsa import deserialize_recoverable, recoverable_convert, cdata_to_der
from coincurve.utils import validate_secret
from mnemonic import Mnemonic
# TODO(kriii): Need to replace bip32 package or wait for the type hint.
from bip32 import BIP32 # type: ignore
from ain.types import ECDSASignature, ECIESEncrypted, TransactionBody

def encodeVarInt(number: int) -> bytes:
    """
    Encodes the number as bitcoin variable length integer
    """
    MAX_SAFE_INTEGER = 9007199254740991
    if number < 0 or number > MAX_SAFE_INTEGER:
        raise ValueError("Number out of range")

    if number < 0xfd:
        byte = 1
    elif number <= 0xffff:
        number = (number << 8) + 0xfd
        byte = 3
    elif number <= 0xffffffff:
        number = (number << 8) + 0xfe
        byte = 5
    else:
        number = (number << 8) + 0xff
        byte = 9

    return number.to_bytes(byte, "little")

SIGNED_MESSAGE_PREFIX = "AINetwork Signed Message:\n"
SIGNED_MESSAGE_PREFIX_BYTES = bytes(SIGNED_MESSAGE_PREFIX, "utf-8")
SIGNED_MESSAGE_PREFIX_LENGTH = encodeVarInt(len(SIGNED_MESSAGE_PREFIX))
AIN_HD_DERIVATION_PATH = "m/44'/412'/0'/0/"

def getTimestamp() -> int:
    """
    Returns the current timestamp.
    """
    return int(time.time() * 1000)

def addHexPrefix(string: str) -> str:
    """
    Adds '0x' to the given string if it does not already start with '0x'.
    """
    return string if isHexPrefixed(string) else ("0x" + string)

def bytesToHex(input: bytes) -> str:
    """
    Converts the given bytes into a hex prefixed hex string.
    """
    return "0x" + input.hex()

def isValidAddress(string: str) -> bool:
    """
    Checks if the given string is a valid address.
    """
    pattern = re.compile("0x[0-9a-fA-F]{40}")
    return pattern.fullmatch(string) is not None

def isHexString(string: str) -> bool:
    """
    Checks if the given string is a hex string.
    """
    pattern = re.compile("0x[0-9a-fA-F]*")
    return pattern.fullmatch(string) is not None

def isHexPrefixed(string: str) -> bool:
    """
    Checks if the given string is prefixed with `0x`.
    """
    return string.startswith("0x")

def stripHexPrefix(string: str) -> str:
    """
    Removes `0x` from the given string.
    """
    return string[2:] if isHexPrefixed(string) else string

def padToEven(string: str) -> str:
    """
    Pads the given string to have an even length.
    """
    return string if len(string) % 2 == 0 else ("0" + string)

def toBytes(input: Any) -> bytes:
    """
    Attempts to turn a value into a bytes,
    As input it supports bytes, list(of ints), string, int, None.
    This function is equivalent to `toBuffer` from `@ainblockchain/ain-util`.
    """
    if type(input) is bytes:
        pass
    elif type(input) is list:
        input = bytes(input)
    elif type(input) is str:
        if isHexString(input):
            input = bytes.fromhex(padToEven(stripHexPrefix(input)))
        else:
            input = bytes(input, "utf-8")
    elif type(input) is int:
        input = bytes.fromhex(padToEven(stripHexPrefix(hex(input))))
    elif input is None:
        input = bytes(0)
    else:
        raise TypeError("Invalid type")
    return input

def toChecksumAddress(address: str) -> str:
    """
    Returns a checksummed address.
    """
    if not isValidAddress(address):
        raise ValueError("Invalid address")

    address = stripHexPrefix(address).lower()
    hash = keccak(address).hex()
    ret = "0x"

    for i in range(len(address)):
        if int(hash[i], base=16) >= 8:
            ret += address[i].upper()
        else:
            ret += address[i]

    return ret

def keccak(input: Any, bits: int = 256) -> bytes:
    """
    Creates Keccak hash of the input.
    """
    input = toBytes(input)
    k = _keccak.new(digest_bits=bits)
    k.update(input)
    return k.digest()

def hashTransaction(transaction: Union[TransactionBody, str]):
    """
    Generates keccak hash using a transaction body.
    """
    if type(transaction) is TransactionBody:
        transaction = json.dumps(
            transaction.__dict__,
            default=lambda o: o.__dict__,
            separators=(",", ":"),
            sort_keys=True
        )
    return keccak(keccak(transaction))

def hashMessage(message: Any):
    """
    Returns the bitcoin's varint encoding of keccak-256 hash of `message`,
    prefixed with the header `AINetwork Signed Message:`.
    """
    msgBytes = toBytes(message)
    msgLenBytes = encodeVarInt(len(msgBytes))
    dataBytes = bytes(
        bytearray(SIGNED_MESSAGE_PREFIX_LENGTH)
        + bytearray(SIGNED_MESSAGE_PREFIX_BYTES)
        + bytearray(msgLenBytes)
        + bytearray(msgBytes)
    )
    return keccak(keccak(dataBytes))

def ecSignHash(msgHash: bytes, privateKey: bytes, chainId: int = None) -> ECDSASignature:
    """
    Returns the ECDSA signature of a message hash.
    """
    pbK = PrivateKey(privateKey)
    sig = pbK.sign_recoverable(msgHash, hasher=None)
    r = sig[0:32]
    s = sig[32:64]
    v = sig[64] + (27 if chainId is None else chainId * 2 + 35)
    return ECDSASignature(r, s, v)

def ecSignMessage(message: Any, privateKey: bytes, chainId: int = None) -> str:
    """
    igns a message with a private key and returns a string signature.
    """
    hashedMsg = hashMessage(message)
    signature = ecSignHash(hashedMsg, privateKey, chainId)
    return "0x" + hashedMsg.hex() + signature.r.hex() + signature.s.hex() + toBytes(signature.v).hex()

def ecSignTransaction(txData: TransactionBody, privateKey: bytes, chainId: int = None) -> str:
    """
    Signs a transaction body with a private key and returns a string signature.
    """
    hashedTx = hashTransaction(txData)
    signature = ecSignHash(hashedTx, privateKey, chainId)
    return "0x" + hashedTx.hex() + signature.r.hex() + signature.s.hex() + toBytes(signature.v).hex()

def ecRecoverPub(msgHash: bytes, signature: ECDSASignature, chainId: int = None) -> bytes:
    """
    ECDSA public key recovery from signature.
    Returns Recovered public key.
    """
    recovery = signature.v - (27 if chainId is None else chainId * 2 + 35)
    if recovery != 0 and recovery != 1:
        raise ValueError("Invalid signature v value")
    cSig = bytes(bytearray(signature.r) + bytearray(signature.s) + bytearray([recovery]))
    senderPubKey = PublicKey.from_signature_and_message(cSig, msgHash, hasher=None)
    nSig = cdata_to_der(recoverable_convert(deserialize_recoverable(cSig)))
    if not senderPubKey.verify(nSig, msgHash, hasher=None):
        raise ValueError('Public key verify failed')
    return senderPubKey.format(False)

def ecVerifySig(data: Any, signature: str, address: str, chainId: int = None):
    """
    Checks if the signature is valid.
    """
    sigBytes = toBytes(signature)
    lenHash = len(sigBytes) - 65
    hashedData = sigBytes[:lenHash]
    if type(data) is TransactionBody:
        if hashedData != hashTransaction(data):
            return False
    else:
        if hashedData != hashMessage(data):
            return False

    sig = ECDSASignature.fromSignature(sigBytes[lenHash:])
    try:
        pub = ecRecoverPub(hashedData, sig, chainId)
    except ValueError:
        return False

    addr = bytesToHex(pubToAddress(pub[1:]))
    return areSameAddresses(address, addr)

def isValidPrivate(privateKey: bytes) -> bool:
    """
    Checks whether the `privateKey` is a valid private key (follows the rules of the
    curve secp256k1).
    """
    try:
        if len(privateKey) != 32:
            return False
        validate_secret(privateKey)
        return True
    except:
        return False

# TODO(kriii): implement this function.
def isValidPublic(publicKey: bytes, isSEC1: bool = False):
    """
    Checks whether the `publicKey` is a valid public key (follows the rules of the
    curve secp256k1 and meets the AIN requirements).

    args:
        publicKey (bytes): The two points of an uncompressed key, unless sanitize is enabled
        isSEC1 (bool): Accept public keys in other formats
    """
    pass

def areSameAddresses(address1: str, address2: str) -> bool:
    """
    Checks if the two addresses are the same.
    """
    return toChecksumAddress(address1) == toChecksumAddress(address2)

def privateToPublic(privateKey: bytes) -> bytes:
    """
    Returns the public key of a given private key.
    
    args:
        privateKey (bytes): A private key must be 256 bits wide
    """
    prK = PrivateKey(privateKey)
    return prK.public_key.format(False)[1:]

# TODO(kriii): Support `isSEC1`.
def pubToAddress(publicKey: Union[bytes, str], isSEC1: bool = False) -> bytes:
    """
    Returns the AI Network address of a given public key.

    args:
        publicKey (Union[bytes, str]):
            AIN public key | SEC1 encoded public key
            When the type is `str`, it must be hex prefixed
        isSEC1 (bool) : Key is SEC1 encoded

    returns:
        bytes: lower 160 bits of the hash of `publicKey`
    """
    if type(publicKey) is str:
        publicKeyBytes = toBytes(publicKey)
    elif type(publicKey) is bytes:
        publicKeyBytes = publicKey
    else:
        raise ValueError("Invalid public key type")

    if len(publicKeyBytes) != 64:
        raise ValueError("Invalid public key")
    return keccak(publicKeyBytes)[-20:]

def privateToAddress(privateKey: bytes) -> str:
    return toChecksumAddress(bytesToHex(pubToAddress(privateToPublic(privateKey))))

def generateMnemonic() -> str:
    """
    Returns a randomly generated mnemonic.
    """
    return Mnemonic("english").generate()

def mnemonicToPrivatekey(mnemonic: str, index: int = 0) -> bytes:
    """
    Returns an private key with the given mnemonic.
    """
    if index < 0:
        raise ValueError("index should be greater than 0")

    if not Mnemonic("english").check(mnemonic):
        raise ValueError("Invalid mnemonic")
    
    seed = Mnemonic.to_seed(mnemonic)
    bip32 = BIP32.from_seed(seed)
    path = AIN_HD_DERIVATION_PATH + f"{index}"
    return bip32.get_privkey_from_path(path)

# NOTE(kriii): Referenced https://github.com/bitchan/eccrypto/blob/master/index.js#L195-L258
def encryptWithPublicKey(publicKey: Union[bytes, str], message: str) -> ECIESEncrypted:
    """
    Encrypts message with publicKey.
    """
    if type(publicKey) is str:
        publicKeyBytes = bytes.fromhex(publicKey)
    elif type(publicKey) is bytes:
        publicKeyBytes = publicKey
    else:
        raise ValueError("Invalid public key type")

    if len(publicKeyBytes) == 64:
        publicKeyBytes = bytes([4]) + publicKeyBytes

    pbK = PublicKey(publicKeyBytes)
    epK = PrivateKey()
    ephemPublicKey = epK.public_key.format(False)
    shared = pbK.multiply(epK.secret)
    derive = shared.format(True)[1:]
    hash = SHA512.new()
    hash.update(derive)
    iv = token_bytes(16)
    encKey = hash.digest()[0:32]
    aes = AES.new(encKey, AES.MODE_CBC, iv=iv)
    ciphertext = aes.encrypt(pad(toBytes(message), 16))
    macKey = hash.digest()[32:]
    hmac = HMAC.new(macKey, digestmod=SHA256)
    hmac.update(iv + ephemPublicKey + ciphertext)
    mac = hmac.digest()

    return ECIESEncrypted(iv, ephemPublicKey, ciphertext, mac)

def decryptWithPrivateKey(privateKey: Union[bytes, str], encrypted: ECIESEncrypted) -> str:
    """
    Decrypts encrypted data with privateKey.
    """
    if type(privateKey) is str:
        privateKeyBytes = bytes.fromhex(privateKey)
    elif type(privateKey) is bytes:
        privateKeyBytes = privateKey
    else:
        raise ValueError("Invalid public key type")

    prK = PrivateKey(privateKeyBytes)
    epK = PublicKey(encrypted.ephemPublicKey)
    shared = epK.multiply(prK.secret)
    derive = shared.format(True)[1:]
    hash = SHA512.new()
    hash.update(derive)
    encKey = hash.digest()[0:32]
    macKey = hash.digest()[32:]
    hmac = HMAC.new(macKey, digestmod=SHA256)
    hmac.update(encrypted.iv + encrypted.ephemPublicKey + encrypted.ciphertext)
    mac = hmac.digest()

    if mac != encrypted.mac:
        raise ValueError("Bad MAC")

    aes = AES.new(encKey, AES.MODE_CBC, iv=encrypted.iv)
    plaintext = unpad(aes.decrypt(encrypted.ciphertext), 16)
    return plaintext.decode("utf-8")

# TODO(kriii): implement this function.
def privateToV3Keystore():
    pass

# TODO(kriii): implement this function.
def v3KeystoreToPrivate():
    pass