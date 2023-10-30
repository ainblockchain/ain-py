import re
import math
import simplejson
import time
from typing import Any, Union
from secrets import token_bytes
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
    """Encodes the number as bitcoin variable length integer

    Args:
        number (int): A number that you want to encode.

    Returns:
        bytes: The encoded number as bitcoin variable length integer.
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
# TODO(platfowner): Migrate to Ethereum HD derivation path 'm/44'/60'/0'/0/'.
AIN_HD_DERIVATION_PATH = "m/44'/412'/0'/0/"  # The hardware wallet derivation path of AIN

def getTimestamp() -> int:
    """Gets the current unix timestamp.
    
    Returns:
        int: The current unix timestamp.
    """
    return int(time.time() * 1000)

def addHexPrefix(input: str) -> str:
    """Adds the hex prefix('0x') to the given string if it does not hex prefixed.
    
    Args:
        input (str): The string that you want to add prefix.
    
    Returns:
        str: The hex prefixed string.
    """
    return input if isHexPrefixed(input) else ("0x" + input)

def bytesToHex(input: bytes) -> str:
    """Converts the given bytes into the hex prefixed hex string.

    Args:
        input (bytes): The bytes that you want to convert into hex.

    Returns:
        str: The hex converted bytes.
    """
    return "0x" + input.hex()

def isValidAddress(address: str) -> bool:
    """Checks if the given string is a valid address.

    Args:
        address (str): The address that you want to check.

    Returns:
        bool: `True`, if the `address` is valid address.
            `False`, if not.
    """
    pattern = re.compile("0x[0-9a-fA-F]{40}")
    return pattern.fullmatch(address) is not None

def isHexString(input: str) -> bool:
    """Checks if the given string is a hex string.
    
    Args:
        input (str): The string that you want to check.
    
    Returns:
        bool: `True`, if the `input` is hex string.
            `False`, if not.
    """
    pattern = re.compile("0x[0-9a-fA-F]*")
    return pattern.fullmatch(input) is not None

def isHexPrefixed(input: str) -> bool:
    """Checks if the given string is prefixed with `0x`.
        
    Args:
        input (str): The string that you want to check.
    
    Returns:
        bool: `True`, if the `input` is hex prefixed.
            `False`, if not.
    """
    return input.startswith("0x")

def stripHexPrefix(input: str) -> str:
    """Strips `0x` from the given string, if that is hex prefixed.
    
    Args:
        input (str): The string that you want to strip.
    
    Returns:
        str: The hex prefix stripped string, if `input` is hex prefixed.
            `input` itself, if it not hex prefixed.
    """
    return input[2:] if isHexPrefixed(input) else input

def padToEven(input: str) -> str:
    """Pads the leading zero into the given string to have an even length.

    Args:
        input (str): The string that you want to pad.
    
    Returns:
        str: The leading zero padded string, if `input` is odd lengthed.
            `input` itself, if it is even lengthed.
    """
    return input if len(input) % 2 == 0 else ("0" + input)

def toBytes(input: Any) -> bytes:
    """Attempts to convert a input into a bytes,
    This function is equivalent to `toBuffer` from `@ainblockchain/ain-util`.

    Args:
        input: The input that you want to convert.
            It supports bytes, list(of ints), string, int, and None.
            If `input` is unsupported type, raises `TypeError`.

    Returns:
        bytes: The converted bytes.
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
    """Returns a checksummed address.

    Args:
        address (str): The address that you want to convert.
            If `address` isn't valid, raises `ValueError`.

    Returns:
        str: The checksummed address.
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
    """Creates the Keccak hash of the input.

    Args:
        input: The input that you want to create hash.
            Note that `input` will be converted with `toBytes` method.
            If `input` is unsupported type, raises `TypeError`.
        bits (int): The size of the hash, in (224, 456, 384, 512).
            Defaults to 256.
        
    Returns:
        bytes: The Keccak hash of the input.
    """
    inputBytes = toBytes(input)
    k = _keccak.new(digest_bits=bits)
    k.update(inputBytes)
    return k.digest()

def countDecimals(value: float) -> int:
    """Counts the given number's decimals.

    Args:
        value(float): The number.

    Returns:
        int: The decimal count.
    """
    valueString = str(value)
    if math.floor(value) == value :
        return 0
    p = re.compile(r'^-{0,1}(\d+\.{0,1}\d*)e-(\d+)$')
    matches = p.findall(valueString)
    if len(matches) > 0 and len(matches[0]) == 2:
        return int(matches[0][1]) + countDecimals(float(matches[0][0]))
    else :
        parts = valueString.split('.')
        if len(parts) >= 2 :
            return len(parts[1])
        return 0

def replaceFloat(matchObj):
    """Generates a replacement string for the given Match object.

    Args:
        matchObj(Any): The Match object.

    Returns:
        str: The replacement string.
    """
    value = float(matchObj.group(0))
    decimals = countDecimals(value)
    return (f'%.{decimals}f') % value

# NOTE(platfowner): This resolves float decimal issues (see https://github.com/ainblockchain/ain-py/issues/31).
def toJsLikeFloats(serialized: str) -> str:
    """Reformats float numbers to JavaScript-like formats.

    Args:
        serialized(str): The string to be reformatted.

    Returns:
        str: The reformatted string.
    """
    return re.sub(r'(\d+\.{0,1}\d*e-0[56]{1,1})', replaceFloat, serialized)

def toJsonString(obj: Any) -> str:
    """Serializes the given object to a JSON string.

    Args:
        obj (Any): The given object to serialize.

    Returns:
        str: The result of the serialization.
    """
    serialized = simplejson.dumps(
        obj.__dict__,
        default=lambda o: o.__dict__,
        separators=(",", ":"),
        sort_keys=True
    )
    return toJsLikeFloats(serialized)

def hashTransaction(transaction: Union[TransactionBody, str]) -> bytes:
    """Creates the Keccak-256 hash of the transaction body.

    Args:
        transaction (Union[TransactionBody, str]):
            The transaction that you want to create hash.

    Returns:
        bytes: The Keccak hash of the transaction.
    """
    if type(transaction) is TransactionBody:
        transaction = toJsonString(transaction)
    return keccak(keccak(transaction))

def hashMessage(message: Any) -> bytes:
    """Creates the bitcoin's varint encoding of Keccak-256 hash of the message,
    prefixed with the header `AINetwork Signed Message:`.

    Args:
        message: The message that you want to create hash.
            Note that `message` should be convertible with :meth:`toBytes`.
            If `message` is unsupported type, raises `TypeError`.
    
    Returns:
        bytes: The bitcoin's varint encoding of Keccak-256 hash of the message.
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

def ecSignHash(msgHash: bytes, privateKey: bytes, chainId: int = 0) -> ECDSASignature:
    """Returns the ECDSA signature of a message hash.

    Args:
        msgHash (bytes): The message hash.
        privateKey (bytes): The private key for the signature.
        chainId (int): The chain ID of the provider. Defaults to 0.

    Returns:
        ECDSASignature: The object of the ECDSA signature.
    """
    pbK = PrivateKey(privateKey)
    sig = pbK.sign_recoverable(msgHash, hasher=None)
    r = sig[0:32]
    s = sig[32:64]
    v = sig[64] + (27 if chainId == 0 else chainId * 2 + 35)
    return ECDSASignature(r, s, v)

def ecSignMessage(message: Any, privateKey: bytes, chainId: int = 0) -> str:
    """Signs a message with a private key and returns a string signature.

    Args:
        message: The message that you want to sign.
            Note that `message` should be convertible with :meth:`toBytes`.
            If `message` is unsupported type, raises `TypeError`.
        privateKey (bytes): The private key for the signature.
        chainId (int): The chain ID of the provider. Defaults to 0.
    
    Returns:
        str: The hex prefixed string signature.
    """
    hashedMsg = hashMessage(message)
    signature = ecSignHash(hashedMsg, privateKey, chainId)
    return "0x" + hashedMsg.hex() + signature.r.hex() + signature.s.hex() + toBytes(signature.v).hex()

def ecSignTransaction(txData: TransactionBody, privateKey: bytes, chainId: int = 0) -> str:
    """Signs a transaction body with a private key and returns a string signature.

    Args:
        txData (TransactionBody): The transaction that you want to sign.
        privateKey (bytes): The private key for the signature.
        chainId (int): The chain ID of the provider. Defaults to 0.

    Returns:
        str: The hex prefixed string signature.
    """
    hashedTx = hashTransaction(txData)
    signature = ecSignHash(hashedTx, privateKey, chainId)
    return "0x" + hashedTx.hex() + signature.r.hex() + signature.s.hex() + toBytes(signature.v).hex()

def ecRecoverPub(msgHash: bytes, signature: ECDSASignature, chainId: int = 0) -> bytes:
    """Recovers the public key from ECDSA signature.

    Args:
        msgHash (bytes): The hash of the message.
        signature (ECDSASignature): The object of the ECDSA signature.
        chainId (int): The chain ID of the provider. Defaults to 0.

    Returns:
        str: The recovered public key.
    """
    recovery = signature.v - (27 if chainId == 0 else chainId * 2 + 35)
    if recovery != 0 and recovery != 1:
        raise ValueError("Invalid signature v value")
    cSig = bytes(bytearray(signature.r) + bytearray(signature.s) + bytearray([recovery]))
    senderPubKey = PublicKey.from_signature_and_message(cSig, msgHash, hasher=None)
    nSig = cdata_to_der(recoverable_convert(deserialize_recoverable(cSig)))
    if not senderPubKey.verify(nSig, msgHash, hasher=None):
        raise ValueError('Public key verify failed')
    return senderPubKey.format(False)

def ecVerifySig(data: Any, signature: str, address: str, chainId: int = 0) -> bool:
    """Verifies if the signature is valid.

    Args:
        data: The message or transaction that you want to verify.
        signature (str): The hex prefixed string signature.
        address (str): The address of the signature.
        chainId (int): The chain ID of the provider. Defaults to 0.

    Returns:
        bool: `True`, if the given signature is a valid signature.
            `False`, if not.
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
    """Checks whether the `privateKey` is a valid private key
    (follows the rules of the curve `secp256k1`).

    Args:
        privateKey (bytes): The private key of the AIN blockchain account that you want to check.

    Returns:
        bool: `True`, if the given key is a valid private key.
            `False`, if not.
    """
    try:
        if len(privateKey) != 32:
            return False
        validate_secret(privateKey)
        return True
    except:
        return False

def isValidPublic(publicKey: bytes, isSEC1: bool = False) -> bool:
    """Checks whether the `publicKey` is a valid public key
    (follows the rules of the curve `secp256k1` and meets the AIN requirements).

    Args:
        publicKey (bytes): The public key of the AIN blockchain account that you want to check.
        isSEC1 (bool): If `True`, public key should be SEC1 encoded one.
            Defaults to `False`.
    
    Returns:
        bool: `True`, if the given key is a valid public key.
            `False`, if not.
    """
    try:
        if len(publicKey) == 64:
            publicKey = bytes([4]) + publicKey
        else:
            if not isSEC1:
                return False
        pk = PublicKey(publicKey)
    except ValueError:
        return False
    return True

def areSameAddresses(address1: str, address2: str) -> bool:
    """Checks if the two addresses are the same.
    
    Args:
        address1 (str): The first address.
        address2 (str): The second address.
    
    Returns:
        bool: `True`, if the two addresses are the same.
            `False`, if not.
    """
    return toChecksumAddress(address1) == toChecksumAddress(address2)

def privateToPublic(privateKey: bytes) -> bytes:
    """Returns the public key of a given private key.
    
    Args:
        privateKey (bytes): The private key of the AIN blockchain account.

    Returns:
        bytes:
            The public key of a given private key.
    """
    prK = PrivateKey(privateKey)
    return prK.public_key.format(False)[1:]

def pubToAddress(publicKey: Union[bytes, str], isSEC1: bool = False) -> bytes:
    """Returns the AIN blockchain address of the given public key,
    which is the lower 160 bits of the Keccak-256 hash of the public key.

    Args:
        publicKey (Union[bytes, str]): The public key of the AIN blockchain account or SEC1 encoded public key.
            When the type is `str`, it must be hex prefixed.
        isSEC1 (bool): If `True`, public key should be SEC1 encoded one.
            Defaults to `False`.

    Returns:
        bytes: The AIN blockchain address of the given public key.
    """
    if type(publicKey) is str:
        publicKeyBytes = toBytes(publicKey)
    elif type(publicKey) is bytes:
        publicKeyBytes = publicKey
    else:
        raise ValueError("Invalid public key type")

    if isSEC1 and len(publicKeyBytes) != 64:
        publicKeyBytes = PublicKey(publicKeyBytes).format(False)[1:]
    if len(publicKeyBytes) != 64:
        raise ValueError("Invalid public key")
    return keccak(publicKeyBytes)[-20:]

def privateToAddress(privateKey: bytes) -> str:
    """Returns the checksummed AIN blockchain address of the given private key.

    Args:
        privateKey (bytes): The private key of an AIN blockchain account.

    Returns:
        str: The checksummed AIN blockchain address of the given private key.
    """
    return toChecksumAddress(bytesToHex(pubToAddress(privateToPublic(privateKey))))

def generateMnemonic() -> str:
    """Generates the random english mnemonic.

    Returns:
        str: The randomly generated english mnemonic.
    """
    return Mnemonic("english").generate()

def mnemonicToPrivatekey(mnemonic: str, index: int = 0) -> bytes:
    """Returns an private key with the given mnemonic.

    Args:
        mnemonic (str): The mnemonic of account.
        index (int): The index of account. Defaults to 0.

    Returns:
        bytes: The private key with the given mnemonic.
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
    """Encrypts message with publicKey.

    Args:
        publicKey (Union[bytes, str]): The public key.
            When the type is `str`, it must be hex prefixed.
        message (str): The message.

    Returns:
        ECIESEncrypted: The object of the encrypted message.
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
    """Decrypts encrypted data with privateKey.

    Args:
        privateKey (Union[bytes, str]): The private key.
        encrypted (ECIESEncrypted): The ECIES encrypted object.
    
    Returns:
        str: The decrypted message.
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
