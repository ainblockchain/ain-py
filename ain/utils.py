import re
import json
import time
from typing import Any, Union
from Crypto.Hash import keccak as _keccak
from coincurve import PrivateKey
from ain.types import ECDSASignature, TransactionBody

def getTimestamp() -> int:
    """
    Gets a current timestamp.
    """
    return int(time.time() * 1000)

def isValidAddress(address: str) -> bool:
    pattern = re.compile("0x[0-9a-fA-F]{40}")
    return pattern.fullmatch(address) is not None

def isHexString(value: str) -> bool:
    pattern = re.compile("0x[0-9a-fA-F]*")
    return pattern.fullmatch(value) is not None

def isHexPrefixed(value: str) -> bool:
    return value[0:2] == "0x"

def stripHexPrefix(value: str) -> str:
    if isHexPrefixed(value):
        value = value[2:]
    return value

def padToEven(value: str) -> str:
    if len(value) % 2 == 1:
        value = "0" + value
    return value

def toBuffer(input: Any) -> bytes:
    if type(input) is bytes:
        pass
    elif type(input) is str:
        if isHexString(input):
            input = bytes.fromhex(padToEven(stripHexPrefix(input)))
        else:
            input = bytes(input, "utf-8")
    elif type(input) is int:
        input = bytes.fromhex(padToEven(stripHexPrefix(hex(input))))
    # TODO(kriii) : complete `toBuffer`
    return input

def bufferToHex(input: bytes) -> str:
    return "0x" + input.hex()

def toChecksumAddress(address: str) -> str:
    if not isValidAddress(address):
        raise ValueError("toChecksumAddress: Invalid address")

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
    input = toBuffer(input)
    k = _keccak.new(digest_bits=bits)
    k.update(input)
    return k.digest()

def pubToAddress(publicKey: Union[bytes, str]) -> bytes:
    return keccak(toBuffer(publicKey))[-20:]

def hashTransaction(transaction: Union[TransactionBody, str]):
    """
    Generates keccak hash using a transaction body.
    """
    if type(transaction) is not str:
        transaction = json.dumps(transaction, separators=(",", ":"), sort_keys=True)
    return keccak(keccak(transaction))

# TODO(kri) : implement code for string `privateKey`
def ecSignHash(msgHash: bytes, privateKey: PrivateKey, chainId: int = None) -> ECDSASignature:
    """
    Returns the ECDSA signature of a message hash.
    """
    sig = bytearray(privateKey.sign_recoverable(msgHash, hasher=None))
    r = sig[0:32]
    s = sig[32:64]
    v = sig[64] + (27 if chainId is None else chainId * 2 + 35)
    return {"r": r, "s": s, "v": v}

def ecSignTransaction(txData: TransactionBody, privateKey: PrivateKey, chainId: int = None) -> str:
    """
    Signs a transaction body with a private key and returns a `string` signature.
    """
    hashedTx = hashTransaction(txData)
    signature = ecSignHash(hashedTx, privateKey, chainId)
    return "0x" + hashedTx.hex() + signature["r"].hex() + signature["s"].hex() + toBuffer(signature["v"]).hex()
