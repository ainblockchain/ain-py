import json
import uuid as UUID
from types import SimpleNamespace
from typing import Union, Optional
from secrets import token_bytes
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2, scrypt
from Crypto.Hash import SHA256
from Crypto.Util.Padding import pad, unpad
from ain.utils import privateToAddress, keccak

class Cipherparams:
    """Class for the cipher params."""

    iv: str
    """The initial vector of the cipher."""

class Crypto:
    """Class for the crypto."""
    
    ciphertext: str
    """The ciphertext."""
    cipherparams: Cipherparams
    """The cipher params."""
    cipher: str
    """The name of the cipher."""
    kdf: str
    """The name of the KDF(key derivation function). `scrypt` and `pbkdf2` are supported."""
    kdfparams: dict
    """The KDF params."""
    mac: str
    """The MAC(message authentication code)."""

class V3KeystoreOptions:
    """Class for the v3 keystore options."""

    cipher: Optional[str]
    """The name of the cipher."""
    iv: Optional[bytes]
    """The initial vector of the cipher."""
    kdf: Optional[str]
    """The name of the KDF(key derivation function). `scrypt` and `pbkdf2` are supported."""
    salt: Optional[bytes]
    """The salt for the KDF."""
    dklen: Optional[int]
    """The length of the desired key for KDF."""
    n: Optional[int]
    """The n option for the KDF `scrypt`"""
    r: Optional[int]
    """The r option for the KDF `scrypt`"""
    p: Optional[int]
    """The p option for the KDF `scrypt`"""
    c: Optional[int]
    """The c option for the KDF `pbkdf2`"""
    uuid: Optional[bytes]
    """The predetermined bytes of the UUID."""

    def __init__(
        self,
        cipher: str = None,
        iv: bytes = None,
        kdf: str = None,
        salt: bytes = None,
        dklen: int = None,
        n: int = None,
        r: int = None,
        p: int = None,
        c: int = None,
        uuid: bytes = None,
    ):
        if cipher is not None:
            self.cipher = cipher
        if iv is not None:
            self.iv = iv
        if kdf is not None:
            self.kdf = kdf
        if salt is not None:
            self.salt = salt
        if dklen is not None:
            self.dklen = dklen
        if n is not None:
            self.n = n
        if r is not None:
            self.r = r
        if p is not None:
            self.r = p
        if c is not None:
            self.c = c
        if uuid is not None:
            self.uuid = uuid

class V3Keystore:
    """Class for the v3 keystore."""

    version: int
    """The version of the keystore."""
    id: str
    """The UUID of the keystore."""
    address: str
    """The AIN blockchain address of the keystore."""
    crypto: Crypto
    """The object of the crypto."""

    def __init__(
        self,
        version: int,
        id: str,
        address: str,
        ciphertext: str,
        iv: str,
        cipher: str,
        kdf: str,
        kdfparams: dict,
        mac: str
    ):
        self.version = version
        self.id = id
        self.address = address
        self.crypto = Crypto()
        self.crypto.ciphertext = ciphertext
        self.crypto.cipherparams = Cipherparams()
        self.crypto.cipherparams.iv = iv
        self.crypto.cipher = cipher
        self.crypto.kdf = kdf
        self.crypto.kdfparams = kdfparams
        self.crypto.mac = mac

    @classmethod
    def fromPrivateKey(
        cls,
        privateKey: Union[bytes, str],
        password: str,
        options: V3KeystoreOptions = V3KeystoreOptions()
    ):
        """Converts an account into a v3 Keystore and encrypts it with a password.
        
        Args:
            privateKey (Union[bytes, str]): The private key of an AIN blockchain account.
            password (str): The password of the v3 keystore.
            options (V3KeystoreOptions): The options for the v3 keystore.
                Defaults to no options.
        """

        if type(privateKey) is str:
            privateKeyBytes = bytes.fromhex(privateKey)
        elif type(privateKey) is bytes:
            privateKeyBytes = privateKey
        else:
            raise ValueError("Invalid public key type")

        salt = getattr(options, "salt", token_bytes(32))
        iv = getattr(options, "iv", token_bytes(16))
        uuid = getattr(options, "uuid", token_bytes(16))
        dklen = getattr(options, "dklen", 32)
        kdf = getattr(options, "kdf", "scrypt")

        kdfparams = {
            "dklen": dklen,
            "salt": salt.hex(),
        }
        if kdf == "scrypt":
            n = getattr(options, "n", 262144)
            r = getattr(options, "r", 8)
            p = getattr(options, "p", 1)
            kdfparams.update({
                "n": n,
                "r": r,
                "p": p,
            })
            derivedKeyTemp = scrypt(
                password,
                salt, # type: ignore
                dklen,
                N=n,
                r=r,
                p=p
            )
            if type(derivedKeyTemp) is bytes:
                derivedKey = derivedKeyTemp
            else:
                raise ValueError("scrypt derived multiple keys")
        elif kdf == "pbkdf2":
            c = getattr(options, "c", 262144)
            kdfparams.update({
                "c": c,
                "prf": "hmac-sha256",
            })
            derivedKey = PBKDF2(
                password,
                salt,
                dklen,
                count=c,
                hmac_hash_module=SHA256
            )
        else:
            raise ValueError("Unsupported kdf")

        cipherkey = derivedKey[0:16]
        padding = False
        cipher = getattr(options, "cipher", "aes-128-ctr")
        if cipher == "aes-128-ecb":
            aescipher = AES.new(cipherkey, AES.MODE_ECB)
            padding = True
        elif cipher == "aes-128-cbc" or cipher == "aes128":
            aescipher = AES.new(cipherkey, AES.MODE_CBC, iv)
            padding = True
        elif cipher == "aes-128-cfb":
            aescipher = AES.new(cipherkey, AES.MODE_CFB, iv, segment_size=128)
        elif cipher == "aes-128-cfb8":
            aescipher = AES.new(cipherkey, AES.MODE_CFB, iv)
        elif cipher == "aes-128-ofb":
            aescipher = AES.new(cipherkey, AES.MODE_OFB, iv)
        elif cipher == "aes-128-ctr":
            aescipher = AES.new(cipherkey, AES.MODE_CTR, nonce=iv[:8], initial_value=iv[8:])
        else:
            raise ValueError("Unsupported cipher")

        if padding:
            ciphertext = aescipher.encrypt(pad(privateKeyBytes, AES.block_size))
        else:
            ciphertext = aescipher.encrypt(privateKeyBytes)

        return cls(
            version=3,
            id=str(UUID.UUID(bytes=uuid, version=4)),
            address=privateToAddress(privateKeyBytes).lower().replace("0x",""),
            ciphertext=ciphertext.hex(),
            iv=iv.hex(),
            cipher=cipher,
            kdf=kdf,
            kdfparams=kdfparams,
            mac=keccak(derivedKey[16:32] + ciphertext).hex()
        )

    @classmethod
    def fromJSON(cls, v3KeystoreJSON: str):
        """Converts the stringified v3 keystore JSON into a v3 keystore object.
        
        Args:
            v3KeystoreJSON (str): The stringified v3 keystore JSON.
        """

        loaded = json.loads(v3KeystoreJSON, object_hook=lambda d: SimpleNamespace(**d))
        version = int(loaded.version)
        id = str(loaded.id)
        address = str(loaded.address)
        ciphertext = str(loaded.crypto.ciphertext)
        iv = str(loaded.crypto.cipherparams.iv)
        cipher = str(loaded.crypto.cipher)
        kdf = str(loaded.crypto.kdf)
        kdfparams = dict(loaded.crypto.kdfparams.__dict__)
        mac = str(loaded.crypto.mac)
        return cls(
            version,
            id,
            address,
            ciphertext,
            iv,
            cipher,
            kdf,
            kdfparams,
            mac
        )

    def toPrivateKey(self, password: str) -> bytes:
        """Returns a private key from a v3 Keystore."""

        kdfparams = self.crypto.kdfparams
        salt = bytes.fromhex(kdfparams["salt"])
        dklen = kdfparams["dklen"]
        if self.crypto.kdf == "scrypt":
            derivedKeyTemp = scrypt(
                password,
                salt, # type: ignore
                dklen,
                N=kdfparams["n"],
                r=kdfparams["r"],
                p=kdfparams["p"]
            )
            if type(derivedKeyTemp) is bytes:
                derivedKey = derivedKeyTemp
            else:
                raise ValueError("scrypt derived multiple keys")
        elif self.crypto.kdf == "pbkdf2":
            derivedKey = PBKDF2(
                password,
                salt,
                dklen,
                count=kdfparams["c"],
                hmac_hash_module=SHA256
            )
        else:
            raise ValueError("Unsupported kdf")

        ciphertext = bytes.fromhex(self.crypto.ciphertext)
        mac = keccak(derivedKey[16:32] + ciphertext).hex()
        if mac != self.crypto.mac:
            raise ValueError("Key derivation failed - possibly wrong password")
            
        cipherkey = derivedKey[0:16]
        padding = False
        cipher = self.crypto.cipher
        iv = bytes.fromhex(self.crypto.cipherparams.iv)
        if cipher == "aes-128-ecb":
            aescipher = AES.new(cipherkey, AES.MODE_ECB)
            padding = True
        elif cipher == "aes-128-cbc" or cipher == "aes128":
            aescipher = AES.new(cipherkey, AES.MODE_CBC, iv)
            padding = True
        elif cipher == "aes-128-cfb":
            aescipher = AES.new(cipherkey, AES.MODE_CFB, iv, segment_size=128)
        elif cipher == "aes-128-cfb8":
            aescipher = AES.new(cipherkey, AES.MODE_CFB, iv)
        elif cipher == "aes-128-ofb":
            aescipher = AES.new(cipherkey, AES.MODE_OFB, iv)
        elif cipher == "aes-128-ctr":
            aescipher = AES.new(cipherkey, AES.MODE_CTR, nonce=iv[:8], initial_value=iv[8:])
        else:
            raise ValueError("Unsupported cipher")

        if padding:
            privateKeyBytes = unpad(aescipher.decrypt(ciphertext), AES.block_size)
        else:
            privateKeyBytes = aescipher.decrypt(ciphertext)
        return privateKeyBytes

    def __str__(self):
        return json.dumps(
            self.__dict__,
            default=lambda o: o.__dict__,
            separators=(",", ":")
        )