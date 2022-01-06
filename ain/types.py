import sys
from typing import Any, Optional, List, Union

if sys.version_info >= (3, 8):
    from typing import Literal
else:
    from typing_extensions import Literal

class ECDSASignature:
    r: bytes
    s: bytes
    v: int

    def __init__(self, r: bytes, s: bytes, v: int):
        if len(r) != 32:
            raise ValueError("Invalid signature length: r")
        if len(s) != 32:
            raise ValueError("Invalid signature length: s")
        if v < 0 or v > 255:
            raise ValueError("Invalid signature: v")

        self.r = r
        self.s = s
        self.v = v

    @classmethod
    def fromSignature(cls, signature: bytes):
        """
        Converts signature format of the `eth_sign` RPC method to signature parameters.
        """
        if len(signature) != 65:
            raise ValueError("Invalid signature length: r")

        r = signature[0:32]
        s = signature[32:64]
        v = signature[64]
        return cls(r, s, v)

class ECIESEncrypted:
    iv: bytes
    ephemPublicKey: bytes
    ciphertext: bytes
    mac: bytes

    def __init__(
        self,
        iv: bytes,
        ephemPublicKey: bytes,
        ciphertext: bytes,
        mac: bytes,
    ):
        self.iv = iv
        self.ephemPublicKey = ephemPublicKey
        self.ciphertext = ciphertext
        self.mac = mac

    def __str__(self):
        return "\n".join(
            (
                "{",
                f"  iv: '{self.iv.hex()}',",
                f"  ephemPublicKey: '{self.ephemPublicKey.hex()}',",
                f"  ciphertext: '{self.ciphertext.hex()}',",
                f"  mac: '{self.mac.hex()}',",
                "}",
            )
        )

SetMultiOperationType = Literal["SET"]

GetMultiOperationType = Literal["GET"]

SetOperationType = Literal["SET_VALUE", "INC_VALUE", "DEC_VALUE", "SET_RULE", "SET_OWNER", "SET_FUNCTION"]

GetOperationType = Literal["GET_VALUE", "GET_RULE", "GET_OWNER", "GET_FUNCTION"]

OwnerPermission = Literal["branch_owner", "write_function", "write_owner", "write_rule"]

class SetOperation():
    type: SetOperationType
    ref: str
    value: Optional[Any]
    is_global: Optional[bool]

    def __init__(
        self,
        type: SetOperationType,
        ref: str,
        value: Any = None,
        is_global: bool = None,
    ):
        self.type = type
        self.ref = ref
        if value is not None:
            self.value = value
        if is_global is not None:
            self.is_global = is_global

class SetMultiOperation():
    type: SetMultiOperationType
    op_list: List[SetOperation]

    def __init__(
        self,
        type: SetMultiOperationType,
        op_list: List[SetOperation]
    ):
        self.type = type
        self.op_list = op_list

class GetOperation():
    type: GetOperationType
    ref: Optional[str]
    is_global: Optional[bool]

    def __init__(
        self,
        type: GetOperationType,
        ref: str = None,
        is_global: bool = None,
    ):
        self.type = type
        if ref is not None:
            self.ref = ref
        if is_global is not None:
            self.is_global = is_global

class GetMultiOperation():
    type: GetMultiOperationType
    op_list: List[GetOperation]

    def __init__(
        self,
        type: GetMultiOperationType,
        op_list: List[GetOperation]
    ):
        self.type = type
        self.op_list = op_list

class TransactionBodyBase:
    parent_tx_hash: Optional[str]
    operation: Union[SetOperation, SetMultiOperation]

class ValueOnlyTransactionBodyBase:
    parent_tx_hash: Optional[str]
    value: Optional[Any]
    ref: Optional[str]
    is_global: Optional[bool]

class TransactionInputBase:
    nonce: Optional[int]
    address: Optional[str]
    timestamp: Optional[int]
    gas_price: Optional[int]

class TransactionBody(TransactionBodyBase):
    nonce: int
    timestamp: int
    gas_price: Optional[int]
    billing: Optional[str]
    def __init__(
        self,
        operation: Union[SetOperation, SetMultiOperation],
        nonce: int,
        timestamp: int,
        gas_price: int = None,
        billing: str = None,
        parent_tx_hash: str = None,
    ):
        self.operation = operation
        self.nonce = nonce
        self.timestamp = timestamp
        if gas_price is not None:
            self.gas_price = gas_price
        if billing is not None:
            self.billing = billing
        if parent_tx_hash is not None:
            self.parent_tx_hash = parent_tx_hash


class TransactionInput(TransactionBodyBase, TransactionInputBase):
    def __init__(
        self,
        operation: Union[SetOperation, SetMultiOperation],
        parent_tx_hash: str = None,
        nonce: int = None,
        address: str = None,
        timestamp: int = None,
        gas_price: int = None,
    ):
        self.operation = operation
        if parent_tx_hash is not None:
            self.parent_tx_hash = parent_tx_hash
        if nonce is not None:
            self.nonce = nonce
        if address is not None:
            self.address = address
        if timestamp is not None:
            self.timestamp = timestamp
        if gas_price is not None:
            self.gas_price = gas_price

class ValueOnlyTransactionInput(ValueOnlyTransactionBodyBase, TransactionInputBase):
    def __init__(
        self,
        parent_tx_hash: str = None,
        value: Any = None,
        ref: str = None,
        is_global: bool = None,
        nonce: int = None,
        address: str = None,
        timestamp: int = None,
        gas_price: int = None,
    ):
        if parent_tx_hash is not None:
            self.parent_tx_hash = parent_tx_hash
        if value is not None:
            self.value = value
        if ref is not None:
            self.ref = ref
        if is_global is not None:
            self.is_global = is_global
        if nonce is not None:
            self.nonce = nonce
        if address is not None:
            self.address = address
        if timestamp is not None:
            self.timestamp = timestamp
        if gas_price is not None:
            self.gas_price = gas_price

class SetMultiTransactionInput(TransactionInputBase):
    parent_tx_hash: Optional[str]
    op_list: List[SetOperation]

    def __init__(
        self,
        op_list: List[SetOperation],
        parent_tx_hash: str = None,
        nonce: int = None,
        address: str = None,
        timestamp: int = None,
        gas_price: int = None,
    ):
        self.op_list = op_list
        if parent_tx_hash is not None:
            self.parent_tx_hash = parent_tx_hash
        if nonce is not None:
            self.nonce = nonce
        if address is not None:
            self.address = address
        if timestamp is not None:
            self.timestamp = timestamp
        if gas_price is not None:
            self.gas_price = gas_price

class Transaction():
    tx_body: TransactionBody
    signature: str
    hash: str
    address: str

class EvalRuleInput:
    value: Any
    ref: Optional[str]
    address: Optional[str]
    timestamp: Optional[int]
    is_global: Optional[bool]

class EvalOwnerInput:
    ref: Optional[str]
    address: Optional[str]
    permission: OwnerPermission
    is_global: Optional[bool]

class MatchInput:
    ref: Optional[str]
    is_global: Optional[bool]
