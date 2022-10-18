import sys
from typing import Any, Optional, List, Union

if sys.version_info >= (3, 8):
    from typing import Literal
else:
    from typing_extensions import Literal

class ECDSASignature:
    """Class for the ECDSA signature."""

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
        """Converts signature format of the `eth_sign` RPC method to signature parameters.

        Args:
            signature: The `eth_sign` signature.
        """
        if len(signature) != 65:
            raise ValueError("Invalid signature length: r")

        r = signature[0:32]
        s = signature[32:64]
        v = signature[64]
        return cls(r, s, v)

class ECIESEncrypted:
    """Class for the ECIES encrypted ciphertext."""

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

class AinOptions():
    """Class for the AIN blockchain options."""

    rawResultMode: Optional[bool]
    """The flag of the using transaction raw result mode. If `True`, the raw result will return."""

    def __init__(
        self,
        rawResultMode: bool = None,
    ):
        if rawResultMode is not None:
            self.rawResultMode = rawResultMode

class GetOptions():
    """Class for the get transaction options."""

    is_global: Optional[bool]
    """The flag of the using global reference path. If `True`, the given ref will be interpreted as a global path."""
    is_final: Optional[bool]
    """The flag of the getting finalized result. If `True`, the result will return finalized."""
    is_shallow: Optional[bool]
    """The flag of the getting shallow result. If `True`, the result will return only the keys of the children."""
    include_version: Optional[bool]
    """The flag of the including version. If `True`, the result will include state versions."""
    include_tree_info: Optional[bool]
    """The flag of the including tree info. If `True`, the result will include additional state tree information."""
    include_proof: Optional[bool]
    """The flag of the including proof hashes. If `True`, the result will include proof hashes."""

    def __init__(
        self,
        is_global: bool = None,
        is_final: bool = None,
        is_shallow: bool = None,
        include_version: bool = None,
        include_tree_info: bool = None,
        include_proof: bool = None,
    ):
        if is_global is not None:
            self.is_global = is_global
        if is_final is not None:
            self.is_final = is_final
        if is_shallow is not None:
            self.is_shallow = is_shallow
        if include_version is not None:
            self.include_version = include_version
        if include_tree_info is not None:
            self.include_tree_info = include_tree_info
        if include_proof is not None:
            self.include_proof = include_proof

class SetOperation():
    """Class for the set operation."""

    type: SetOperationType
    """The type of the set operation."""
    ref: str
    """The reference of the path."""
    value: Optional[Any]
    """The value that you want to set."""
    is_global: Optional[bool]
    """The flag of the using global reference path. If `True`, the given ref will be interpreted as a global path."""

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
    """Class for the multiple set operation."""

    type: SetMultiOperationType
    """The type of the multiple set operation."""
    op_list: List[SetOperation]
    """The list of the set operations."""

    def __init__(
        self,
        type: SetMultiOperationType,
        op_list: List[SetOperation]
    ):
        self.type = type
        self.op_list = op_list

class GetOperation():
    """Class for the get operation."""

    type: GetOperationType
    """The type of the get operation."""
    ref: Optional[str]
    """The path that you want to make transaction."""
    is_global: Optional[bool]
    """The flag of the using global reference path. If `True`, the given ref will be interpreted as a global path."""

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
    """Class for the multiple get operation."""

    type: GetMultiOperationType
    """The type of the multiple get operation."""
    op_list: List[GetOperation]
    """The list of the get operations."""

    def __init__(
        self,
        type: GetMultiOperationType,
        op_list: List[GetOperation]
    ):
        self.type = type
        self.op_list = op_list

class TransactionBodyBase:
    """Class for the transaction body base."""

    parent_tx_hash: Optional[str]
    """The hash of the parent transaction. If transaction is not nested, this should not be given."""
    operation: Union[SetOperation, SetMultiOperation]
    """The set operation."""

class ValueOnlyTransactionBodyBase:
    """Class for the value only transaction body base."""

    parent_tx_hash: Optional[str]
    """The hash of the parent transaction. If transaction is not nested, this should not be given."""
    value: Optional[Any]
    """The value that you want to set."""
    ref: Optional[str]
    """The path that you want to make transaction."""
    is_global: Optional[bool]
    """The flag of the using global reference path. If `True`, the given ref will be interpreted as a global path."""

class TransactionInputBase:
    """Class for the transaction input base."""

    nonce: Optional[int]
    """The nonce of the transaction."""
    address: Optional[str]
    """The AIN blockchain address of the sender."""
    timestamp: Optional[int]
    """The unix time in milliseconds when the transaction has been created."""
    gas_price: Optional[int]
    """The gas price of the transaction."""

class TransactionBody(TransactionBodyBase):
    """Class for the transaction body."""

    nonce: int
    """The nonce of the transaction."""
    timestamp: int
    """The unix time in milliseconds when the transaction has been created."""
    gas_price: Optional[int]
    """The gas price of the transaction."""
    billing: Optional[str]
    """The billing app name and the billing ID. Must be formatted as `<app_name>|<billing_id>`"""

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
    """Class for the transaction input."""

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
    """Class for the value only transaction input."""

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
    """Class for the multiple set transaction input."""

    parent_tx_hash: Optional[str]
    """The hash of the parent transaction. If transaction is not nested, this should not be given."""
    op_list: List[SetOperation]
    """The list of the set operations."""

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
    """Class for the transaction."""

    tx_body: TransactionBody
    """The transaction body."""
    signature: str
    """The signature of the transaction."""
    hash: str
    """The transaction hash."""
    address: str
    """The AIN blockchain address of the sender."""

class EvalRuleInput:
    """Class for the eval rule input."""

    value: Any
    """The value that you want to set."""
    ref: Optional[str]
    """The path that you want to make transaction."""
    address: Optional[str]
    """The AIN blockchain address of the sender."""
    timestamp: Optional[int]
    """The unix time in milliseconds when the transaction has been created."""
    is_global: Optional[bool]
    """The flag of the using global reference path. If `True`, the given ref will be interpreted as a global path."""

    def __init__(
        self,
        value: Any = None,
        ref: str = None,
        address: str = None,
        timestamp: int = None,
        is_global: bool = None,
    ):
        if value is not None:
            self.value = value
        if ref is not None:
            self.ref = ref
        if address is not None:
            self.address = address
        if timestamp is not None:
            self.timestamp = timestamp
        if is_global is not None:
            self.is_global = is_global

class EvalOwnerInput:
    """Class for the eval owner input."""

    permission: OwnerPermission
    """The type of the permission."""
    ref: Optional[str]
    """The path that you want to make transaction."""
    address: Optional[str]
    """The AIN blockchain address of the sender."""
    is_global: Optional[bool]
    """The flag of the using global reference path. If `True`, the given ref will be interpreted as a global path."""

    def __init__(
        self,
        permission: OwnerPermission,
        ref: str = None,
        address: str = None,
        is_global: bool = None,
    ):
        self.permission = permission
        if ref is not None:
            self.ref = ref
        if address is not None:
            self.address = address
        if is_global is not None:
            self.is_global = is_global

class MatchInput:
    """Class for the match input."""

    ref: Optional[str]
    """The path that you want to make transaction."""
    is_global: Optional[bool]
    """The flag of the using global reference path. If `True`, the given ref will be interpreted as a global path."""

    def __init__(
        self,
        ref: str = None,
        is_global: bool = None,
    ):
        if ref is not None:
            self.ref = ref
        if is_global is not None:
            self.is_global = is_global
