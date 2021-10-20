from typing import Any
from typing_extensions import TypedDict


class ECDSASignature(TypedDict):
    r: bytes
    s: bytes
    v: int


class TransactionBody(TypedDict):
    operation: Any
    nonce: int
    timestamp: int
    # parent_tx_hash: str
    # TODO : find a method to substitute `NotRequired` or use python 3.11
