from typing import TYPE_CHECKING, Any, List, Optional
from ain.types import (
    SetOperation,
    GetOperation,
    SetOperationType,
    GetOperationType,
    SetMultiOperationType,
    SetMultiOperation,
    TransactionInput,
    ValueOnlyTransactionInput,
    SetMultiTransactionInput,
    EvalRuleInput,
    EvalOwnerInput,
    MatchInput,
)
from ain.ain_db.push_id import PushId

if TYPE_CHECKING:
    from ain.ain import Ain

class Reference:
    _path: str
    _key: Optional[str]
    _ain: "Ain"
    _pushId: PushId
    _isGlobal: bool

    def __init__(self, ain: "Ain", path: str = None):
        self._path = Reference.sanitizeRef(path)
        pathArr = self._path.split("/")
        if len(pathArr) > 0:
            self._key = pathArr[-1]
        else:
            self._key = None
        self._ain = ain
        self._pushId = PushId()
        self._isGlobal = False

    @property
    def path(self) -> str:
        return self._path

    @property
    def key(self) -> Optional[str]:
        return self._key

    def setIsGlobal(self, isGlobal):
        """
        Sets the global path flag.
        """
        self._isGlobal = isGlobal

    def push(self) -> "Reference":
        """
        Creates a key for a new child but doesn't set any values.
        """
        newKey = "/" + self._pushId.generate()
        return Reference(self._ain, Reference.extendPath(self._path, newKey))

    async def pushValue(self, value: Any = None) -> Any:
        """
        Sets the value at a new child of self.path;
        """
        return await self.push().setValue(ValueOnlyTransactionInput(value=value))

    async def getValue(self, path: str = None) -> Any:
        """
        Returns the value at the path.
        """
        req = self.buildGetRequest("GET_VALUE", Reference.extendPath(self.path, path))
        return await self._ain.provider.send("ain_get", req)

    async def getRule(self, path: str = None) -> Any:
        """
        Returns the rule at the path.
        """
        req = self.buildGetRequest("GET_RULE", Reference.extendPath(self.path, path))
        return await self._ain.provider.send("ain_get", req)

    async def getOwner(self, path: str = None) -> Any:
        """
        Returns the owner config at the path.
        """
        req = self.buildGetRequest("GET_OWNER", Reference.extendPath(self.path, path))
        return await self._ain.provider.send("ain_get", req)

    async def getFunction(self, path: str = None) -> Any:
        """
        Returns the function config at the path.
        """
        req = self.buildGetRequest("GET_FUNCTION", Reference.extendPath(self.path, path))
        return self._ain.provider.send("ain_get", req)

    async def get(self, gets: List[GetOperation]) -> Any:
        """
        Returns the value / write rule / owner rule / function hash at multiple paths.

        Args:
            gets (List[GetOperation]): Array of get requests
                Could be any one from "VALUE", "RULE", "OWNER", "FUNC" or a combination of them as an array.
        """
        extendedGets: List[GetOperation] = []
        for get in gets:
            extendedGets.append(
                GetOperation(
                    type=get.type,
                    ref=Reference.extendPath(self._path, getattr(get, "ref", None)),
                    is_global=getattr(get, "is_global", None),
                )
            )
        req = {"type": "GET", "op_list": extendedGets}
        return await self._ain.provider.send("ain_get", req)

    async def deleteValue(self, transactionInput: ValueOnlyTransactionInput = None) -> Any:
        """
        Deletes a value.

        Args:
            transactionInput (ValueOnlyTransactionInput):
                A transaction input object.
                Any value given will be overwritten with null.
        """
        txInput = ValueOnlyTransactionInput()
        if transactionInput is not None:
            txInput = transactionInput
        txInput.value = None
        ref = Reference.extendPath(self._path, getattr(txInput, "ref", None))
        return await self._ain.sendTransaction(
            Reference.extendSetTransactionInput(
                txInput,
                ref,
                "SET_VALUE",
                self._isGlobal
            )
        )

    async def setFunction(self, transactionInput: ValueOnlyTransactionInput) -> Any:
        """
        Sets a function config.
        """
        ref = Reference.extendPath(self._path, getattr(transactionInput, "ref", None))
        return await self._ain.sendTransaction(
            Reference.extendSetTransactionInput(
                transactionInput,
                ref,
                "SET_FUNCTION",
                self._isGlobal
            )
        )

    async def setOwner(self, transactionInput: ValueOnlyTransactionInput) -> Any:
        """
        Sets the owner rule.
        """
        ref = Reference.extendPath(self._path, getattr(transactionInput, "ref", None))
        return await self._ain.sendTransaction(
            Reference.extendSetTransactionInput(
                transactionInput,
                ref,
                "SET_OWNER",
                self._isGlobal
            )
        )

    async def setRule(self, transactionInput: ValueOnlyTransactionInput) -> Any:
        """
        Sets the write rule.
        """
        ref = Reference.extendPath(self._path, getattr(transactionInput, "ref", None))
        return await self._ain.sendTransaction(
            Reference.extendSetTransactionInput(
                transactionInput,
                ref,
                "SET_RULE",
                self._isGlobal
            )
        )

    async def setValue(self, transactionInput: ValueOnlyTransactionInput) -> Any:
        """
        Sets a value.
        """
        ref = Reference.extendPath(self._path, getattr(transactionInput, "ref", None))
        return await self._ain.sendTransaction(
            Reference.extendSetTransactionInput(
                transactionInput,
                ref,
                "SET_VALUE",
                self._isGlobal
            )
        )

    async def incrementValue(self, transactionInput: ValueOnlyTransactionInput) -> Any:
        """
        Increments the value.
        """
        ref = Reference.extendPath(self._path, getattr(transactionInput, "ref", None))
        return await self._ain.sendTransaction(
            Reference.extendSetTransactionInput(
                transactionInput,
                ref,
                "INC_VALUE",
                self._isGlobal
            )
        )

    async def decrementValue(self, transactionInput: ValueOnlyTransactionInput) -> Any:
        """
        Decrements the value.
        """
        ref = Reference.extendPath(self._path, getattr(transactionInput, "ref", None))
        return await self._ain.sendTransaction(
            Reference.extendSetTransactionInput(
                transactionInput,
                ref,
                "DEC_VALUE",
                self._isGlobal
            )
        )

    async def set(self, transactionInput: SetMultiTransactionInput) -> Any:
        """
        Processes multiple set operations.
        """
        return await self._ain.sendTransaction(
            Reference.extendSetMultiTransactionInput(
                transactionInput,
                self._path,
            )
        )

    async def evalRule(self, params: EvalRuleInput) -> bool:
        """
        Returns the rule evaluation result. True if the params satisfy the write rule,
        false if not.
        """
        address = self._ain.wallet.getImpliedAddress(getattr(params, "address", None))
        req = {
            "address": address,
            "ref": Reference.extendPath(self._path, getattr(params, "ref", None)),
            "value": params.value,
        }
        if hasattr(params, "timestamp"):
            req["timestamp"] = params.timestamp
        return await self._ain.provider.send("ain_evalRule", req)

    async def evalOwner(self, params: EvalOwnerInput) -> Any:
        """
        Returns the owner evaluation result.
        """
        address = self._ain.wallet.getImpliedAddress(getattr(params, "address", None))
        req = {
            "address": address,
            "ref": Reference.extendPath(self._path, getattr(params, "ref", None)),
            "permission": params.permission,
        }
        return await self._ain.provider.send("ain_evalOwner", req)

    async def matchFunction(self, params: MatchInput = None) -> Any:
        """
        Returns the function configs that are related to the input ref.
        """
        ref = self._path
        if params is not None and hasattr(params, "ref"):
            ref = Reference.extendPath(ref, getattr(params, "ref", None))
        return await self._ain.provider.send("ain_matchFunction", {"ref": ref})

    async def matchRule(self, params: MatchInput = None) -> Any:
        """
        Returns the rule configs that are related to the input ref.
        """
        ref = self._path
        if params is not None and hasattr(params, "ref"):
            ref = Reference.extendPath(ref, getattr(params, "ref", None))
        return await self._ain.provider.send("ain_matchRule", {"ref": ref})

    async def matchOwner(self, params: MatchInput = None) -> Any:
        """
        Returns the owner configs that are related to the input ref.
        """
        ref = self._path
        if params is not None and hasattr(params, "ref"):
            ref = Reference.extendPath(ref, getattr(params, "ref", None))
        return await self._ain.provider.send("ain_matchOwner", {"ref": ref})

    @staticmethod
    def buildGetRequest(type: GetOperationType, ref: str) -> dict:
        """
        Builds a get request.
        """
        return {"type": type, "ref": Reference.sanitizeRef(ref)}

    @staticmethod
    def extendPath(basePath: str = None, extension: str = None) -> str:
        """
        Returns a path that is the basePath extended with extension.
        """
        sanitizedBase = Reference.sanitizeRef(basePath)
        sanitizedExt = Reference.sanitizeRef(extension)
        if sanitizedBase == "/":
            return sanitizedExt
        if sanitizedExt == "/":
            return sanitizedBase
        return sanitizedBase + sanitizedExt

    @staticmethod
    def extendSetTransactionInput(
        input: ValueOnlyTransactionInput,
        ref: str,
        type: SetOperationType, 
        isGlobal: bool
    ) -> TransactionInput:
        """
        Decorates a transaction input with an appropriate type, ref and value.

        Args:
            input (ValueOnlyTransactionInput): A transaction input object
            ref (str): The path at which set operations will take place
            type (SetOperationType): A type of set operations
        """
        operation = SetOperation(
            type=type,
            ref=ref,
            value=getattr(input, "value", None),
            is_global=getattr(input, "is_global", isGlobal),
        )
        return TransactionInput(
            operation=operation,
            parent_tx_hash=getattr(input, "parent_tx_hash", None),
        )

    @staticmethod
    def extendSetMultiTransactionInput(
        input: SetMultiTransactionInput,
        ref: str,
        type: SetMultiOperationType = "SET",
    ):
        """
        Decorates a transaction input with an appropriate type and op_list.

        Args:
            input (SetMultiTransactionInput): A transaction input object
            ref (str): The path at which set operations will take place
            type (SetMultiOperationType): A type of set operations
        """
        op_list: List[SetOperation] = []
        for op in input.op_list:
            op_list.append(
                SetOperation(
                    type=op.type,
                    ref=Reference.extendPath(ref, op.ref),
                    value=getattr(op, "value", None),
                    is_global=getattr(op, "is_global", None)
                )
            )
            
        operatiron = SetMultiOperation(type, op_list)
        return TransactionInput(
            operation=operatiron,
            parent_tx_hash=getattr(input, "parent_tx_hash", None),
            nonce=getattr(input, "nonce", None),
            address=getattr(input, "address", None),
            timestamp=getattr(input, "timestamp", None),
        )

    @staticmethod
    def sanitizeRef(ref: str = None):
        """
        Returns a sanitized ref. If should have a slash at the
        beginning and no slash at the end.
        """
        if ref is None:
            return "/"
        return "/" + "/".join(filter(lambda s: s != "", ref.split("/")))
