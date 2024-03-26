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
    StateInfoInput,
    GetOptions,
)
from ain.db.push_id import PushId

if TYPE_CHECKING:
    from ain.ain import Ain

class Reference:
    """Class that creates a reference to a path in the AIN Database."""

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
        """The base path of this reference."""
        return self._path

    @property
    def key(self) -> Optional[str]:
        """The key of this reference."""
        return self._key

    def setIsGlobal(self, isGlobal: bool):
        """Sets a global reference using flag.

        Args:
            isGlobal (bool): The global reference using flag.
        """
        self._isGlobal = isGlobal

    def push(self) -> "Reference":
        """Creates a key for a new child of base path virtually.
        So doesn't set any values on the AIN Blockchain.

        Returns:
            Reference: The instance of `Reference` of a new child.
        """
        newKey = "/" + self._pushId.generate()
        return Reference(self._ain, Reference.extendPath(self._path, newKey))

    async def pushValue(self, value: Any = None) -> Any:
        """Sets the value at a new child of base path.

        Args:
            value (Any, Optional): The value that you want to set. Defaults to `None`.
        
        Returns:
            The result of the transaction.
        """
        return await self.push().setValue(ValueOnlyTransactionInput(value=value))

    async def getValue(self, path: str = None, options: GetOptions = None) -> Any:
        """Gets a value at the `path`.

        Args:
            path (str, Optional): The path that you want to extend under the base path.
                If `path` is `None`, no extending. Defaults to `None`.
            options (GetOptions, Optional): The options for this transaction.
                Defaults to no options.

        Returns:
            The value at the `path`.
        """
        req = self.buildGetRequest("GET_VALUE", Reference.extendPath(self.path, path), options)
        return await self._ain.provider.send("ain_get", req)

    async def getRule(self, path: str = None, options: GetOptions = None) -> Any:
        """Gets a rule at the `path`.

        Args:
            path (str, Optional): The path that you want to extend under the base path.
                If `path` is `None`, no extending. Defaults to `None`.
            options (GetOptions, Optional): The options for this transaction.
                Defaults to no options.

        Returns:
            The rule at the `path`.
        """
        req = self.buildGetRequest("GET_RULE", Reference.extendPath(self.path, path), options)
        return await self._ain.provider.send("ain_get", req)

    async def getOwner(self, path: str = None, options: GetOptions = None) -> Any:
        """Gets an owner config at the `path`.

        Args:
            path (str, Optional): The path that you want to extend under the base path.
                If `path` is `None`, no extending. Defaults to `None`.
            options (GetOptions, Optional): The options for this transaction.
                Defaults to no options.
        
        Returns:
            The owner config at the `path`.
        """
        req = self.buildGetRequest("GET_OWNER", Reference.extendPath(self.path, path), options)
        return await self._ain.provider.send("ain_get", req)

    async def getFunction(self, path: str = None, options: GetOptions = None) -> Any:
        """Gets a function config at the `path`.

        Args:
            path (str, Optional): The path that you want to extend under the base path.
                If `path` is `None`, no extending. Defaults to `None`.
            options (GetOptions, Optional): The options for this transaction.
                Defaults to no options.
        
        Returns:
            The function config at the `path`.
        """
        req = self.buildGetRequest("GET_FUNCTION", Reference.extendPath(self.path, path), options)
        return await self._ain.provider.send("ain_get", req)

    async def get(self, gets: List[GetOperation]) -> Any:
        """Gets a value, write rule, owner rule, or function hash at multiple paths.

        Args:
            gets (List[GetOperation]): The array of the get requests.
                Could be any one from "VALUE", "RULE", "OWNER", "FUNC" or a combination of them as an array.

        Returns:
            The value, write rule, owner rule, or function hash at multiple paths.
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

    async def deleteValue(self, transactionInput: ValueOnlyTransactionInput = None, isDryrun = False) -> Any:
        """Deletes the value.

        Args:
            transactionInput (ValueOnlyTransactionInput): The transaction input object.
                Any value given will be overwritten with null.
            isDryrun (bool): Dryrun option.

        Returns:
            The result of the transaction.
        """
        txInput = ValueOnlyTransactionInput()
        if transactionInput is not None:
            txInput = transactionInput
        ref = Reference.extendPath(self._path, getattr(txInput, "ref", None))
        operation = SetOperation(
            type="SET_VALUE",
            ref=ref,
            is_global=getattr(txInput, "is_global", self._isGlobal),
        )
        operation.value = None
        return await self._ain.sendTransaction(
            TransactionInput(
                operation=operation,
                parent_tx_hash=getattr(txInput, "parent_tx_hash", None),
            ),
            isDryrun
        )

    async def setFunction(self, transactionInput: ValueOnlyTransactionInput, isDryrun = False) -> Any:
        """Sets the function config.

        Args:
            transactionInput (ValueOnlyTransactionInput): The transaction input object.
            isDryrun (bool): Dryrun option.

        Returns:
            The result of the transaction.
        """
        ref = Reference.extendPath(self._path, getattr(transactionInput, "ref", None))
        return await self._ain.sendTransaction(
            Reference.extendSetTransactionInput(
                transactionInput,
                ref,
                "SET_FUNCTION",
                self._isGlobal
            ),
            isDryrun
        )

    async def setOwner(self, transactionInput: ValueOnlyTransactionInput, isDryrun = False) -> Any:
        """Sets the owner rule.

        Args:
            transactionInput (ValueOnlyTransactionInput): The transaction input object.
            isDryrun (bool): Dryrun option.
            
        Returns:
            The result of the transaction.
        """
        ref = Reference.extendPath(self._path, getattr(transactionInput, "ref", None))
        return await self._ain.sendTransaction(
            Reference.extendSetTransactionInput(
                transactionInput,
                ref,
                "SET_OWNER",
                self._isGlobal
            ),
            isDryrun
        )

    async def setRule(self, transactionInput: ValueOnlyTransactionInput, isDryrun = False) -> Any:
        """Sets the write rule.

        Args:
            transactionInput (ValueOnlyTransactionInput): The transaction input object.
            isDryrun (bool): Dryrun option.
            
        Returns:
            The result of the transaction.
        """
        ref = Reference.extendPath(self._path, getattr(transactionInput, "ref", None))
        return await self._ain.sendTransaction(
            Reference.extendSetTransactionInput(
                transactionInput,
                ref,
                "SET_RULE",
                self._isGlobal
            ),
            isDryrun
        )

    async def setValue(self, transactionInput: ValueOnlyTransactionInput, isDryrun = False) -> Any:
        """Sets the value.

        Args:
            transactionInput (ValueOnlyTransactionInput): The transaction input object.
            isDryrun (bool): Dryrun option.
            
        Returns:
            The result of the transaction.
        """
        ref = Reference.extendPath(self._path, getattr(transactionInput, "ref", None))
        return await self._ain.sendTransaction(
            Reference.extendSetTransactionInput(
                transactionInput,
                ref,
                "SET_VALUE",
                self._isGlobal
            ),
            isDryrun
        )

    async def incrementValue(self, transactionInput: ValueOnlyTransactionInput, isDryrun = False) -> Any:
        """Increments the value.

        Args:
            transactionInput (ValueOnlyTransactionInput): The transaction input object.
            isDryrun (bool): Dryrun option.
            
        Returns:
            The result of the transaction.
        """
        ref = Reference.extendPath(self._path, getattr(transactionInput, "ref", None))
        return await self._ain.sendTransaction(
            Reference.extendSetTransactionInput(
                transactionInput,
                ref,
                "INC_VALUE",
                self._isGlobal
            ),
            isDryrun
        )

    async def decrementValue(self, transactionInput: ValueOnlyTransactionInput, isDryrun = False) -> Any:
        """Decrements the value.
        
        Args:
            transactionInput (ValueOnlyTransactionInput): The transaction input object.
            isDryrun (bool): Dryrun option.
            
        Returns:
            The result of the transaction.
        """
        ref = Reference.extendPath(self._path, getattr(transactionInput, "ref", None))
        return await self._ain.sendTransaction(
            Reference.extendSetTransactionInput(
                transactionInput,
                ref,
                "DEC_VALUE",
                self._isGlobal
            ),
            isDryrun
        )

    async def set(self, transactionInput: SetMultiTransactionInput, isDryrun = False) -> Any:
        """Processes the multiple set operations.
        
        Args:
            transactionInput (SetMultiTransactionInput): The transaction input object.
            isDryrun (bool): Dryrun option.
            
        Returns:
            The result of the transaction.
        """
        return await self._ain.sendTransaction(
            Reference.extendSetMultiTransactionInput(
                transactionInput,
                self._path,
            ),
            isDryrun
        )

    async def evalRule(self, params: EvalRuleInput) -> Any:
        """Evals the rule evaluation result.

        Args:
            params (EvalRuleInput): The eval rule input object.
            
        Returns:
            The result of the evaluation.
            `True`, if the params satisfy the write rule,
            `False,` if not.
        """
        address = self._ain.signer.getAddress(getattr(params, "address", None))
        req = {
            "address": address,
            "ref": Reference.extendPath(self._path, getattr(params, "ref", None)),
            "value": params.value,
        }
        if hasattr(params, "timestamp"):
            req["timestamp"] = params.timestamp
        return await self._ain.provider.send("ain_evalRule", req)

    async def evalOwner(self, params: EvalOwnerInput) -> Any:
        """Evals the owner evaluation result.

        Args:
            params (EvalOwnerInput): The eval owner input object.
            
        Returns:
            The owner evaluation result.
        """
        address = self._ain.signer.getAddress(getattr(params, "address", None))
        req = {
            "address": address,
            "ref": Reference.extendPath(self._path, getattr(params, "ref", None)),
            "permission": params.permission,
        }
        return await self._ain.provider.send("ain_evalOwner", req)

    async def matchFunction(self, params: MatchInput = None) -> Any:
        """Matches the function configs that are related to the input ref.

        Args:
            params (MatchInput): The match input object.
            
        Returns:
            The function configs that are related to the input ref.
        """
        ref = self._path
        if params is not None and hasattr(params, "ref"):
            ref = Reference.extendPath(ref, getattr(params, "ref", None))
        return await self._ain.provider.send("ain_matchFunction", {"ref": ref})

    async def matchRule(self, params: MatchInput = None) -> Any:
        """Matches the rule configs that are related to the input ref.

        Args:
            params (MatchInput): The match input object.
            
        Returns:
            The rule configs that are related to the input ref.
        """
        ref = self._path
        if params is not None and hasattr(params, "ref"):
            ref = Reference.extendPath(ref, getattr(params, "ref", None))
        return await self._ain.provider.send("ain_matchRule", {"ref": ref})

    async def matchOwner(self, params: MatchInput = None) -> Any:
        """Matches the owner configs that are related to the input ref.

        Args:
            params (MatchInput): The match input object.
            
        Returns:
            The owner configs that are related to the input ref.
        """
        ref = self._path
        if params is not None and hasattr(params, "ref"):
            ref = Reference.extendPath(ref, getattr(params, "ref", None))
        return await self._ain.provider.send("ain_matchOwner", {"ref": ref})

    async def getStateProof(self, params: StateInfoInput = None) -> Any:
        """Fetches the state proof of a global blockchain state path.

        Args:
            params (StateInfoInput): The state info input object.
            
        Returns:
            The return value of the blockchain API.
        """
        ref = self._path
        if params is not None and hasattr(params, "ref"):
            ref = Reference.extendPath(ref, getattr(params, "ref", None))
        return await self._ain.provider.send("ain_getStateProof", {"ref": ref})

    async def getProofHash(self, params: StateInfoInput = None) -> Any:
        """Fetches the proof hash of a global blockchain state path.

        Args:
            params (StateInfoInput): The state info input object.
            
        Returns:
            The return value of the blockchain API.
        """
        ref = self._path
        if params is not None and hasattr(params, "ref"):
            ref = Reference.extendPath(ref, getattr(params, "ref", None))
        return await self._ain.provider.send("ain_getProofHash", {"ref": ref})

    async def getStateInfo(self, params: StateInfoInput = None) -> Any:
        """Fetches the state information of a global blockchain state path.

        Args:
            params (StateInfoInput): The state info input object.
            
        Returns:
            The return value of the blockchain API.
        """
        ref = self._path
        if params is not None and hasattr(params, "ref"):
            ref = Reference.extendPath(ref, getattr(params, "ref", None))
        return await self._ain.provider.send("ain_getStateInfo", {"ref": ref})

    @staticmethod
    def buildGetRequest(type: GetOperationType, ref: str, options: GetOptions = None) -> dict:
        """Builds a get request.

        Args:
            type (GetOperationType): The type of get operation.
            ref (str): The path that you want to make transaction.
            options (GetOptions, Optional): The options for this transaction.
                Defaults to no options.
        
        Returns:
            dict: The builded get request.
        """
        request = {"type": type, "ref": Reference.sanitizeRef(ref)}
        if options is not None:
            request.update(options.__dict__)
        return request

    @staticmethod
    def extendPath(basePath: str = None, extension: str = None) -> str:
        """Extends the path.

        Args:
            basePath (str, Optional): The base path that you want.
            extension (str, Optional): The extension that you want to extend under the base path.
        
        Returns:
            str: The extended `basePath`, by the `extension`.
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
        """Extends the transaction input with an appropriate type, ref and value.

        Args:
            input (ValueOnlyTransactionInput): The transaction input object.
            ref (str): The path that you want to make transaction.
            type (SetOperationType): The type of set operation.
        
        Returns:
            TransactionInput: The decorated transaction input.
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
            nonce=getattr(input, "nonce", None),
            address=getattr(input, "address", None),
            timestamp=getattr(input, "timestamp", None),
            gas_price=getattr(input, "gas_price", None),
        )
        
    @staticmethod
    def extendSetMultiTransactionInput(
        input: SetMultiTransactionInput,
        ref: str,
        type: SetMultiOperationType = "SET",
    ) -> TransactionInput:
        """Extends the transaction input with an appropriate type and op_list.

        Args:
            input (SetMultiTransactionInput): The transaction input object.
            ref (str): The path that you want to make transaction.
            type (SetMultiOperationType): The type of set operations.
        
        Returns:
            TransactionInput: The decorated transaction input.
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
            
        operation = SetMultiOperation(type, op_list)
        return TransactionInput(
            operation=operation,
            parent_tx_hash=getattr(input, "parent_tx_hash", None),
            nonce=getattr(input, "nonce", None),
            address=getattr(input, "address", None),
            timestamp=getattr(input, "timestamp", None),
            gas_price=getattr(input, "gas_price", None),
        )

    @staticmethod
    def sanitizeRef(ref: str = None) -> str:
        """Sanitizes the path.

        Args:
            ref (str): A path that you want to sanitize.
        
        Returns:
            str: A sanitized ref. It should have a slash at the beginning and no slash at the end.
        """
        if ref is None:
            return "/"
        return "/" + "/".join(filter(lambda s: s != "", ref.split("/")))
