import aiohttp
import json
from urllib.parse import urlparse, urljoin
from jsonrpcclient import request, parse, Ok, Error
from typing import TYPE_CHECKING, Any
from ain.errors import BlockchainError

if TYPE_CHECKING:
    from ain.ain import Ain

JSON_RPC_ENDPOINT = "json-rpc"

class Provider:
    endPoint: str
    apiEndPoint: str
    _ain: "Ain"
    
    def __init__(self, ain: "Ain", endpoint: str):
        self._ain = ain
        parsed = urlparse(endpoint)
        if parsed.scheme == "" or parsed.netloc == "":
            raise ValueError("Invalid endpoint received.")
        self.endPoint = parsed.geturl()
        self.apiEndPoint = urljoin(self.endPoint, JSON_RPC_ENDPOINT)

    async def send(self, rpcMethod: str, params: dict = {}) -> Any:
        params.update({"protoVer": self._ain.net.protoVer})
        dump = json.dumps(
            request(rpcMethod, params=params, id=0),
            default=lambda o: o.__dict__,
            separators=(",", ":"),
            sort_keys=True
        )
        async with aiohttp.ClientSession() as session:
            async with session.post(self.apiEndPoint, json=json.loads(dump)) as response:
                res = await response.read()
                parsed = parse(json.loads(res))
                if isinstance(parsed, Ok):
                    rawResult = parsed.result
                    if self._ain.rawResultMode:
                        return rawResult
                    if not isinstance(rawResult, dict) or not ("code" not in rawResult or rawResult["code"] == 0):
                        raise BlockchainError(rawResult["code"], rawResult["message"])
                    if "code" in rawResult:
                        return rawResult
                    return rawResult.get("result", None)
                if isinstance(parsed, Error):
                    return parsed
                raise AssertionError("The response must be singular.")
