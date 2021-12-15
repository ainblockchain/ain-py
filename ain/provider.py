import aiohttp
import json
from urllib.parse import urlparse, urljoin
from jsonrpcclient import request, parse, Ok, Error
from typing import TYPE_CHECKING, Any

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
                    return parsed.result.get("result", None)
                if isinstance(parsed, Error):
                    return parsed
                raise AssertionError("The response must be singular.")
