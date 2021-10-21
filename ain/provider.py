import aiohttp
import asyncio
from urllib.parse import urlparse, urljoin
from jsonrpcclient import request, parse, Ok
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ain.ain import Ain

JSON_RPC_ENDPOINT = "json-rpc"

class Provider:
    def __init__(self, ain: "Ain", endpoint: str):
        self.ain = ain
        parsed = urlparse(endpoint)
        self.endPoint = parsed.geturl()
        self.apiEndPoint = urljoin(self.endPoint, JSON_RPC_ENDPOINT)

    async def send(self, rpcMethod: str, params: dict = {}):
        params.update({"protoVer": self.ain.net.protoVer})
        json = request(rpcMethod, params=params, id=0)
        async with aiohttp.ClientSession() as session:
            async with session.post(self.apiEndPoint, json=json) as response:
                parsed = parse(await response.json())
                if isinstance(parsed, Ok):
                    print(parsed.result)
                # TODO(kriii):  match return value to js
                return parsed.result
