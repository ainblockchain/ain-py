import aiohttp
import asyncio
import json

def asyncTest(coroutine):
    def wrapper(*args, **kwargs):
        loop = asyncio.new_event_loop()
        try:
            return loop.run_until_complete(coroutine(*args, **kwargs))
        finally:
            loop.close()
    return wrapper

async def getRequest(url: str):
    async with aiohttp.ClientSession() as session:
        async with session.get(url) as response:
            res = await response.read()
            return json.loads(res)

async def postRequest(url: str, params: dict = {}):
    dump = json.dumps(params)
    async with aiohttp.ClientSession() as session:
        async with session.post(url, json=json.loads(dump)) as response:
            res = await response.read()
            return json.loads(res)

async def waitUntilTxFinalized(testNode: str, txHash: str) -> bool:
    MAX_ITERATION = 20
    for _ in range(MAX_ITERATION):
        try:
            res = await getRequest(f"{testNode}/get_transaction?hash={txHash}")
            if res["result"]["is_finalized"]:
                return True
        except:
            pass
        await asyncio.sleep(5)
    return False