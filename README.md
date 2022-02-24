# ain-py

A python version of [ain-js](https://www.npmjs.com/package/@ainblockchain/ain-js).

## Installation
```
pip install ain-py
```

## Run all test
```
tox
```

## Examples
```python
from ain.ain import Ain
import asyncio

ain = Ain('https://mainnet-api.ainetwork.ai/')

async def process():
    accounts = await ain.db.ref('/accounts').getValue()
    print(accounts)

loop = asyncio.get_event_loop()
loop.run_until_complete(process())
```