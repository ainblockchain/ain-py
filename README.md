# ain-py

## Installation
```
pip install -i ain
```

## Run all test
```
tox
```

## Examples
```python
from ain.ain import Ain
import asyncio

ain = Ain('http://node.ainetwork.ai:8080/', chainId=None)

async def process():
    accounts = await ain.db.ref('/accounts').getValue()
    print(accounts)

loop = asyncio.get_event_loop()
loop.run_until_complete(process())
```