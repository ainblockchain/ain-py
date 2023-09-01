# ain-py

A python version of [ain-js](https://www.npmjs.com/package/@ainblockchain/ain-js).


## Installation
```
pip install ain-py
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


## Test How-To
1. Clone AIN Blockchain and install
```
git clone git@github.com:ainblockchain/ain-blockchain.git
yarn install
```

2. Start blockchain locally
```
bash start_local_blockchain.sh
```

3. Run tests
```
tox
```


## License

This project is licensed under the MIT License

