from ain.provider import Provider
from ain.constants import BLOCKCHAIN_PROTOCOL_VERSION

class Network:
    provider: Provider
    protoVer: str
    
    def __init__(self, provider: Provider):
        self.provider = provider
        self.protoVer = BLOCKCHAIN_PROTOCOL_VERSION
