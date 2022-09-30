from ain.provider import Provider
from ain.constants import BLOCKCHAIN_PROTOCOL_VERSION

class Network:
    """Class for the AIN Blockchain network status checker."""

    provider: Provider
    """The `Provider` instance."""
    protoVer: str
    """The protocol version of the blockchain."""
    
    def __init__(self, provider: Provider):
        self.provider = provider
        self.protoVer = BLOCKCHAIN_PROTOCOL_VERSION

    async def isListening(self):
        """Returns whether the node is listening for network connections."""
        return await self.provider.send("net_listening")
    
    async def getNetworkId(self):
        """Returns the id of the network the node is connected to."""
        return await self.provider.send("net_getNetworkId")

    async def checkProtocolVersion(self):
        """Checks the protocol version."""
        return await self.provider.send("ain_checkProtocolVersion")
    
    async def getProtocolVersion(self):
        """Returns the protocol version of the node."""
        return await self.provider.send("ain_getProtocolVersion")
    
    async def getPeerCount(self):
        """Returns the number of peers the provider node is connected to."""
        return await self.provider.send("net_peerCount")

    async def isSyncing(self):
        """Returns whether the node is syncing with the network or not."""
        return await self.provider.send("net_syncing")

    async def getEventHandlerNetworkInfo(self):
        """Returns the event handler network information."""
        return await self.provider.send("net_getEventHandlerNetworkInfo")
