from ain.provider import Provider
from ain.constants import BLOCKCHAIN_PROTOCOL_VERSION

class Network:
    provider: Provider
    protoVer: str
    
    def __init__(self, provider: Provider):
        self.provider = provider
        self.protoVer = BLOCKCHAIN_PROTOCOL_VERSION

    async def isListening(self) -> bool:
        """
        Returns whether the node is listening for network connections.
        """
        return await self.provider.send("net_listening")
    
    async def getNetworkId(self) -> str:
        """
        Returns the id of the network the node is connected to.
        """
        return await self.provider.send("net_getNetworkId")

    async def checkProtocolVersion(self) -> dict:
        """
        Checks the protocol version.
        """
        return await self.provider.send("ain_checkProtocolVersion")
    
    async def getProtocolVersion(self) -> str:
        """
        Returns the protocol version of the node.
        """
        return await self.provider.send("ain_getProtocolVersion")
    
    async def getPeerCount(self) -> int:
        """
        Returns the number of peers the provider node is connected to.
        """
        return await self.provider.send("net_peerCount")

    async def isSyncing(self) -> bool:
        """
        Returns whether the node is syncing with the network or not.
        """
        return await self.provider.send("net_syncing")

    async def getEventHandlerNetworkInfo(self) -> dict:
        """
        Returns the event handler network information.
        """
        return await self.provider.send("net_getEventHandlerNetworkInfo")
