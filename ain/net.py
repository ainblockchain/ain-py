from typing import Any
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

    async def getNetworkId(self) -> int:
        """Fetches the ID of the network the blokchain node is connected to."""
        return await self.provider.send("net_getNetworkId")

    async def getChainId(self) -> int:
        """Fetches the ID of the chain the blokchain node is validating."""
        return await self.provider.send("net_getChainId")

    async def isListening(self) -> bool:
        """Checks whether the blockchain node is listening for network connections."""
        return await self.provider.send("net_listening")

    async def isSyncing(self) -> bool:
        """Checks whether the blockchain node is syncing with the network or not."""
        return await self.provider.send("net_syncing")

    async def getPeerCount(self) -> int:
        """Fetches the number of the peers the blockchain node is connected to."""
        return await self.provider.send("net_peerCount")

    async def getConsensusStatus(self) -> Any:
        """Fetches the consensus status of the network."""
        return await self.provider.send("net_consensusStatus")

    async def getRawConsensusStatus(self) -> Any:
        """Fetches the consensus status raw data of the network."""
        return await self.provider.send("net_rawConsensusStatus")

    async def getPeerCandidateInfo(self) -> Any:
        """Fetches the peer candidate information of the blockchain node."""
        return await self.provider.send("p2p_getPeerCandidateInfo")

    async def checkProtocolVersion(self) -> bool:
        """Checks the protocol version."""
        return await self.provider.send("ain_checkProtocolVersion")
    
    async def getProtocolVersion(self) -> str:
        """Returns the protocol version of the node."""
        return await self.provider.send("ain_getProtocolVersion")
    
    async def getEventHandlerNetworkInfo(self) -> Any:
        """Returns the event handler network information."""
        return await self.provider.send("net_getEventHandlerNetworkInfo")
