from typing import TYPE_CHECKING
from ain.ain_db.ref import Reference

if TYPE_CHECKING:
    from ain.ain import Ain
    from ain.provider import Provider

class Database:
    _ain: "Ain"
    _provider: "Provider"
    
    def __init__(self, ain: "Ain", provider: "Provider"):
        self._ain = ain
        self._provider = provider

    def ref(self, path: str = None) -> Reference:
        return Reference(self._ain, path)

