from typing import TYPE_CHECKING
from ain.db.ref import Reference

if TYPE_CHECKING:
    from ain.ain import Ain
    from ain.provider import Provider

class Database:
    """Class for the AIN Database instance."""

    _ain: "Ain"
    _provider: "Provider"
    
    def __init__(self, ain: "Ain", provider: "Provider"):
        self._ain = ain
        self._provider = provider

    def ref(self, path: str = None) -> Reference:
        """Creates a `Reference` to the given path at the AIN Blockchain Database(global state tree).

        Args:
            path (str, Optional): The path that you want to create a `Reference`.
                If `path` is `None`, references the root of the tree. Defaults to `None`.

        Returns:
            Reference: The `Reference` at the path.
        """
        return Reference(self._ain, path)

