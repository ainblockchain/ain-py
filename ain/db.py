from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ain.ain import Ain
    from ain.provider import Provider


class Database:
    def __init__(self, ain: "Ain", provider: "Provider"):
        self.ain = ain
        self.provider = provider
