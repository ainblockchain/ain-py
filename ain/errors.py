class BlockchainError(Exception):
    """Class for the custom error of the blockchain API result."""

    code: int
    """The code of an error."""
    message: str
    """The message of an error."""

    def __init__(self, code: int, message: str):
        self.code = code
        self.message = message
        super().__init__(message)

    def __str__(self):
        return f"{str(self.code)}: {str(self.message)}"
