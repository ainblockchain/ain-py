import string


class BlockchainError(Exception):
    code: int
    message: str

    def __init__(self, code, message):
        self.code = code
        self.message = message
        super().__init__(message)

    def __str__(self):
        return f"{str(self.code)}: {str(self.message)}"
