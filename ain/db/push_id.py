import random
from ain.utils import getTimestamp
from typing import List

"""SEE --> https://gist.github.com/mikelehen/3596a30bd69384624c11

Generator that creates 20-character string identifiers with the following properties:

1. They're based on timestamp so that they sort *after* any existing ids.
2. They contain 72-bits of random data after the timestamp so that IDs won't collide.
3. They sort *lexicographically* (timestamp converted to chars which will sort)
4. They're monotonically increasing. This is done by storing previous random bits
    increasing them only by one.
"""

# ASCII ordered base64 web safe chars.
ASCII_CHARS = "-0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ_abcdefghijklmnopqrstuvwxyz"

class PushId:
    """Timestamp of last push, used to prevent local
    collisions if you push twice in one ms.
    """
    _lastPushTime: int
    """We generate 72-bits of randomness which get
    turned into 12 characters and appended to the
    timestamp to prevent collisions with other clients.
    We store the last characters we generated because
    in the event of a collision, we'll use those same
    characters except "incremented" by one.
    """
    _lastRandChars: bytearray

    def __init__(self):
        self._lastPushTime = 0
        self._lastRandChars = bytearray(12)

    def generate(self) -> str:
        now = getTimestamp()
        duplicateTime = (now == self._lastPushTime)
        self._lastPushTime = now
        timeStampChars: List[str] = []
        for i in range(8):
            timeStampChars.append(ASCII_CHARS[now % 64])
            now //= 64
        if now != 0:
            raise ValueError("We should have converted the entire timestamp.")
        id = "".join(reversed(timeStampChars))
        if not duplicateTime:
            for i in range(12):
                self._lastRandChars[i] = random.randint(0, 63)
        else:
            i = 11
            while i >= 0 and self._lastRandChars[i] == 63:
                self._lastRandChars[i] = 0
                i -= 1
            if i >= 0:
                self._lastRandChars[i] += 1
        for i in range(12):
            id += ASCII_CHARS[self._lastRandChars[i]]
        if len(id) != 20:
            raise AssertionError("Length should be 20.")
        return id

    # TODO(kriii): Implement `Timestamp`.