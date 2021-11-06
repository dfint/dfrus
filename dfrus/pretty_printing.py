import sys
import textwrap
from typing import Iterable, Optional


def myrepr(s: str):
    text = repr(s)
    if sys.stdout:
        b = text.encode(sys.stdout.encoding, 'backslashreplace')
        text = b.decode(sys.stdout.encoding, 'strict')
    return text


def format_hex_list(s: Iterable[int], wrap_at: Optional[int] = None):
    result = "[{}]".format(', '.join(hex(x) for x in sorted(s)))
    if wrap_at:
        return textwrap.wrap(result, wrap_at)
    else:
        return result
