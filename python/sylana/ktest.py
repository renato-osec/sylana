"""Parser for KLEE .ktest witness files.

Format (version 3): b"KTEST" magic, uint32 BE version, uint32 BE numArgs then
each arg (uint32 len + bytes), uint32 symArgvs, uint32 symArgvLen, uint32
numObjects, then per object uint32 nameLen + name + uint32 size + bytes.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

_MAGIC = b"KTEST"
_OLD_MAGIC = b"BOUT\n"


@dataclass(frozen=True)
class KTestObject:
    name: str
    data: bytes


@dataclass(frozen=True)
class KTest:
    version: int
    args: tuple[str, ...]
    objects: tuple[KTestObject, ...]

    def get(self, name: str) -> bytes | None:
        for obj in self.objects:
            if obj.name == name:
                return obj.data
        return None

    def as_dict(self) -> dict[str, bytes]:
        return {obj.name: obj.data for obj in self.objects}


def _read_u32(blob: bytes, offset: int) -> tuple[int, int]:
    (value,) = struct.unpack_from(">I", blob, offset)
    return value, offset + 4


def parse(blob: bytes) -> KTest:
    """Parse a .ktest byte string into a KTest."""
    if blob[:5] not in (_MAGIC, _OLD_MAGIC):
        raise ValueError("not a KTEST file")
    offset = 5
    version, offset = _read_u32(blob, offset)

    num_args, offset = _read_u32(blob, offset)
    args = []
    for _ in range(num_args):
        length, offset = _read_u32(blob, offset)
        args.append(blob[offset:offset + length].decode("utf-8", "replace"))
        offset += length

    _, offset = _read_u32(blob, offset)  # symArgvs
    _, offset = _read_u32(blob, offset)  # symArgvLen

    num_objects, offset = _read_u32(blob, offset)
    objects = []
    for _ in range(num_objects):
        name_len, offset = _read_u32(blob, offset)
        name = blob[offset:offset + name_len].decode("utf-8", "replace")
        offset += name_len
        size, offset = _read_u32(blob, offset)
        data = blob[offset:offset + size]
        offset += size
        objects.append(KTestObject(name=name, data=data))

    return KTest(version=version, args=tuple(args), objects=tuple(objects))


def parse_file(path: str) -> KTest:
    with open(path, "rb") as handle:
        return parse(handle.read())


# The witness-export idiom (make_symbolic + assume) adds one equality per
# exported object; those are not real branch decisions, so drop them.
_EXPORT_MARKERS = ("_after", "return_value", "callarg.")


def constraints_from_kquery(text: str) -> tuple[str, ...]:
    """Extract the path-condition clauses over the symbolic inputs from a KLEE
    `.kquery`, dropping the witness-export equalities. Each clause is returned as
    one-line KQuery text (e.g. "(Ule (ReadLSB w64 0 account1.data[0:8]) 100)")."""
    start = text.find("(query")
    if start == -1:
        return ()
    lb = text.find("[", start)
    if lb == -1:
        return ()
    clauses: list[str] = []
    depth = 0
    buf: list[str] = []
    for ch in text[lb + 1:]:
        if ch == "]" and depth == 0:
            break
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        buf.append(ch)
        if depth == 0 and ch == ")":
            clauses.append(" ".join("".join(buf).split()))
            buf = []
    return tuple(
        c for c in clauses if c and not any(m in c for m in _EXPORT_MARKERS)
    )
