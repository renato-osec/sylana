"""A live, queryable KLEE session.

Backed by a resident `klee-session` process (the libKLEE fork) that keeps every
terminated state's per-object symbolic memory alive and concretizes reads on
demand. The memory stays queryable exactly as long as this object lives; close()
/ context exit / __del__ terminate the process and free the states.
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Optional

from .errors import SylanaEngineError


class SimulationSession:
    def __init__(self, proc: subprocess.Popen, snapshots: list[str]) -> None:
        self._proc: Optional[subprocess.Popen] = proc
        # One entry per terminated state; the string is its KLEE error suffix.
        self.snapshots = snapshots

    @classmethod
    def spawn(
        cls,
        klee_session_bin: Path,
        linked_bc: Path,
        runtime_lib: Optional[Path] = None,
        runtime_suffix: str = "64_Release",
    ) -> "SimulationSession":
        cmd = [str(klee_session_bin), str(linked_bc)]
        if runtime_lib is not None:
            cmd.append(str(runtime_lib))
            cmd.append(runtime_suffix)
        proc = subprocess.Popen(
            cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, text=True, bufsize=1,
        )
        assert proc.stdout is not None
        header = ""
        for _ in range(1000):
            header = proc.stdout.readline()
            if header == "":
                break
            if header.startswith("ready snapshots="):
                break
        if not header.startswith("ready snapshots="):
            proc.kill()
            raise SylanaEngineError(f"klee-session failed to start: {header!r}")
        count = int(header.split("=", 1)[1])
        snapshots = []
        for _ in range(count):
            parts = proc.stdout.readline().strip().split(" ", 2)
            snapshots.append(parts[2] if len(parts) > 2 else "")
        return cls(proc, snapshots)

    def count(self) -> int:
        return len(self.snapshots)

    def objects(self, snapshot: int = 0) -> list[tuple[int, int]]:
        """List (base_address, size) of every mapped object in a snapshot."""
        self._send(f"objects {snapshot}")
        result = []
        while True:
            line = self._recv()
            if line == "end" or line.startswith("error"):
                break
            base, size = line.split()
            result.append((int(base, 16), int(size)))
        return result

    def read_symbolic(self, address: int, length: int, *, snapshot: int = 0):
        """Report which bytes at `address` are symbolic and the arrays they use.

        Returns {"mask": str of 0/1 per byte, "arrays": [names], "is_symbolic":
        bool} or None if unmapped. A '1' in mask means that byte is a formula,
        not a fixed value; `arrays` names the symbolic inputs it depends on.
        """
        self._send(f"symbolic {snapshot} {address:x} {length}")
        line = self._recv()
        if line == "unmapped":
            return None
        mask, arrays = "", []
        while line != "end" and not line.startswith("error"):
            if line.startswith("bits "):
                mask = line[5:]
            elif line.startswith("arrays "):
                arrays = line[7:].split()
            line = self._recv()
        return {"mask": mask, "arrays": arrays, "is_symbolic": "1" in mask}

    def expr(self, address: int, length: int, *, snapshot: int = 0) -> Optional[str]:
        """Pretty-printed symbolic expression of a 1..8 byte region, or None."""
        self._send(f"expr {snapshot} {address:x} {length}")
        line = self._recv()
        if line == "unmapped":
            return None
        if line.startswith("error"):
            raise SylanaEngineError(line)
        lines = []
        line = self._recv()
        while line != "exprend":
            lines.append(line)
            line = self._recv()
        return "\n".join(lines)

    def read(self, address: int, length: int, *, snapshot: int = 0) -> Optional[bytes]:
        """Concrete bytes at `address` in a snapshot, or None if unmapped."""
        self._send(f"read {snapshot} {address:x} {length}")
        reply = self._recv()
        if reply.startswith("ok "):
            return bytes.fromhex(reply[3:])
        if reply == "unmapped":
            return None
        raise SylanaEngineError(f"klee-session read error: {reply!r}")

    def deref(self, address: int, *, snapshot: int = 0) -> Optional[int]:
        """Read an 8-byte little-endian pointer at `address`."""
        raw = self.read(address, 8, snapshot=snapshot)
        return None if raw is None else int.from_bytes(raw, "little")

    def _send(self, line: str) -> None:
        if self._proc is None or self._proc.poll() is not None:
            raise SylanaEngineError("klee-session process has exited")
        assert self._proc.stdin is not None
        self._proc.stdin.write(line + "\n")
        self._proc.stdin.flush()

    def _recv(self) -> str:
        assert self._proc is not None and self._proc.stdout is not None
        return self._proc.stdout.readline().strip()

    def close(self) -> None:
        proc, self._proc = self._proc, None
        if proc is None or proc.poll() is not None:
            return
        try:
            if proc.stdin is not None:
                proc.stdin.write("quit\n")
                proc.stdin.flush()
            proc.wait(timeout=5)
        except Exception:
            proc.kill()

    def __enter__(self) -> "SimulationSession":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:
            pass
