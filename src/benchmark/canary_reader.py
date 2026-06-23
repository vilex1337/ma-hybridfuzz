"""
Reader for Magma's canary shared-memory storage file (magma/magma/src/storage.h).

Magma's canary mechanism (MAGMA_LOG, injected by magma/targets/*/patches/bugs/*.patch)
records "reached"/"triggered" counters for a bug directly in the binary under test,
synchronously, via an mmap'd file (MAGMA_STORAGE env var). Unlike LLVM source coverage,
these writes survive the process crashing right after, since they happen before the
fault rather than being buffered for an at-exit flush.

Layout (storage.h, verified via offsetof() against the compiled headers):
    canary_t:      char name[16]; uint64 reached; uint64 triggered;  (32 bytes)
    stored_data_t: bool consumed (+pad); data_t producer_buffer; data_t consumer_buffer
    producer_buffer starts at offset 8, holds BUFFERLEN=31 canary_t entries.

We read producer_buffer directly (written unconditionally by magma_log on every call)
rather than following the consumed/consumer_buffer handshake, since we only need to
detect the first reached/triggered>0 transition, not a fully synchronized snapshot.
"""

import struct
from pathlib import Path

FILESIZE = 2048
NAME_SIZE = 16
CANARY_SIZE = 32          # sizeof(canary_t)
BUFFERLEN = 31            # (FILESIZE - sizeof(max_align_t)) / sizeof(canary_t) / 2
PRODUCER_OFFSET = 8       # offsetof(stored_data_t, producer_buffer)


def read_canary(storage_path: str | Path, bug_id: str) -> tuple[int, int] | None:
    """
    Return (reached, triggered) counters for *bug_id* from the canary storage
    file, or None if the file doesn't exist yet or the bug isn't found.
    """
    path = Path(storage_path)
    if not path.exists():
        return None
    try:
        with open(path, "rb") as f:
            buf = f.read(FILESIZE)
    except OSError:
        return None
    if len(buf) < FILESIZE:
        return None

    name_bytes = bug_id.encode()[:NAME_SIZE]
    for i in range(BUFFERLEN):
        off = PRODUCER_OFFSET + i * CANARY_SIZE
        entry_name = buf[off:off + NAME_SIZE].split(b"\0", 1)[0]
        if not entry_name:
            continue
        if entry_name == name_bytes:
            reached, triggered = struct.unpack_from("<QQ", buf, off + NAME_SIZE)
            return reached, triggered
    return None


def init_canary_storage(storage_path: str | Path) -> None:
    """Create/truncate the canary storage file to FILESIZE zero bytes."""
    path = Path(storage_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "wb") as f:
        f.write(b"\0" * FILESIZE)
