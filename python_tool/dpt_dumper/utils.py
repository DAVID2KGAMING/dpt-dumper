import os
import sys

_PREFIX = {"info": "[*]", "success": "[+]", "error": "[!]", "debug": "[DEBUG]"}
QUIET = False


def log(msg: str, level: str = "info") -> None:
    if QUIET and level in ("info", "debug"):
        return
    stream = sys.stderr if level == "error" else sys.stdout
    print(f"{_PREFIX.get(level, '[*]')} {msg}", file=stream, flush=True)


def ensure_dir(path: str) -> None:
    os.makedirs(path, exist_ok=True)


def read_file(path: str) -> bytes:
    with open(path, "rb") as f:
        return f.read()


def write_file(path: str, data: bytes) -> None:
    ensure_dir(os.path.dirname(path) or ".")
    with open(path, "wb") as f:
        f.write(data)
