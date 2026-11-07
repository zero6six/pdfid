"""Unified byte-stream input for the scanner.

Accepts a local file path, an ``http(s)`` URL, a ``.zip`` archive (the first
entry is read, using the malware-sample convention password ``infected``),
standard input, raw ``bytes`` or any file-like object, and exposes a small
byte-oriented reader with push-back support.
"""

from __future__ import annotations

import sys
import zipfile
from io import BytesIO
from pathlib import Path
from typing import BinaryIO, List, Optional, Union
from urllib.error import URLError
from urllib.request import urlopen

PathLike = Union[str, 'Path', bytes, BinaryIO]

#: Password used for password-protected malware sample archives.
ZIP_PASSWORD = b'infected'

#: Timeout (seconds) for URL downloads.
URL_TIMEOUT = 5.0


class InputError(Exception):
    """Raised when an input source cannot be opened."""


class BinaryFile:
    """Byte reader with single- and multi-byte unget (push-back) support."""

    def __init__(self, source: PathLike, timeout: float = URL_TIMEOUT):
        self._pushback: List[int] = []
        self._stream: BinaryIO
        self._zipfile: Optional[zipfile.ZipFile] = None

        if isinstance(source, bytes):
            source = BytesIO(source)

        if hasattr(source, 'read'):  # file-like: BytesIO, HTTP response, ...
            self._stream = source  # type: ignore[assignment]
        elif isinstance(source, str) and source in ('', '-'):
            self._stream = sys.stdin.buffer  # type: ignore[assignment]
        else:
            path = str(source)
            lowered = path.lower()
            try:
                if lowered.startswith('http://') or lowered.startswith('https://'):
                    self._stream = urlopen(path, timeout=timeout)  # type: ignore[assignment]
                elif lowered.endswith('.zip'):
                    self._zipfile = zipfile.ZipFile(path, 'r')
                    entry = self._zipfile.infolist()[0]
                    self._stream = self._zipfile.open(entry, 'r', pwd=ZIP_PASSWORD)  # type: ignore[assignment]
                else:
                    self._stream = open(path, 'rb')
            except (OSError, URLError, RuntimeError, zipfile.BadZipFile, IndexError) as error:
                raise InputError(f'Error opening file {path}: {error}') from error

    # -- context manager ------------------------------------------------
    def __enter__(self) -> 'BinaryFile':
        return self

    def __exit__(self, *exc_info) -> None:
        self.close()

    def close(self) -> None:
        try:
            self._stream.close()
        except Exception:  # noqa: BLE001 - best effort close
            pass
        if self._zipfile is not None:
            try:
                self._zipfile.close()
            except Exception:  # noqa: BLE001
                pass

    # -- reading ---------------------------------------------------------
    def read_byte(self) -> Optional[int]:
        """Return the next byte as an int, or ``None`` at end of input."""
        if self._pushback:
            return self._pushback.pop()
        data = self._stream.read(1)
        if not data:
            return None
        return data[0]

    def read(self, size: int) -> List[int]:
        """Read up to ``size`` bytes as a list of ints (push-back aware)."""
        if size <= 0:
            return []
        if size > len(self._pushback):
            data = self._stream.read(size - len(self._pushback))
            self._pushback.extend(data)
        result = self._pushback[:size]
        del self._pushback[:size]
        return result

    # -- push-back --------------------------------------------------------
    def unget(self, byte: int) -> None:
        """Push a single byte back so it is returned by the next read."""
        self._pushback.append(byte)

    def ungets(self, data: List[int]) -> None:
        """Push a sequence of bytes back (last byte is read first)."""
        self._pushback.extend(reversed(data))
