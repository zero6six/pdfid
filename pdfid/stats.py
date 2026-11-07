"""Streaming statistics used when scanning with ``extra_data`` enabled:
byte entropy, ``%%EOF`` counting and PDF date extraction.
"""

from __future__ import annotations

import math
from typing import Iterable, List, Optional

from pdfid.model import EntropyStats


def shannon_entropy(counts: Iterable[int]) -> float:
    """Shannon entropy (bits per byte) from a 256-bucket byte histogram."""
    histogram = list(counts)
    total = sum(histogram)
    if total <= 0:
        return 0.0
    return -sum((count / total) * math.log2(count / total) for count in histogram if count > 0)


class EntropyTracker:
    """Accumulates byte histograms for the whole file and for stream contents."""

    __slots__ = ('_all', '_stream')

    def __init__(self) -> None:
        self._all: List[int] = [0] * 256
        self._stream: List[int] = [0] * 256

    def add(self, byte: int, inside_stream: bool) -> None:
        self._all[byte] += 1
        if inside_stream:
            self._stream[byte] += 1

    def remove_inside_stream(self, byte: int) -> None:
        """Undo a previous ``add`` (used for ``endstream`` markers)."""
        if self._stream[byte] > 0:
            self._stream[byte] -= 1

    def calc(self) -> EntropyStats:
        non_stream = [a - s for a, s in zip(self._all, self._stream)]
        return EntropyStats(
            total_entropy=shannon_entropy(self._all),
            total_count=sum(self._all),
            stream_entropy=shannon_entropy(self._stream),
            stream_count=sum(self._stream),
            non_stream_entropy=shannon_entropy(non_stream),
            non_stream_count=sum(non_stream),
        )


class EOFTracker:
    """Counts ``%%EOF`` markers and characters trailing the last one.

    Data appended after the final ``%%EOF`` (e.g. by incremental updates or
    by an attacker hiding content) is a classic triage signal.
    """

    _TOKEN = '%%EOF'

    def __init__(self) -> None:
        self.count_eofs = 0
        self.chars_after_last_eof = 0
        self._token = ''

    def parse(self, char: str) -> None:
        if self.count_eofs > 0:
            self.chars_after_last_eof += 1

        if self._token == '' and char == '%':
            self._token = '%'
        elif self._token == '%' and char == '%':
            self._token = '%%'
        elif self._token == '%%' and char == 'E':
            self._token = '%%E'
        elif self._token == '%%E' and char == 'O':
            self._token = '%%EO'
        elif self._token == '%%EO' and char == 'F':
            self._token = '%%EOF'
        elif self._token == '%%EOF' and char in '\n\r \t':
            self.count_eofs += 1
            self.chars_after_last_eof = 0
            if char == '\n':
                self._token = ''
            else:
                self._token += char  # e.g. '%%EOF\r', may be followed by \n
        elif self._token == '%%EOF\r':
            if char == '\n':
                self.chars_after_last_eof = 0  # CRLF belongs to the marker
            self._token = ''
        else:
            self._token = ''

    def finish(self) -> None:
        """Handle a file ending exactly on ``%%EOF`` without trailing newline."""
        if self._token == '%%EOF':
            self.count_eofs += 1
            self.chars_after_last_eof = 0
            self._token = ''

    @property
    def token(self) -> str:
        return self._token


class PDFDateParser:
    """Streaming state machine extracting PDF date strings.

    Recognized formats: ``D:YYYYMMDDHHmmSS`` (at least 14 digits) optionally
    followed by a timezone: ``+HH'mm``, ``-HH'mm`` or ``Z``.
    """

    def __init__(self) -> None:
        self._state = 0
        self._digits1 = ''
        self._digits2 = ''
        self._tz = ''
        self.date: Optional[str] = None

    def _finish(self, date: str) -> str:
        self._state = 0
        self.date = date
        return date

    def parse(self, char: str) -> Optional[str]:
        """Consume one character; return a complete date string when one ends."""
        if self._state == 0:
            if char == 'D':
                self._state = 1
        elif self._state == 1:
            if char == ':':
                self._digits1 = ''
                self._state = 2
            else:
                self._state = 0
        elif self._state == 2:
            if char.isdigit() and len(self._digits1) < 14:
                self._digits1 += char
            elif len(self._digits1) == 14:
                if char in ('+', '-', 'Z'):
                    self._tz = char
                    self._digits2 = ''
                    self._state = 3
                elif not char.isdigit():
                    # A non-digit (e.g. ')') terminates the date.
                    return self._finish(f'D:{self._digits1}')
                else:
                    self._state = 0  # more than 14 digits: not a date
            else:
                self._state = 0  # non-digit before 14 digits: abandon
        elif self._state == 3:
            if len(self._digits2) < 2:
                if char.isdigit():
                    self._digits2 += char
                else:
                    self._state = 0
            elif len(self._digits2) == 2:
                if char == "'":
                    self._digits2 += char
                else:
                    self._state = 0
            elif char.isdigit():  # collecting minutes: "hh'mm"
                self._digits2 += char
                if len(self._digits2) == 5:
                    return self._finish(f'D:{self._digits1}{self._tz}{self._digits2}')
            else:
                self._state = 0
        return None
