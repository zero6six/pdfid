"""Core PDFiD scanner.

A deliberately *simple*, byte-oriented string scanner: it never fully parses
the PDF structure (that would require a complex - and exploitable - parser),
it only counts keywords, decodes hex-encoded name obfuscation (``/J#61va*``),
tracks stream boundaries, extracts dates/entropy/EOF statistics and can
"disarm" a document by case-swapping dangerous names.
"""

from __future__ import annotations

import os
import sys
import traceback
from io import BytesIO
from pathlib import Path
from typing import List, Optional, Tuple, Union

from pdfid import __version__
from pdfid.model import (
    COLORS_PSEUDO_KEYWORD,
    DateEntry,
    EOFStats,
    KeywordCount,
    PDFiDResult,
)
from pdfid.reader import BinaryFile, InputError
from pdfid.stats import EntropyTracker, EOFTracker, PDFDateParser

#: Names neutralized (case-swapped) by the disarm feature.
DISARM_KEYWORDS = frozenset({
    '/JS', '/JavaScript', '/AA', '/OpenAction', '/JBIG2Decode', '/RichMedia', '/Launch',
})

#: CVE-2009-3459: /Colors values expressed with more than 3 bytes (> 2**24).
#: (The original code compared against ``2^24`` - a bitwise XOR equal to 26 -
#: which was a long-standing bug; fixed here.)
COLORS_LIMIT = 2 ** 24

Source = Union[str, bytes, BytesIO, Path]

_HEX_DIGITS = frozenset('0123456789abcdefABCDEF')


def _find_pdf_header(binary_file: BinaryFile) -> Tuple[List[int], Optional[str]]:
    """Look for a relaxed ``%PDF-x.y`` header within the first 1024 bytes.

    Returns ``(header_bytes, header_string)``; header_string is ``None`` when
    no header was found.  Consumed non-header bytes are pushed back.
    """
    data = binary_file.read(1024)
    text = bytes(data).decode('latin-1')
    index = text.find('%PDF')
    if index == -1:
        binary_file.ungets(data)
        return [], None
    end = index + 4
    limit = min(len(data), index + 4 + 10)
    while end < limit and data[end] not in (10, 13):
        end += 1
    binary_file.ungets(data[end:])
    return data[:end], text[index:end]


def _render_exact(word_exact: list, swapcase: bool = False) -> str:
    """Render a scanned name back to its literal form.

    ``word_exact`` holds single-character strings plus decoded hex-name bytes
    (ints); the latter are re-encoded as ``#xx`` so disarm output stays valid.
    """
    parts = []
    for element in word_exact:
        if isinstance(element, int):
            if swapcase:
                element = ord(chr(element).swapcase())  # keep legacy disarm byte encoding
            parts.append('#%02x' % element)
        elif swapcase:
            parts.append(element.swapcase())
        else:
            parts.append(element)
    return ''.join(parts)


def _scan(binary_file: BinaryFile, result: PDFiDResult, *, all_names: bool,
          extra_data: bool, disarm: bool, force: bool,
          out_file=None) -> None:
    keywords = result.keywords
    dates = result.dates

    word = ''
    word_exact: list = []
    hexcode = False
    last_name = ''
    inside_stream = False
    slash = False
    colors_violations = 0

    date_parser = PDFDateParser() if extra_data else None
    entropy = EntropyTracker() if extra_data else None
    eof_tracker = EOFTracker() if extra_data else None

    header_bytes, header = _find_pdf_header(binary_file)

    result.is_pdf = header is not None
    if header is None and not force:
        return  # not a PDF, and not forced: stop here
    result.header = header

    for byte in header_bytes:
        if out_file is not None:
            out_file.write(bytes([byte]))
        if entropy is not None:
            entropy.add(byte, inside_stream)

    def flush_word() -> None:
        """Terminate the current word: update counters, stream state, disarm output."""
        nonlocal word, word_exact, hexcode, last_name, inside_stream
        if word:
            key = '/' + word if slash else word
            entry = keywords.get(key)
            if entry is None and slash and all_names:
                entry = keywords[key] = KeywordCount(key)
            if entry is not None:
                entry.count += 1
                if hexcode:
                    entry.hexcode += 1
            if slash:
                last_name = key
            elif word == 'stream':
                inside_stream = True
            elif word == 'endstream':
                if inside_stream and entropy is not None:
                    for char in 'endstream':
                        entropy.remove_inside_stream(ord(char))
                inside_stream = False
        if out_file is not None and word_exact:
            literal = _render_exact(word_exact)
            if slash and '/' + word in DISARM_KEYWORDS:
                swapped = _render_exact(word_exact, swapcase=True)
                out_file.write(swapped.encode('latin-1'))
                print(f'/{word} -> {swapped}', file=sys.stderr)
            else:
                out_file.write(literal.encode('latin-1'))
        word = ''
        word_exact = []
        hexcode = False

    while True:
        byte = binary_file.read_byte()
        if byte is None:
            break
        char = chr(byte)
        upper = char.upper()
        if 'A' <= upper <= 'Z' or '0' <= char <= '9':
            word += char
            word_exact.append(char)
        elif slash and char == '#':
            first = binary_file.read_byte()
            if first is None:
                flush_word()
                if out_file is not None:
                    out_file.write(char.encode('latin-1'))
            else:
                second = binary_file.read_byte()
                if second is not None and chr(first) in _HEX_DIGITS and chr(second) in _HEX_DIGITS:
                    value = int(chr(first) + chr(second), 16)
                    word += chr(value)
                    word_exact.append(value)
                    hexcode = True
                    if entropy is not None:
                        entropy.add(first, inside_stream)
                        entropy.add(second, inside_stream)
                    if eof_tracker is not None:
                        eof_tracker.parse(chr(first))
                        eof_tracker.parse(chr(second))
                else:
                    if second is not None:
                        binary_file.unget(second)
                    binary_file.unget(first)
                    flush_word()
                    if out_file is not None:
                        out_file.write(char.encode('latin-1'))
        else:
            # Word boundary: CVE-2009-3459 check then close the current word.
            if last_name == '/Colors' and word.isdigit() and int(word) > COLORS_LIMIT:
                colors_violations += 1
            flush_word()
            slash = char == '/'
            if out_file is not None:
                out_file.write(char.encode('latin-1'))

        if date_parser is not None:
            date_value = date_parser.parse(char)
            if date_value is not None:
                dates.append(DateEntry(date_value, last_name))
        if entropy is not None:
            entropy.add(byte, inside_stream)
        if eof_tracker is not None:
            eof_tracker.parse(char)

    flush_word()
    if eof_tracker is not None:
        eof_tracker.finish()

    dates.sort(key=lambda entry: entry.value)
    keywords[COLORS_PSEUDO_KEYWORD].count = colors_violations
    if entropy is not None:
        result.entropy = entropy.calc()
    if eof_tracker is not None:
        result.eof = EOFStats(count_eofs=eof_tracker.count_eofs,
                              chars_after_last_eof=eof_tracker.chars_after_last_eof)


def PDFiD(source: Source, all_names: bool = False, extra_data: bool = False,
          disarm: bool = False, force: bool = False, **legacy_kwargs) -> PDFiDResult:
    """Scan ``source`` and return a :class:`PDFiDResult`.

    Args:
        source: file path, ``http(s)`` URL, ``.zip`` archive, ``bytes``,
            file-like object, or ``''``/``'-'`` for standard input.
        all_names: also count every ``/Name`` (not just the known keywords).
        extra_data: collect dates, entropy and ``%%EOF`` statistics.
        disarm: write a copy with dangerous names case-swapped
            (only supported for real file paths).
        force: scan even without a ``%PDF`` header.

    Legacy keyword aliases ``allNames`` and ``extraData`` are accepted for
    backward compatibility with the pre-1.0 API.
    """
    if 'allNames' in legacy_kwargs:
        all_names = bool(legacy_kwargs.pop('allNames'))
    if 'extraData' in legacy_kwargs:
        extra_data = bool(legacy_kwargs.pop('extraData'))
    if legacy_kwargs:
        raise TypeError(f'unexpected arguments: {", ".join(legacy_kwargs)}')

    result = PDFiDResult(filename=str(source), version=__version__, all_names=all_names)

    out_file = None
    try:
        binary_file = BinaryFile(source)
    except InputError as error:
        result.error_occurred = True
        result.error_message = str(error)
        return result

    try:
        try:
            if disarm:
                if not isinstance(source, (str, Path)):
                    raise InputError('Option disarm not supported for this input type')
                stem, extension = os.path.splitext(str(source))
                disarmed_path = f'{stem}.disarmed{extension}'
                out_file = open(disarmed_path, 'wb')
                result.disarmed_to = disarmed_path
            with binary_file:
                _scan(binary_file, result, all_names=all_names, extra_data=extra_data,
                      disarm=disarm, force=force, out_file=out_file)
        finally:
            if out_file is not None:
                out_file.close()
    except Exception:  # noqa: BLE001 - report any failure in the result
        result.error_occurred = True
        result.error_message = traceback.format_exc()

    return result
