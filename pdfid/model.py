"""Data model for PDFiD scan results.

The original code passed around an ``xml.dom.minidom`` document as its data
structure.  This module replaces that with plain dataclasses: the scanner
produces a :class:`PDFiDResult`, and the renderers (text/JSON/CSV/XML) consume
it.  Convenience attributes (``result.js``, ``result.isPDF``, ...) keep the
historical ``select`` expressions working, e.g. ``pdf.js.count > 0``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterator, Optional, Union

#: Keyword table, in canonical output order.
KEYWORDS: tuple = (
    'obj',
    'endobj',
    'stream',
    'endstream',
    'xref',
    'trailer',
    'startxref',
    '/Page',
    '/Encrypt',
    '/ObjStm',
    '/JS',
    '/JavaScript',
    '/AA',
    '/OpenAction',
    '/AcroForm',
    '/JBIG2Decode',
    '/RichMedia',
    '/Launch',
    '/EmbeddedFile',
    '/XFA',
)

#: Pseudo keyword used to report CVE-2009-3459 (/Colors with > 24-bit values).
COLORS_PSEUDO_KEYWORD = '/Colors > 2^24'

#: All entries always present in :attr:`PDFiDResult.keywords`.
_ALL_KEYWORDS: tuple = KEYWORDS + (COLORS_PSEUDO_KEYWORD,)


@dataclass
class KeywordCount:
    """Occurrences of one keyword: total and obfuscated (hex-encoded) count."""

    name: str
    count: int = 0
    hexcode: int = 0


@dataclass
class DateEntry:
    """A PDF date (``D:...``) found in the document, with the name it belongs to."""

    value: str
    name: str


@dataclass
class EntropyStats:
    """Shannon entropy computed over the whole file / inside streams / outside streams."""

    total_entropy: float = 0.0
    total_count: int = 0
    stream_entropy: float = 0.0
    stream_count: int = 0
    non_stream_entropy: float = 0.0
    non_stream_count: int = 0


@dataclass
class EOFStats:
    """``%%EOF`` marker statistics."""

    count_eofs: int = 0
    chars_after_last_eof: int = 0


def _new_keywords() -> dict:
    return {name: KeywordCount(name) for name in _ALL_KEYWORDS}


@dataclass
class PDFiDResult:
    """Complete result of a PDFiD scan.

    Attributes mirror the historical CLI/XML output.  ``keywords`` always
    contains the entries of :data:`KEYWORDS` plus the pseudo keyword
    ``/Colors > 2^24``; when ``all_names`` is enabled, every ``/Name`` found
    in the document is added as an extra entry.
    """

    filename: str
    version: str
    all_names: bool = False
    is_pdf: bool = False
    header: Optional[str] = None
    error_occurred: bool = False
    error_message: str = ''
    keywords: dict = field(default_factory=_new_keywords)
    dates: list = field(default_factory=list)
    entropy: Optional[EntropyStats] = None
    eof: Optional[EOFStats] = None
    disarmed_to: Optional[str] = None

    # ------------------------------------------------------------------
    # Convenience accessors (historical cPDFiD attribute names)
    # ------------------------------------------------------------------
    @property
    def obj(self) -> KeywordCount:
        return self.keywords['obj']

    @property
    def endobj(self) -> KeywordCount:
        return self.keywords['endobj']

    @property
    def stream(self) -> KeywordCount:
        return self.keywords['stream']

    @property
    def endstream(self) -> KeywordCount:
        return self.keywords['endstream']

    @property
    def xref(self) -> KeywordCount:
        return self.keywords['xref']

    @property
    def trailer(self) -> KeywordCount:
        return self.keywords['trailer']

    @property
    def startxref(self) -> KeywordCount:
        return self.keywords['startxref']

    @property
    def page(self) -> KeywordCount:
        return self.keywords['/Page']

    @property
    def encrypt(self) -> KeywordCount:
        return self.keywords['/Encrypt']

    @property
    def objstm(self) -> KeywordCount:
        return self.keywords['/ObjStm']

    @property
    def js(self) -> KeywordCount:
        return self.keywords['/JS']

    @property
    def javascript(self) -> KeywordCount:
        return self.keywords['/JavaScript']

    @property
    def aa(self) -> KeywordCount:
        return self.keywords['/AA']

    @property
    def openaction(self) -> KeywordCount:
        return self.keywords['/OpenAction']

    @property
    def acroform(self) -> KeywordCount:
        return self.keywords['/AcroForm']

    @property
    def jbig2decode(self) -> KeywordCount:
        return self.keywords['/JBIG2Decode']

    @property
    def richmedia(self) -> KeywordCount:
        return self.keywords['/RichMedia']

    @property
    def launch(self) -> KeywordCount:
        return self.keywords['/Launch']

    @property
    def embeddedfile(self) -> KeywordCount:
        return self.keywords['/EmbeddedFile']

    @property
    def xfa(self) -> KeywordCount:
        return self.keywords['/XFA']

    @property
    def colors_gt_2_24(self) -> KeywordCount:
        return self.keywords[COLORS_PSEUDO_KEYWORD]

    # Historical camelCase aliases, used by legacy select expressions.
    @property
    def errorOccured(self) -> bool:  # noqa: N802 - legacy API
        return self.error_occurred

    @property
    def errorMessage(self) -> str:  # noqa: N802 - legacy API
        return self.error_message

    @property
    def isPDF(self) -> bool:  # noqa: N802 - legacy API
        return self.is_pdf

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    def iter_keywords(self, all_names: Union[bool, None] = None) -> Iterator[KeywordCount]:
        """Iterate keyword entries in canonical order (fixed keywords first,
        then alphabetically sorted extra names when ``all_names`` is on)."""
        if all_names is None:
            all_names = self.all_names
        for name in _ALL_KEYWORDS:
            yield self.keywords[name]
        if all_names:
            extras = set(self.keywords) - set(_ALL_KEYWORDS)
            for name in sorted(extras):
                yield self.keywords[name]
