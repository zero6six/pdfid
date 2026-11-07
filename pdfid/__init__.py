"""PDFiD: a simple PDF triage scanner.

Scans PDF documents for suspicious keywords (/JavaScript, /OpenAction, ...)
including hex-encoded name obfuscation, without implementing a full - and
therefore risky - PDF parser.  Modernized Python 3 rewrite of Didier Stevens'
pdfid.py.

Typical use::

    from pdfid import PDFiD

    result = PDFiD('sample.pdf', extra_data=True)
    print(result.javascript.count, result.openaction.count)
"""

__version__ = '1.0.0'
__author__ = 'Didier Stevens / Raphaël Vinot'

from pdfid.model import (
    COLORS_PSEUDO_KEYWORD,
    KEYWORDS,
    DateEntry,
    EntropyStats,
    EOFStats,
    KeywordCount,
    PDFiDResult,
)
from pdfid.plugins import PDFiDPlugin, builtin_plugins, register
from pdfid.render import PDFiD2JSON, PDFiD2String, render_json, render_text, render_xml
from pdfid.scanner import PDFiD

__all__ = [
    'PDFiD',
    'PDFiD2String',
    'PDFiD2JSON',
    'render_text',
    'render_json',
    'render_xml',
    'PDFiDResult',
    'KeywordCount',
    'DateEntry',
    'EntropyStats',
    'EOFStats',
    'KEYWORDS',
    'COLORS_PSEUDO_KEYWORD',
    'PDFiDPlugin',
    'register',
    'builtin_plugins',
    '__version__',
]
