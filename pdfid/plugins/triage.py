"""Triage plugin: flags PDFs with suspicious keywords or unbalanced structure."""

from __future__ import annotations

from pdfid.model import COLORS_PSEUDO_KEYWORD
from pdfid.plugins import PDFiDPlugin, register

TRIAGE_KEYWORDS = (
    '/ObjStm', '/JS', '/JavaScript', '/AA', '/OpenAction', '/AcroForm',
    '/JBIG2Decode', '/RichMedia', '/Launch', '/EmbeddedFile', '/XFA',
    COLORS_PSEUDO_KEYWORD,
)


@register
class TriagePlugin(PDFiDPlugin):
    name = 'Triage plugin'

    def score(self) -> float:
        for keyword in TRIAGE_KEYWORDS:
            entry = self.pdf.keywords.get(keyword)
            if entry is not None and entry.count > 0:
                return 1.0
        keywords = self.pdf.keywords
        if keywords['obj'].count != keywords['endobj'].count:
            return 1.0
        if keywords['stream'].count != keywords['endstream'].count:
            return 1.0
        return 0.0
