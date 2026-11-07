"""EmbeddedFile plugin: flags embedded files, especially obfuscated ones."""

from __future__ import annotations

from pdfid.plugins import PDFiDPlugin, register


@register
class EmbeddedFilePlugin(PDFiDPlugin):
    name = 'EmbeddedFile plugin'

    def score(self) -> float:
        entry = self.pdf.keywords.get('/EmbeddedFile')
        if entry is None or entry.count == 0:
            return 0.0
        if entry.hexcode > 0:
            return 1.0  # hex-obfuscated /EmbeddedFile: highly suspicious
        return 0.9
