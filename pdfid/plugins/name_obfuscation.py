"""Name Obfuscation plugin: flags any hex-encoded (obfuscated) PDF name."""

from __future__ import annotations

from pdfid.plugins import PDFiDPlugin, register


@register
class NameObfuscationPlugin(PDFiDPlugin):
    name = 'Name Obfuscation plugin'

    def score(self) -> float:
        if any(entry.hexcode > 0 for entry in self.pdf.keywords.values()):
            return 1.0
        return 0.0
