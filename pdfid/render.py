"""Renderers turning a :class:`~pdfid.model.PDFiDResult` into the historical
output formats: human-readable text, JSON (PDFiD2JSON layout), XML and CSV.

The text and JSON layouts are kept byte-compatible with the original tool so
existing pipelines keep working.
"""

from __future__ import annotations

import json
import xml.etree.ElementTree as ET
from typing import Iterable, Tuple

from pdfid.model import PDFiDResult


def render_text(result: PDFiDResult, force: bool = False) -> str:
    """Render the classic multi-line report."""
    lines = [f'PDFiD {result.version} {result.filename}']
    if result.error_occurred:
        lines.append('***Error occured***')
        lines.append(result.error_message)
        return '\n'.join(lines) + '\n'
    if not force and not result.is_pdf:
        lines.append(' Not a PDF document')
        return '\n'.join(lines) + '\n'

    lines.append(f' PDF Header: {result.header or ""}')
    for keyword in result.iter_keywords():
        line = f' {keyword.name:<16} {keyword.count:7d}'
        if keyword.hexcode > 0:
            line += f'({keyword.hexcode})'
        lines.append(line)
    if result.eof is not None:
        lines.append(f' {"%%EOF":<16} {result.eof.count_eofs:7d}')
        lines.append(f' {"After last %%EOF":<16} {result.eof.chars_after_last_eof:7d}')
    for date in result.dates:
        lines.append(f' {date.value:<23} {date.name}')
    if result.entropy is not None:
        entropy = result.entropy
        lines.append(f' Total entropy:           {entropy.total_entropy:.6f} ({entropy.total_count:10d} bytes)')
        lines.append(f' Entropy inside streams:  {entropy.stream_entropy:.6f} ({entropy.stream_count:10d} bytes)')
        lines.append(f' Entropy outside streams: {entropy.non_stream_entropy:.6f} ({entropy.non_stream_count:10d} bytes)')
    return '\n'.join(lines) + '\n'


def render_json(result: PDFiDResult, force: bool = False) -> str:
    """Render JSON using the historical PDFiD2JSON structure.

    Keys and string-encoded booleans ('True'/'False') match the original
    output consumed by e.g. MISP/peepdf integrations.
    """
    entropy = result.entropy
    eof = result.eof

    data = {
        'countEof': str(eof.count_eofs) if eof is not None else '',
        'countChatAfterLastEof': str(eof.chars_after_last_eof) if eof is not None else '',
        'totalEntropy': f'{entropy.total_entropy:.6f}' if entropy is not None else '',
        'streamEntropy': f'{entropy.stream_entropy:.6f}' if entropy is not None else '',
        'nonStreamEntropy': f'{entropy.non_stream_entropy:.6f}' if entropy is not None else '',
        'errorOccured': 'True' if result.error_occurred else 'False',
        'errorMessage': result.error_message,
        'filename': result.filename,
        'header': result.header if result.header is not None else '',
        'isPdf': 'True' if result.is_pdf else 'False',
        'version': result.version,
        'entropy': '',
        'keywords': {
            'keyword': [
                {'count': keyword.count, 'hexcodecount': keyword.hexcode, 'name': keyword.name}
                for keyword in result.iter_keywords()
            ],
        },
        'dates': {
            'date': [{'name': date.name, 'value': date.value} for date in result.dates],
        },
    }
    return json.dumps([{'pdfid': data}])


def render_xml(result: PDFiDResult) -> str:
    """Render XML matching the historical minidom layout."""
    root = ET.Element('PDFiD')
    root.set('Version', result.version)
    root.set('Filename', result.filename)
    root.set('ErrorOccured', 'True' if result.error_occurred else 'False')
    root.set('ErrorMessage', result.error_message)
    if not result.error_occurred:
        root.set('IsPDF', 'True' if result.is_pdf else 'False')
        if result.header is not None:
            root.set('Header', repr(result.header[0:10]).strip("'"))

    entropy = result.entropy
    eof = result.eof
    attributes = (
        ('TotalEntropy', f'{entropy.total_entropy:.6f}' if entropy else ''),
        ('TotalCount', str(entropy.total_count) if entropy else ''),
        ('StreamEntropy', f'{entropy.stream_entropy:.6f}' if entropy else ''),
        ('StreamCount', str(entropy.stream_count) if entropy else ''),
        ('NonStreamEntropy', f'{entropy.non_stream_entropy:.6f}' if entropy else ''),
        ('NonStreamCount', str(entropy.non_stream_count) if entropy else ''),
        ('CountEOF', str(eof.count_eofs) if eof else ''),
        ('CountCharsAfterLastEOF', str(eof.chars_after_last_eof) if eof else ''),
    )
    for name, value in attributes:
        root.set(name, value)

    keywords_element = ET.SubElement(root, 'Keywords')
    for keyword in result.iter_keywords():
        element = ET.SubElement(keywords_element, 'Keyword')
        element.set('Name', keyword.name)
        element.set('Count', str(keyword.count))
        element.set('HexcodeCount', str(keyword.hexcode))

    dates_element = ET.SubElement(root, 'Dates')
    for date in result.dates:
        element = ET.SubElement(dates_element, 'Date')
        element.set('Value', date.value)
        element.set('Name', date.name)

    ET.indent(root)
    return ET.tostring(root, encoding='unicode')


def make_csv_line(fields: Iterable[Tuple[str, object]], separator: str = ';', quote: str = '"') -> str:
    """Format one CSV line from ``(format_spec, value)`` pairs, quoting when needed."""
    format_string = separator.join(spec for spec, _ in fields)
    values = []
    for _, value in fields:
        if isinstance(value, str) and separator in value:
            value = f'{quote}{value}{quote}'
        values.append(value)
    return format_string % tuple(values)


# ----------------------------------------------------------------------
# Historical API names
# ----------------------------------------------------------------------
def PDFiD2String(result: PDFiDResult, force: bool = False) -> str:  # noqa: N802 - legacy API
    return render_text(result, force)


def PDFiD2JSON(result: PDFiDResult, force: bool = False) -> str:  # noqa: N802 - legacy API
    return render_json(result, force)
