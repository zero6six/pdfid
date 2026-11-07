"""Smoke tests for the modernized PDFiD package."""

import json
import zipfile
from io import BytesIO
from pathlib import Path

import pytest

from pdfid import PDFiD, PDFiD2JSON, PDFiD2String
from pdfid.cli import main, safe_eval
from pdfid.plugins import builtin_plugins

MINIMAL_PDF = b"""%PDF-1.4
1 0 obj
<</Type/Catalog/Pages 2 0 R/OpenAction 4 0 R>>
endobj
2 0 obj
<</Type/Pages/Kids[3 0 R]/Count 1>>
endobj
3 0 obj
<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]>>
endobj
4 0 obj
<</S/JavaScript/JS(alert(1))>>
endobj
xref
0 5
trailer
<</Size 5/Root 1 0 R>>
startxref
123
%%EOF
"""


@pytest.fixture()
def sample_pdf(tmp_path: Path) -> Path:
    path = tmp_path / 'sample.pdf'
    path.write_bytes(MINIMAL_PDF)
    return path


def test_basic_scan(sample_pdf: Path):
    result = PDFiD(str(sample_pdf))
    assert result.is_pdf is True
    assert result.error_occurred is False
    assert result.header == '%PDF-1.4'
    assert result.obj.count == 4
    assert result.endobj.count == 4
    assert result.xref.count == 1
    assert result.trailer.count == 1
    assert result.startxref.count == 1
    assert result.page.count == 1
    assert result.javascript.count == 1
    assert result.js.count == 1
    assert result.openaction.count == 1
    assert result.stream.count == 0
    assert result.encrypt.count == 0


def test_scan_bytes():
    result = PDFiD(MINIMAL_PDF)
    assert result.is_pdf is True
    assert result.obj.count == 4


def test_scan_bytesio():
    result = PDFiD(BytesIO(MINIMAL_PDF))
    assert result.is_pdf is True


def test_not_a_pdf(tmp_path: Path):
    path = tmp_path / 'text.txt'
    path.write_bytes(b'just some text, no header')
    result = PDFiD(str(path))
    assert result.is_pdf is False
    assert 'Not a PDF document' in PDFiD2String(result)


def test_force_scan(tmp_path: Path):
    path = tmp_path / 'noheader.pdf'
    path.write_bytes(b'1 0 obj\n<<>>\nendobj\n')
    result = PDFiD(str(path))
    assert result.is_pdf is False
    assert result.obj.count == 0  # early return without force
    forced = PDFiD(str(path), force=True)
    assert forced.is_pdf is False
    assert forced.obj.count == 1
    assert forced.endobj.count == 1


def test_hexcode_obfuscation(tmp_path: Path):
    content = MINIMAL_PDF.replace(b'/JavaScript', b'/J#61vaScript')
    path = tmp_path / 'obfuscated.pdf'
    path.write_bytes(content)
    result = PDFiD(str(path))
    assert result.javascript.count == 1
    assert result.javascript.hexcode == 1


def test_extra_data_dates_entropy_eof(tmp_path: Path):
    content = MINIMAL_PDF.replace(
        b'<</Size 5/Root 1 0 R>>',
        b'<</Size 5/Root 1 0 R/ModDate(D:20200101010101+01\'00)>>',
    ) + b'JUNK-AFTER-EOF'
    path = tmp_path / 'extra.pdf'
    path.write_bytes(content)
    result = PDFiD(str(path), extra_data=True)
    assert any(d.value == "D:20200101010101+01'00" and d.name == '/ModDate' for d in result.dates)
    assert result.entropy is not None
    assert result.entropy.total_count > 0
    assert result.entropy.total_entropy > 0
    assert result.eof is not None
    assert result.eof.count_eofs == 1
    assert result.eof.chars_after_last_eof == len(b'JUNK-AFTER-EOF')


def test_streams_and_entropy(tmp_path: Path):
    content = b"""%PDF-1.5
1 0 obj
<</Length 44>>
stream
0123456789abcdefghijklmnopqrstuvwxyz
endstream
endobj
%%EOF
"""
    path = tmp_path / 'stream.pdf'
    path.write_bytes(content)
    result = PDFiD(str(path), extra_data=True)
    assert result.stream.count == 1
    assert result.endstream.count == 1
    assert result.entropy.stream_count > 0
    assert result.entropy.stream_entropy > 0
    assert result.entropy.non_stream_count > 0


def test_disarm(tmp_path: Path, sample_pdf: Path, capsys):
    result = PDFiD(str(sample_pdf), disarm=True)
    disarmed = Path(result.disarmed_to)
    assert disarmed.exists()
    assert disarmed.name == 'sample.disarmed.pdf'
    content = disarmed.read_bytes()
    assert b'/jAVAsCRIPT' in content  # case-swapped = neutralized
    assert b'/oPENaCTION' in content
    assert b'/JavaScript' not in content
    assert b'/OpenAction' not in content
    # The disarmed document must remain scannable and score clean on triage
    recheck = PDFiD(str(disarmed))
    assert recheck.javascript.count == 0
    triage = [p for p in builtin_plugins() if p.name == 'Triage plugin'][0]
    assert triage(recheck).score() == 0.0


def test_colors_cve_2009_3459(tmp_path: Path):
    content = b"""%PDF-1.4
1 0 obj
<</DecodeParms<</Colors 99999999/BitsPerComponent 8>>>>>>
endobj
%%EOF
"""
    path = tmp_path / 'colors.pdf'
    path.write_bytes(content)
    result = PDFiD(str(path))
    assert result.colors_gt_2_24.count == 1


def test_plugins(tmp_path: Path, sample_pdf: Path):
    plugins = {plugin.name: plugin for plugin in builtin_plugins()}
    assert set(plugins) == {'Triage plugin', 'EmbeddedFile plugin', 'Name Obfuscation plugin'}

    result = PDFiD(str(sample_pdf))
    assert plugins['Triage plugin'](result).score() == 1.0
    assert plugins['EmbeddedFile plugin'](result).score() == 0.0
    assert plugins['Name Obfuscation plugin'](result).score() == 0.0

    obfuscated = tmp_path / 'obf.pdf'
    obfuscated.write_bytes(MINIMAL_PDF.replace(b'/JavaScript', b'/J#61vaScript'))
    result2 = PDFiD(str(obfuscated))
    assert plugins['Name Obfuscation plugin'](result2).score() == 1.0

    embedded = tmp_path / 'embedded.pdf'
    embedded.write_bytes(MINIMAL_PDF + b'5 0 obj\n<</Type/EmbeddedFile/Length 3>>\nstream\nabc\nendstream\nendobj\n')
    result3 = PDFiD(str(embedded))
    assert plugins['EmbeddedFile plugin'](result3).score() == 0.9


def test_select_expression(sample_pdf: Path):
    result = PDFiD(str(sample_pdf))
    assert safe_eval('pdf.js.count > 0', {'pdf': result}) is True
    assert safe_eval('pdf.obj.count == pdf.endobj.count', {'pdf': result}) is True
    assert safe_eval("pdf.keywords['/OpenAction'].count > 0", {'pdf': result}) is True
    assert safe_eval('pdf.isPDF and len(pdf.keywords) > 20', {'pdf': result}) is True
    with pytest.raises(ValueError):
        safe_eval('pdf.__class__', {'pdf': result})
    with pytest.raises(ValueError):
        safe_eval('__import__("os")', {'pdf': result})


def test_json_render(sample_pdf: Path):
    result = PDFiD(str(sample_pdf))
    payload = json.loads(PDFiD2JSON(result))
    data = payload[0]['pdfid']
    assert data['isPdf'] == 'True'
    assert data['header'] == '%PDF-1.4'
    keyword = {entry['name']: entry for entry in data['keywords']['keyword']}
    assert keyword['obj']['count'] == 4
    assert keyword['/JavaScript']['count'] == 1


def test_all_names(sample_pdf: Path):
    result = PDFiD(str(sample_pdf), all_names=True)
    assert '/Type' in result.keywords
    assert '/Catalog' in result.keywords
    assert result.keywords['/Type'].count == 3


def test_zip_input(tmp_path: Path):
    archive = tmp_path / 'sample.zip'
    with zipfile.ZipFile(archive, 'w') as handle:
        handle.writestr('document.pdf', MINIMAL_PDF)
    result = PDFiD(str(archive))
    assert result.is_pdf is True
    assert result.obj.count == 4


def test_cli_report(sample_pdf: Path, capsys):
    assert main([str(sample_pdf)]) == 0
    out = capsys.readouterr().out
    assert 'PDF Header: %PDF-1.4' in out
    assert '/JavaScript' in out


def test_cli_extra_and_json(sample_pdf: Path, capsys):
    assert main(['-e', '-j', str(sample_pdf)]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload[0]['pdfid']['totalEntropy'] != ''


def test_cli_select(sample_pdf: Path, capsys):
    assert main(['-S', 'pdf.js.count > 0', str(sample_pdf)]) == 0
    out = capsys.readouterr().out
    assert 'PDF Header: %PDF-1.4' in out


def test_cli_plugins_csv(sample_pdf: Path, capsys):
    assert main(['-p', 'all', '-c', '-m', '0.5', str(sample_pdf)]) == 0
    out = capsys.readouterr().out
    assert 'Filename;Plugin-name;Score' in out
    assert 'Triage plugin' in out


def test_cli_scan_directory(tmp_path: Path, capsys, sample_pdf: Path, monkeypatch):
    monkeypatch.chdir(tmp_path)  # keep PDFiD.log out of the project root
    subdir = tmp_path / 'nested'
    subdir.mkdir()
    (subdir / 'inner.pdf').write_bytes(MINIMAL_PDF)
    assert main(['-s', str(tmp_path)]) == 0
    out = capsys.readouterr().out
    assert out.count('PDF Header: %PDF-1.4') >= 2


def test_cli_disarm(sample_pdf: Path, capsys):
    assert main(['-d', str(sample_pdf)]) == 0
    disarmed = sample_pdf.parent / 'sample.disarmed.pdf'
    assert disarmed.exists()
    assert b'/jAVAsCRIPT' in disarmed.read_bytes()
