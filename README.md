# pdfid

A modernized, pure-Python 3 (≥ 3.9) rewrite of Didier Stevens'
[PDFiD](https://blog.didierstevens.com/programs/pdf-tools/) triage tool,
originally packaged by Raphaël Vinot.

PDFiD is **not** a PDF parser — on purpose. It scans a file for certain PDF
keywords, letting you quickly identify documents that contain (for example)
JavaScript or execute an action when opened, while handling hex-encoded name
obfuscation (`/J#61vaScript`). Use it first to triage, then analyze the
suspicious ones with a real parser.

Zero third-party dependencies: standard library only.

## Usage without installing

The repository uses the sqlmap/dirsearch layout: a thin entry script next
to the package, no installation needed:

```bash
python pdfid.py [options] file.pdf      # run directly, nothing to install
cat file.pdf | python pdfid.py          # read from stdin
python pdfid.py -s /some/dir            # recursive scan
```

Copy the whole folder (or just `pdfid.py` + `pdfid/`) anywhere - as long as
they stay side by side, it runs on any Python ≥ 3.9.

## Optional: install as a package

```bash
pip install .            # from a checkout
pip install ".[test]"    # with the test extra
```

Installing provides the `pdfid` console command and makes `import pdfid`
available from anywhere; tests: `python -m pytest`.

## CLI usage

```
usage: pdfid [-h] [-s] [-a] [-e] [-f] [-d] [-p PLUGINS] [-c] [-j]
             [-m MINIMUMSCORE] [-v] [-S SELECT] [-o OUTPUT]
             [pdf-file|zip-file|url|@file ...]
```

| Option | Description |
|---|---|
| `-s`, `--scan` | recursively scan a directory |
| `-a`, `--all` | display all names, not just the known keywords |
| `-e`, `--extra` | display extra data: dates, entropy, `%%EOF` statistics |
| `-f`, `--force` | scan even without a proper `%PDF` header |
| `-d`, `--disarm` | write a `.disarmed.pdf` copy with dangerous names case-swapped |
| `-p`, `--plugins` | `all`, a builtin name (`triage`, `embeddedfile`, `nameobfuscation`), or `.py` file paths |
| `-c`, `--csv` | CSV output when using plugins |
| `-j`, `--json` | JSON output (PDFiD2JSON-compatible layout) |
| `-m`, `--minimumscore` | minimum score for plugin results |
| `-S`, `--select` | selection expression, safely evaluated (e.g. `pdf.js.count > 0`) |
| `-o`, `--output` | also append output to a log file |
| `-v`, `--verbose` | verbose (re-raises caught exceptions) |

Inputs can be files, URLs, `.zip` archives (first entry, password
`infected`), `@file` lists, or glob patterns; with no argument PDFiD reads
from stdin.

```console
$ pdfid -e sample.pdf
PDFiD 1.0.0 sample.pdf
 PDF Header: %PDF-1.4
 obj                        4
 endobj                     4
 ...
 /JavaScript                1
 /OpenAction                1
 ...
```

A number between parentheses after a counter is the number of *obfuscated*
occurrences, e.g. `/JBIG2Decode 1(1)` means the name was found hex-encoded
(`/JBIG#32Decode`).

## Python API

```python
from pdfid import PDFiD

result = PDFiD('sample.pdf', extra_data=True)
result.is_pdf                      # True
result.javascript.count            # 1
result.openaction.hexcode          # 0
result.eof.chars_after_last_eof    # data appended after %%EOF
PDFiD('x.pdf', disarm=True).disarmed_to
```

Historical names `PDFiD2String(result)` / `PDFiD2JSON(result)` are kept for
compatibility; the old camelCase keyword arguments (`allNames`, `extraData`)
are still accepted. Data is carried by dataclasses
(`PDFiDResult`, `KeywordCount`, `DateEntry`, `EntropyStats`, `EOFStats`)
instead of an XML DOM document.

### Writing plugins

```python
from pdfid.plugins import PDFiDPlugin, register

@register
class MyPlugin(PDFiDPlugin):
    name = 'My plugin'
    only_valid_pdf = True

    def score(self) -> float:
        return 1.0 if self.pdf.launch.count > 0 else 0.0
```

Legacy plugin files (`class cPDFiDTriage(cPluginParent)` + `AddPlugin(...)`)
still load through `-p path/to/plugin.py` via a compatibility adapter.

## Changes vs. the original 0.2.1

* Python ≥ 3.9, no Python 2 support code, type hints throughout.
* `pyproject.toml` (PEP 621) + `src/` layout + `pdfid` entry point; `optparse` → `argparse`.
* XML DOM no longer used as a data container — dataclasses instead.
* **Bug fixes**:
  * `/Colors > 2^24` (CVE-2009-3459) check now compares against `2**24`; the
    original used `2^24` (XOR = 26), flagging nearly everything.
  * Non-stream entropy was always `0.000000` on Python 3 (a lazy `map`
    consumed twice); now computed correctly.
  * Reading from stdin now uses the binary buffer; several rare crash paths
    (short `%PDF` header, EOF inside `#xx` sequences) are handled.
* `-S/--select` expressions are evaluated through an AST whitelist instead of
  bare `eval()`.
* Disarm notices go to stderr, keeping stdout reports clean.
* New `-j/--json` output option; `-p` accepts builtin plugin names and `all`.
* Smoke-test suite (`pytest`).

## Credits & license

Original tool by Didier Stevens (https://DidierStevens.com), put in the
public domain. Modernization by Raphaël Vinot / contributors. Use at your
own risk.
