#!/usr/bin/env python3
"""PDFiD entry point.

Run directly without installing:

    python pdfid.py [options] [pdf-file|zip-file|url|@file] ...

The implementation lives in the ``pdfid`` package next to this file;
Python adds this script's directory to ``sys.path``, so no installation
is required (same layout as sqlmap/dirsearch). Optionally install the
package with ``pip install .`` to get the ``pdfid`` console command.
"""

import sys

from pdfid.cli import main

if __name__ == '__main__':
    sys.exit(main())
