"""Command line interface for PDFiD.

Single-command interface (like the original tool)::

    pdfid [options] [pdf-file|zip-file|url|@file] ...

Run ``pdfid --help`` for the full option list.
"""

from __future__ import annotations

import argparse
import ast
import glob
import operator
import sys
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence

from pdfid import __version__
from pdfid.model import KeywordCount, PDFiDResult
from pdfid.plugins import builtin_plugins, load_plugin_file
from pdfid.render import PDFiD2String, make_csv_line, render_json
from pdfid.scanner import PDFiD

# ----------------------------------------------------------------------
# Safe evaluation of -S/--select expressions
# ----------------------------------------------------------------------
_BINARY_OPS: Dict[type, Callable[[Any, Any], Any]] = {
    ast.Add: operator.add, ast.Sub: operator.sub, ast.Mult: operator.mul,
    ast.Div: operator.truediv, ast.FloorDiv: operator.floordiv, ast.Mod: operator.mod,
    ast.Pow: operator.pow,
}
_COMPARE_OPS: Dict[type, Callable[[Any, Any], bool]] = {
    ast.Eq: operator.eq, ast.NotEq: operator.ne, ast.Lt: operator.lt, ast.LtE: operator.le,
    ast.Gt: operator.gt, ast.GtE: operator.ge,
    ast.In: lambda a, b: a in b, ast.NotIn: lambda a, b: a not in b,
}
_UNARY_OPS: Dict[type, Callable[[Any], Any]] = {
    ast.USub: operator.neg, ast.UAdd: operator.pos, ast.Not: operator.not_,
}
_SAFE_FUNCTIONS: Dict[str, Callable[..., Any]] = {
    'len': len, 'int': int, 'float': float, 'str': str, 'bool': bool,
}


def safe_eval(expression: str, names: Dict[str, Any]) -> Any:
    """Evaluate a select expression against a whitelist of AST nodes.

    Unlike the original ``eval()`` approach this only allows literals,
    arithmetic/comparison, boolean logic, indexing, safe builtins (``len``,
    ``int``, ...) and attribute access on the scan result types, e.g.
    ``pdf.js.count > 0 and pdf.obj.count == pdf.endobj.count``.
    """
    tree = ast.parse(expression, mode='eval')
    return _eval_node(tree.body, names)


def _eval_node(node: ast.AST, names: Dict[str, Any]) -> Any:
    if isinstance(node, ast.Constant) and isinstance(node.value, (bool, int, float, str, bytes, type(None))):
        return node.value
    if isinstance(node, ast.Name):
        if node.id in names:
            return names[node.id]
        raise ValueError(f'name {node.id!r} is not defined')
    if isinstance(node, ast.Attribute):
        value = _eval_node(node.value, names)
        if isinstance(value, (PDFiDResult, KeywordCount)) and not node.attr.startswith('_'):
            return getattr(value, node.attr)
        raise ValueError(f'attribute access not allowed: {node.attr!r}')
    if isinstance(node, ast.Subscript):
        return _eval_node(node.value, names)[_eval_node(node.slice, names)]
    if isinstance(node, ast.BinOp) and type(node.op) in _BINARY_OPS:
        return _BINARY_OPS[type(node.op)](_eval_node(node.left, names), _eval_node(node.right, names))
    if isinstance(node, ast.UnaryOp) and type(node.op) in _UNARY_OPS:
        return _UNARY_OPS[type(node.op)](_eval_node(node.operand, names))
    if isinstance(node, ast.BoolOp):
        values = (_eval_node(value, names) for value in node.values)
        return all(values) if isinstance(node.op, ast.And) else any(values)
    if isinstance(node, ast.Compare):
        left = _eval_node(node.left, names)
        for comparator, right_node in zip(node.ops, node.comparators):
            operation = _COMPARE_OPS.get(type(comparator))
            if operation is None:
                raise ValueError(f'comparison not allowed: {type(comparator).__name__}')
            right = _eval_node(right_node, names)
            if not operation(left, right):
                return False
            left = right
        return True
    if isinstance(node, (ast.Tuple, ast.List)):
        return [_eval_node(element, names) for element in node.elts]
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in _SAFE_FUNCTIONS:
        if node.keywords:
            raise ValueError('keyword arguments are not allowed')
        return _SAFE_FUNCTIONS[node.func.id](*(_eval_node(arg, names) for arg in node.args))
    raise ValueError(f'unsupported expression element: {type(node).__name__}')


# ----------------------------------------------------------------------
# Argument expansion (@file lists + glob patterns)
# ----------------------------------------------------------------------
def _read_lines(path: str) -> Optional[List[str]]:
    try:
        with open(path, 'r', encoding='latin-1') as handle:
            return [line.rstrip('\n').rstrip('\r') for line in handle]
    except OSError:
        return None


def expand_filename_arguments(filenames: Sequence[str]) -> List[str]:
    """Expand ``@file`` lists and glob patterns, keeping first-seen order."""
    arguments: List[str] = []
    for argument in filenames:
        if argument.startswith('@'):
            lines = _read_lines(argument[1:])
            if lines is None:
                raise OSError(f'Error reading {argument}')
            arguments.extend(lines)
        else:
            arguments.append(argument)

    expanded: List[str] = []
    seen = set()
    for pattern in arguments:
        for path in glob.glob(pattern):
            if path not in seen:
                seen.add(path)
                expanded.append(path)
    return expanded


# ----------------------------------------------------------------------
# Plugin loading
# ----------------------------------------------------------------------
def load_plugins(spec: str, verbose: bool = False) -> List[type]:
    """Resolve the ``-p`` argument: builtin names, 'all', or .py file paths."""
    builtins = builtin_plugins()
    normalize = lambda name: name.lower().replace('_', '').replace(' ', '')  # noqa: E731
    aliases: Dict[str, type] = {}
    for plugin in builtins:
        for key in (plugin.__name__, plugin.__name__.removesuffix('Plugin'), plugin.name):
            aliases[normalize(key)] = plugin

    classes: List[type] = []
    for token in spec.split(','):
        token = token.strip()
        if not token:
            continue
        stripped = normalize(token.removesuffix('.py'))
        if stripped == 'all':
            classes.extend(builtins)
        elif stripped in aliases:
            classes.append(aliases[stripped])
        else:
            path = token if token.endswith('.py') else f'{token}.py'
            if not Path(path).exists():
                path = token  # maybe a path without .py after all
            classes.extend(load_plugin_file(path, verbose))
    return classes


# ----------------------------------------------------------------------
# Processing
# ----------------------------------------------------------------------
class Options:
    """Namespace holding the parsed CLI options."""

    def __init__(self, **kwargs: Any) -> None:
        self.scan = False
        self.all = False
        self.extra = False
        self.force = False
        self.disarm = False
        self.plugins = ''
        self.csv = False
        self.json = False
        self.minimumscore = 0.0
        self.verbose = False
        self.select = ''
        self.output = ''
        for key, value in kwargs.items():
            setattr(self, key, value)


def _output(text: str, options: Options) -> None:
    print(text)
    log_path = 'PDFiD.log' if options.scan else None
    if options.output:
        log_path = options.output
    if log_path:
        with open(log_path, 'a', encoding='utf-8') as handle:
            handle.write(text + '\n')


def _report(result: PDFiDResult, options: Options) -> str:
    if options.json:
        return render_json(result, options.force)
    return PDFiD2String(result, options.force)


def process_file(filename: str, options: Options, plugins: List[type]) -> None:
    result = PDFiD(filename, all_names=options.all, extra_data=options.extra,
                   disarm=options.disarm, force=options.force)

    if not plugins and not options.select:
        _output(_report(result, options), options)
        return

    if options.select:
        if options.force or (not result.error_occurred and result.is_pdf):
            try:
                selected = safe_eval(options.select, {'pdf': result})
            except Exception as error:
                _output(f'Error evaluating select expression: {options.select}', options)
                if options.verbose:
                    raise error
                return
            if selected:
                _output(filename if options.csv else _report(result, options), options)
        return

    for plugin_class in plugins:
        if not plugin_class.only_valid_pdf or (not result.error_occurred and result.is_pdf):
            try:
                score = plugin_class(result).score()
            except Exception as error:  # noqa: BLE001
                _output(f'Error running plugin: {plugin_class.name}', options)
                if options.verbose:
                    raise error
                return
            if score >= options.minimumscore:
                if options.csv:
                    _output(make_csv_line((('%s', filename), ('%s', plugin_class.name), ('%.02f', score))), options)
                else:
                    _output(_report(result, options), options)
                    _output(f'{plugin_class.name} score: {score:.02f}', options)
        elif options.csv:
            if result.error_occurred:
                _output(make_csv_line((('%s', filename), ('%s', plugin_class.name), ('%s', 'Error occured'))), options)
            if not result.is_pdf:
                _output(make_csv_line((('%s', filename), ('%s', plugin_class.name), ('%s', 'Not a PDF document'))), options)
        else:
            _output(_report(result, options), options)


def scan_directory(directory: str, options: Options, plugins: List[type]) -> None:
    path = Path(directory)
    try:
        if path.is_dir():
            for entry in path.iterdir():
                scan_directory(str(entry), options, plugins)
        else:
            process_file(directory, options, plugins)
    except Exception as error:  # noqa: BLE001 - keep scanning other entries
        print(error)


def run(filenames: Sequence[str], options: Options) -> int:
    plugins = load_plugins(options.plugins, options.verbose)

    if options.csv:
        if plugins:
            _output(make_csv_line((('%s', 'Filename'), ('%s', 'Plugin-name'), ('%s', 'Score'))), options)
        elif options.select:
            _output('Filename', options)

    for filename in filenames:
        if options.scan:
            scan_directory(filename, options, plugins)
        else:
            process_file(filename, options, plugins)
    return 0


# ----------------------------------------------------------------------
# Entry point
# ----------------------------------------------------------------------
def build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog='pdfid',
        description='Tool to triage a PDF file',
        epilog=(
            'Arguments:\n'
            'pdf-file and zip-file can be a single file, several files, and/or @file\n'
            '@file: run PDFiD on each file listed in the text file specified\n'
            'wildcards are supported\n\n'
            'Source code put in the public domain by Didier Stevens, no Copyright\n'
            'Use at your own risk - https://DidierStevens.com'
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument('files', nargs='*', metavar='pdf-file|zip-file|url|@file',
                        help='files to scan (default: stdin)')
    parser.add_argument('-s', '--scan', action='store_true', help='scan the given directory')
    parser.add_argument('-a', '--all', action='store_true', help='display all the names')
    parser.add_argument('-e', '--extra', action='store_true', help='display extra data, like dates')
    parser.add_argument('-f', '--force', action='store_true', help='force the scan of the file, even without proper %%PDF header')
    parser.add_argument('-d', '--disarm', action='store_true', help='disable JavaScript and auto launch')
    parser.add_argument('-p', '--plugins', default='',
                        help="plugins to load: 'all', builtin names (triage, embeddedfile, nameobfuscation) or .py file paths, comma separated")
    parser.add_argument('-c', '--csv', action='store_true', help='output csv data when using plugins')
    parser.add_argument('-j', '--json', action='store_true', help='output JSON (PDFiD2JSON compatible)')
    parser.add_argument('-m', '--minimumscore', type=float, default=0.0, help='minimum score for plugin results output')
    parser.add_argument('-v', '--verbose', action='store_true', help='verbose (will also raise caught exceptions)')
    parser.add_argument('-S', '--select', default='', help='selection expression, e.g. "pdf.js.count > 0"')
    parser.add_argument('-o', '--output', default='', help='output to log file')
    parser.add_argument('--version', action='version', version=f'%(prog)s {__version__}')
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_argument_parser()
    args = parser.parse_args(argv)
    options = vars(args)

    files = options.pop('files') or []
    if not files:
        if options['disarm']:
            print('Option disarm not supported with stdin')
            options['disarm'] = False
        if options['scan']:
            print('Option scan not supported with stdin')
            options['scan'] = False
        filenames = ['']
    else:
        try:
            filenames = expand_filename_arguments(files)
        except OSError as error:
            print(error)
            return 1

    return run(filenames, Options(**options))


if __name__ == '__main__':
    sys.exit(main())
