"""Plugin framework for PDFiD.

A plugin receives a :class:`~pdfid.model.PDFiDResult` and returns a score
between 0.0 (benign) and 1.0 (suspicious).  Built-in plugins register
themselves with the :func:`register` decorator; legacy plugin *files*
(classes deriving from ``cPluginParent`` calling ``AddPlugin``) are still
loadable via :func:`load_plugin_file` through a small adapter.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Dict, List, Type

from pdfid.model import PDFiDResult

__all__ = ['PDFiDPlugin', 'register', 'builtin_plugins', 'load_plugin_file']

_registry: List[Type['PDFiDPlugin']] = []


class PDFiDPlugin(ABC):
    """Base class for scoring plugins."""

    #: Human readable name shown in reports / CSV output.
    name: str = 'plugin'
    #: When True the plugin only runs on files identified as valid PDFs.
    only_valid_pdf: bool = True

    def __init__(self, pdf: PDFiDResult) -> None:
        self.pdf = pdf

    @abstractmethod
    def score(self) -> float:
        """Return a suspicion score between 0.0 and 1.0."""
        raise NotImplementedError


def register(plugin_class: Type[PDFiDPlugin]) -> Type[PDFiDPlugin]:
    """Class decorator adding a plugin class to the registry."""
    _registry.append(plugin_class)
    return plugin_class


def builtin_plugins() -> List[Type[PDFiDPlugin]]:
    """Import built-in plugin modules and return the registry copy."""
    from pdfid.plugins import embeddedfile, name_obfuscation, triage  # noqa: F401
    return list(_registry)


def _adapt_legacy(legacy_class: type) -> Type[PDFiDPlugin]:
    """Wrap a pre-1.0 plugin class (``cPluginParent`` + ``Score()``)."""

    class _LegacyPluginAdapter(PDFiDPlugin):
        name = getattr(legacy_class, 'name', legacy_class.__name__)
        only_valid_pdf = getattr(legacy_class, 'onlyValidPDF', True)

        def score(self) -> float:
            return float(legacy_class(self.pdf).Score())  # noqa: N802 - legacy API

    return _LegacyPluginAdapter


class _LegacyPluginParent:
    """Compatibility base class injected into legacy plugin files."""

    name = 'plugin'
    onlyValidPDF = True  # noqa: N815 - legacy API


def load_plugin_file(path: str, verbose: bool = False) -> List[Type[PDFiDPlugin]]:
    """Load a plugin from a ``.py`` file (legacy ``AddPlugin`` style or new style)."""
    loaded: List[Type[PDFiDPlugin]] = []

    def add_plugin(plugin_class: type) -> None:
        if isinstance(plugin_class, type) and issubclass(plugin_class, PDFiDPlugin):
            loaded.append(plugin_class)
        else:
            loaded.append(_adapt_legacy(plugin_class))

    source = Path(path).read_text(encoding='latin-1')
    namespace: Dict[str, object] = {
        'PDFiDPlugin': PDFiDPlugin,
        'register': register,
        'cPluginParent': _LegacyPluginParent,
        'AddPlugin': add_plugin,
    }
    try:
        exec(compile(source, path, 'exec'), namespace)  # noqa: S102 - explicit user request
    except Exception as error:  # noqa: BLE001
        print(f'Error loading plugin: {path}')
        if verbose:
            raise error
        return []
    return loaded
