"""Normalización de mensajes para agrupar "el mismo error".

Dos líneas como
    "Connection to 10.0.0.5:5432 timed out after 3000 ms (req 7f3a9c21)"
    "Connection to 10.0.0.9:5432 timed out after 2950 ms (req 0b11e4aa)"
son el mismo problema. Reemplazamos todo lo variable (IPs, números, ids, hex,
rutas temporales, fechas) por placeholders y hasheamos el resultado.
"""

from __future__ import annotations

import hashlib
import re

# El orden importa: primero lo más específico (UUID, timestamps, IPs) y al final
# los números sueltos, para no romper patrones más largos.
_RULES: list[tuple[re.Pattern[str], str]] = [
    (
        re.compile(
            r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"
        ),
        "<UUID>",
    ),
    (
        re.compile(
            r"\b\d{4}[-/]\d{2}[-/]\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?"
        ),
        "<TS>",
    ),
    (re.compile(r"\b\d{1,2}:\d{2}:\d{2}(?:\.\d+)?\b"), "<TIME>"),
    (re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b"), "<EMAIL>"),
    (re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?\b"), "<IP>"),
    # IPv6 (incluye la forma comprimida con "::"). Las horas ya se reemplazaron antes.
    (re.compile(r"(?<![\w:])(?=[0-9a-fA-F:]*:[0-9a-fA-F:]*:)[0-9a-fA-F:]{2,39}(?![\w:])"), "<IP>"),
    (re.compile(r"\b0x[0-9a-fA-F]+\b"), "<HEX>"),
    # Hex largo (hashes, ids de request). Exigimos al menos un dígito y una letra
    # para no pisar palabras comunes ni números largos (que caen en <N>).
    (re.compile(r"\b(?=[0-9a-fA-F]*\d)(?=[0-9a-fA-F]*[a-fA-F])[0-9a-fA-F]{8,}\b"), "<HEX>"),
    (re.compile(r"(?<=/)\d+(?=/|\b)"), "<N>"),
    (re.compile(r"\b(?:pid|PID)[=: ]\d+"), "pid=<N>"),
    (re.compile(r"(?<![A-Za-z])[-+]?\d+(?:\.\d+)?(?![A-Za-z])"), "<N>"),
]

_WHITESPACE = re.compile(r"\s+")


def normalize_message(message: str) -> str:
    """Devuelve la plantilla del mensaje, sin partes variables."""
    text = message.strip()
    for pattern, replacement in _RULES:
        text = pattern.sub(replacement, text)
    return _WHITESPACE.sub(" ", text)


def signature_of(message: str, category: str = "") -> str:
    """Hash corto y estable de la plantilla (incluye la categoría como namespace)."""
    template = normalize_message(message)
    digest = hashlib.sha1(f"{category}|{template}".encode(), usedforsecurity=False)
    return digest.hexdigest()[:16]
