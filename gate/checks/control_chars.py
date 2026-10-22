r"""TST-4: control characters a mangled backslash escape leaves behind (estate rule, 2026-08-14).

A Windows path in a non-raw string loses one segment silently: "C:\tools" holds a TAB, "\b" is
0x08, "\a" 0x07, "\f" 0x0C, "\v" 0x0B. Python warns on the harmless escapes and is silent on
these. Ported from the Naitsirc tools/check_control_chars.py (the stricter estate copy: an
undecodable source file is cannot-tell, not clean). Differences: a TAB after text is reported in
Python and JS/TS sources only (where the escape bug lives), and TAB indentation is a style
question this gate does not ask.
"""
from __future__ import annotations

from pathlib import Path

from ..core import BLOCK, WARN, Repo, Result

NAMED = {0x07: ("BEL", r"\a"), 0x08: ("BS", r"\b"), 0x0B: ("VT", r"\v"), 0x0C: ("FF", r"\f"), 0x00: ("NUL", r"\0")}
INVISIBLE = (set(range(0x200B, 0x2010)) | set(range(0x202A, 0x202F)) | set(range(0x2060, 0x2065))
             | set(range(0x2066, 0x206A)) | {0xFEFF, 0x00AD})
EXAMPLE = "'C:" + "\\temp'"  # assembled, so the paths check does not flag the message itself
TAB_AFTER_TEXT = {".py", ".pyi", ".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".mts", ".cts"}
STRICT_TEXT = {".py", ".pyi", ".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".md", ".toml", ".yaml", ".yml",
               ".json", ".sh", ".txt", ".cfg", ".ini"}


def scan_bytes(rel: str, data: bytes):
    """Yield (severity, line, col, message). A decode failure in a strict-text file is yielded as
    ('cannot', ...)."""
    suffix = Path(rel).suffix.lower()
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        if suffix in STRICT_TEXT:
            yield "cannot", 0, 0, "not valid UTF-8"
        return
    tab_rule = suffix in TAB_AFTER_TEXT
    for n, line in enumerate(text.split("\n"), 1):
        body = line[:-1] if line.endswith("\r") else line
        for col, ch in enumerate(body, 1):
            c = ord(ch)
            if c == 0x09:
                if tab_rule and body[: col - 1].strip():
                    yield BLOCK, n, col, "TAB after text: a Windows path like " + EXAMPLE + " in a non-raw string?"
            elif c == 0xFEFF and n == 1 and col == 1:
                yield WARN, n, col, "byte-order mark at file start; save as UTF-8 without BOM"
            elif c in INVISIBLE:
                yield BLOCK, n, col, f"invisible or bidi character U+{c:04X}; write it as an escape"
            elif c == 0x0D:
                yield BLOCK, n, col, "bare CR (0x0D) inside a line"
            elif c < 0x20 or c == 0x7F:
                name, esc = NAMED.get(c, (f"0x{c:02X}", "an escape"))
                yield BLOCK, n, col, f"{name} (0x{c:02X}); almost certainly a mangled {esc}"


def run(repo: Repo, opts) -> Result:
    r = Result("control-chars", "Control characters from mangled escapes (Windows paths in non-raw strings)")
    files = opts.files if getattr(opts, "files", None) else repo.tracked()
    unsure = []
    for rel in files:
        p = repo.root / rel
        if not p.is_file() or Path(rel).suffix.lower() in {".png", ".jpg", ".pdf", ".zip", ".ico", ".woff2"}:
            continue
        try:
            data = p.read_bytes()
        except OSError:
            unsure.append(rel)
            continue
        if b"\0" in data[:8192] and Path(rel).suffix.lower() not in STRICT_TEXT:
            continue  # binary
        for sev, n, col, msg in scan_bytes(rel, data):
            if sev == "cannot":
                unsure.append(rel)
                continue
            r.add(sev, f"TST-4: {msg}", rel, n, key=f"{rel}|{msg}|{n}:{col}")
    if unsure:
        r.cannot(f"cannot tell for {len(unsure)} file(s) that are not valid UTF-8 or unreadable: {', '.join(unsure[:10])}")
    return r
