"""PKG-1 / PKG-2: "install with X" in the README means X installs from that registry.

Reads README.md, llms.txt and docs/*.md for pip / pipx / uv / uvx / npm / npx / pnpm / yarn /
cargo install lines, and asks the registry whether each named package exists (PyPI JSON API,
npm registry, crates.io). With --deep (CI), a PyPI package is also fetched with
`pip download --no-deps`, which proves an installable artifact exists for this platform.
A package the README says is not published yet ("not yet published", "not on PyPI") is exempt.
No network is cannot-tell, never a pass. Tony's review, 2026-10-22: an npm 404 and a package
advertised but not on PyPI.
"""
from __future__ import annotations

import json
import re
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request

from ..core import BLOCK, Repo, Result

CMD = re.compile(r"(?m)(?:^|[`$>\s])(?P<tool>pipx install|pip3? install|python3? -m pip install|uv pip install|uv add|uv tool install|uvx"
                 r"|npm (?:install|i|add)|npx|pnpm (?:add|install|i)|pnpm dlx|yarn (?:global )?add|bunx|bun add|cargo install)"
                 r"(?P<args>[^\n`|;&]*)")
UNPUBLISHED = re.compile(r"(?i)(not (yet )?(published|released|on (pypi|npm|crates\.io))|unpublished|not available on (pypi|npm)"
                         r"|install from (source|a clone)|until (it is|it's) published)")
PLANNED = re.compile(r"(?i)\b(planned|proposed|roadmap|future|not yet (built|shipped|available)|coming soon|mvp\+\d*|"
                     r"when (the )?\w+ lands)\b")
# README and llms.txt, plus user-facing docs; design notes under docs/ describe things not built yet
USER_DOC = re.compile(r"(?i)^docs/([^/]*/)?(index|readme|install(ation|ing)?|quick-?start|getting[-_]started|usage|setup)[^/]*\.mdx?$")
REGISTRY = {"pip": "pypi", "pip3": "pypi", "python": "pypi", "python3": "pypi", "uv": "pypi", "uvx": "pypi", "pipx": "pypi",
            "npm": "npm", "npx": "npm", "pnpm": "npm", "yarn": "npm", "bunx": "npm", "bun": "npm", "cargo": "crates"}
FLAGS_WITH_ARG = {"-r", "--requirement", "-c", "--constraint", "-e", "--editable", "-i", "--index-url", "--extra-index-url",
                  "-f", "--find-links", "--prefix", "--target", "-t", "--python", "--registry", "--git", "--path", "--branch",
                  "--tag", "--rev", "--root", "--version", "--from", "-p", "--package", "--with"}
SAFE_NAME = re.compile(r"^(@[a-z0-9][\w.-]*/)?[A-Za-z0-9][\w.-]*$")


def parse_packages(args: str) -> list[str]:
    out, skip = [], False
    toks = args.replace('"', " \" ").replace("'", " ' ").split()
    toks = [t for t in toks if t not in ('"', "'")]
    for i, tok in enumerate(toks):
        if skip:
            skip = False
            continue
        nxt = toks[i + 1] if i + 1 < len(toks) else ""
        if nxt == "@" or re.match(r"^[\w.-]+@(git\+|https?:|file:)", tok):
            skip = nxt == "@"
            continue  # PEP 508 direct reference ("name @ git+https://..."): installs from a URL, not the registry
        if tok in FLAGS_WITH_ARG:
            skip = True
            continue
        if tok.startswith("-") or tok.startswith((".", "/", "~", "git+", "http", "file:", "$", "<", "{", "\\")):
            continue
        if "=" in tok and not re.search(r"[<>=!~]=", tok):
            continue
        name = re.split(r"\[|==|>=|<=|~=|!=|>|<|@(?=\d|latest|next|\^|~)", tok, maxsplit=1)[0].strip("'\"`,")
        if tok.startswith("@") and "@" in tok[1:]:
            name = "@" + tok[1:].split("@", 1)[0]
        if name and SAFE_NAME.match(name) and name.lower() not in ("install", "add", "global", "and", "or", "the", "then"):
            out.append(name)
    return out


def lookup(registry: str, name: str) -> int:
    """HTTP status from the registry; raises OSError when the registry cannot be reached."""
    url = {"pypi": f"https://pypi.org/pypi/{name}/json",
           "npm": f"https://registry.npmjs.org/{name.replace('/', '%2F')}",
           "crates": f"https://crates.io/api/v1/crates/{name}"}[registry]
    req = urllib.request.Request(url, headers={"User-Agent": "saluca-merge-gate (github.com/salucallc/ci-shared)",
                                               "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:  # nosec B310  (fixed https host)
            return resp.status
    except urllib.error.HTTPError as e:
        return e.code


def deep_pip(name: str) -> tuple[bool, str]:
    with tempfile.TemporaryDirectory() as td:
        out = subprocess.run([sys.executable, "-m", "pip", "download", "--no-deps", "--quiet", "-d", td, name],
                             capture_output=True, text=True, timeout=300)
        return out.returncode == 0, out.stderr.strip()[-300:]


def claims_in(repo: Repo) -> list[tuple[str, int, str, str, bool]]:
    """(file, line, registry, package, exempt) for every install instruction."""
    docs = [f for f in repo.tracked() if f in ("README.md", "llms.txt") or USER_DOC.match(f)]
    found = []
    for rel in docs:
        text = repo.text(rel) or ""
        lines = text.splitlines()
        heads = [i for i, l in enumerate(lines) if re.match(r"^#{1,6}\s", l)]
        # Only instructions a reader would paste: fenced code blocks and inline code spans.
        regions = [(m.start(), m.end()) for m in re.finditer(r"```[\s\S]*?```|`[^`\n]+`", text)]
        for m in CMD.finditer(text):
            if not any(a <= m.start("tool") < b for a, b in regions):
                continue
            tool = m.group("tool").split()[0]
            if m.group("tool").startswith(("python", "uv pip")):
                tool = "pip"
            reg = REGISTRY.get(tool)
            if not reg:
                continue
            ln = text.count("\n", 0, m.start()) + 1
            # the exemption holds for the whole section the instruction sits in (heading to heading)
            start = max([h for h in heads if h < ln] or [0])
            end = min([h for h in heads if h >= ln] or [len(lines)])
            section = " ".join(lines[start:end])
            exempt = bool(UNPUBLISHED.search(section) or PLANNED.search(section))
            for pkg in parse_packages(m.group("args")):
                found.append((rel, ln, reg, pkg, exempt))
    return found


def run(repo: Repo, opts) -> Result:
    r = Result("packaging", "Install instructions resolve: packages named in README/docs exist on their registry")
    claims = claims_in(repo)
    if not claims:
        return r.na("no registry install instruction in README.md, llms.txt or docs/")
    if getattr(opts, "offline", False):
        return r.cannot(f"{len(claims)} install instruction(s) to verify and --offline was given")
    cache: dict[tuple[str, str], int] = {}
    unreachable = []
    for rel, ln, reg, pkg, exempt in claims:
        if exempt:
            r.notes.append(f"{rel}:{ln}: {reg}:{pkg} exempt (the README says it is not published yet)")
            continue
        k = (reg, pkg.lower())
        if k not in cache:
            try:
                cache[k] = lookup(reg, pkg)
            except OSError as e:
                unreachable.append(f"{reg}:{pkg} ({e})")
                cache[k] = -1
        code = cache[k]
        if code == 404:
            r.add(BLOCK, f"PKG-1: README says install {pkg!r} from {reg}, and {reg} has no such package (404). Publish it, "
                  "or say 'not yet published' and give the from-source install", rel, ln, key=f"{reg}|{pkg}")
        elif code not in (200, -1):
            unreachable.append(f"{reg}:{pkg} (HTTP {code})")
        elif code == 200 and reg == "pypi" and getattr(opts, "deep", False):
            ok, err = deep_pip(pkg)
            if not ok:
                r.add(BLOCK, f"PKG-2: {pkg!r} is on PyPI but `pip download --no-deps` fails: {err}", rel, ln,
                      key=f"deep|{pkg}")
    if unreachable:
        r.cannot("registry unreachable for: " + "; ".join(sorted(set(unreachable))[:10]))
    r.notes.append(f"{len(cache)} distinct package(s) checked")
    return r
