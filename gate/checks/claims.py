"""CLM-1..CLM-7: every capability claim maps to code that exists, is mounted, and is tested.

CLAIMS.md at the repo root holds one markdown table:

| id | claim | source | status | code | wired | test | note |
|---|---|---|---|---|---|---|---|
| C1 | detects truncation of the chain | README.md | shipped | src/chain.py::verify | src/cli.py: cmd_verify | tests/test_chain.py::test_truncation | |
| C2 | forgets memories after 30 days | README.md | planned | | | | |
| C3 | does not read the message text | README.md | withdrawn | | | | 2026-10-22: it does; see README Corrections |

- claim:  the sentence fragment, quoted from the source doc (the check finds it there, so the
          table and the doc cannot drift apart silently).
- source: the file(s) the claim appears in, comma-separated.
- status: shipped | planned | withdrawn | changed.
- code:   path::Symbol[::member], path:LINE, separated by ';'. Must exist and not be a stub.
- wired:  where it is mounted or called from ("path: literal text" that must occur in that
          file), or "n/a: <reason>" for a library function with no mount point.
- test:   path::test_name (pytest node id style; JS: path::"test title"). Must exist and not
          be skipped or xfailed.
- note:   for withdrawn or changed: a YYYY-MM-DD date and a correction note in the README's
          Corrections section (or CORRECTIONS.md / CHANGELOG.md) naming the id or the date.

CLM-6 and CLM-7 are warnings: capability-like sentences in public prose that no claim row
covers, and ALL-CAPS named concepts (Tony's "NHE") that appear in docs and in no code.
"""
from __future__ import annotations

import ast
import re
from pathlib import PurePosixPath

from ..core import BLOCK, SOURCE_SUFFIXES, WARN, Repo, Result, is_test_path
from .security import code_view

STATUSES = {"shipped", "planned", "withdrawn", "changed"}
PLANNED_WORDS = re.compile(r"(?i)\b(planned|not yet|roadmap|coming soon|future|todo|experimental|in progress|"
                           r"proposed|work in progress|wip|not implemented|unreleased)\b")
DATE = re.compile(r"\b20\d\d-[01]\d-[0-3]\d\b")
TRIGGERS = re.compile(
    r"(?i)\b(hash[- ]chain(ed)?|tamper[- ](evident|proof|resistant)|immutable|append[- ]only|cryptographically|"
    r"verif(y|ies|iable)|detects?|guarantee[sd]?|prevents?|zero[- ]trust|end[- ]to[- ]end|encrypt(s|ed|ion)?|"
    r"never (reads?|stores?|sends?|logs?|sees?)|(does not|doesn't|do not|don't|cannot) (read|store|send|log|see)|"
    r"without (reading|storing|sending)|forget(s|ting)?|privacy[- ]preserving|secure by default|"
    r"production[- ]ready|on[- ]?prem(ise)?s?|air[- ]gapped|local[- ]only|attest(s|ation)|audit (trail|log|chain)|"
    r"redact(s|ion)|hipaa|soc ?2|gdpr|compliant|certified)\b")
PUBLIC_PROSE = re.compile(r"(?i)^(README[^/]*|llms\.txt|docs/.+\.(md|mdx|rst)|[^/]*statement[^/]*\.md|marketing/.+\.(md|mdx|html|txt)|"
                          r"site/.+\.(md|mdx))$")
STOP = set("""API APIS CLI URL URLS URI HTTP HTTPS JSON JSONL YAML TOML CSV TSV PDF PNG JPG SVG GIF HTML CSS JS TS SQL DB OS UI UX
AI ML LLM LLMS GPU GPUS CPU RAM SSD MIT BSD GPL AGPL LGPL MPL CC BY SA NC ND CC0 PR PRS CI CD ID IDS IO README TODO FAQ MCP SDK
IDE DOI ORCID SHA SHA1 MD5 HMAC JWT TLS SSL SSH DNS IP TCP UDP REST RPC AWS GCP GCS S3 EC2 VM VMS K8S US UK EU USA OK NOT AND
OR THE NO MUST SHOULD MAY IMPORTANT NOTE WARNING TL DR PII PHI RAG NLP GPT RFC ISO UTC PT PST PDT ETA E2E V1 V2 V3 V4 CLAIMS
AGENTS LICENSE NOTICE CHANGELOG SPDX CFF NPM PYPI GH II III IV VI VII VIII IX XI XII OSS FOSS EOF UTF UTF8 ASCII AM PM
FIXME XXX HACK WIP TBD N A B C D E F G H X Y Z PS OAUTH SSO MFA TOTP RBAC ACL DDOS XSS CSRF SSRF CVE CVSS OWASP SAST DAST SBOM
CPU USB HDMI BLE LED GPIO PWM I2C SPI UART CAD STL CNC FDM SLA PLA PETG ABS TPU NAS SAN LAN WAN VPN WIFI MAC PC MB GB TB KB MS
S MS2 QA QPS RPS SLO SLI SLA KPI ROI MVP POC DIY TOS EULA DMCA FIPS NIST HIPAA SOC GDPR CCPA CPRA RFC2119 BCP DOCX PPTX XLSX
CLI2 DAG ETL ELT OLAP OLTP CRUD ORM SSE WS WSS ENV DEV PROD QA STG LF CR CRLF EOL THIS THAT THESE THOSE ALL ANY ONLY
NEVER ALWAYS NONE NEW OLD YES WHY HOW WHAT WHEN WHERE WHO IS IT IN ON AT TO OF IF BE DO SO UP US WE AS AN AM GO MY
ARE WAS NOW ONE TWO USE SEE NOTES STOP DONE FAIL PASS RED GREEN WARN INFO DEBUG ERROR TRUE FALSE NULL NAN TBA ASAP
FYI IMO TIL RTFM WTF LGTM NB ET AL IE EG VS ETC MAX MIN AVG SUM KEY KEYS RAW API2 APP APPS WEB DEMO BETA ALPHA RC
GA LTS EOL FREE PAID PRO MD RST TXT LOG LOGS BIN LIB SRC DOCS TEST TESTS CORS DOM JSX TSX NODE NPX PNPM UV PIP""".split())


def norm(s: str) -> str:
    s = s.replace("\u2019", "'").replace("\u201c", '"').replace("\u201d", '"')
    s = re.sub(r"[`*_>]|\[([^\]]*)\]\([^)]*\)", lambda m: m.group(1) or "", s)
    return re.sub(r"\s+", " ", s).strip().lower()


def parse_table(text: str) -> tuple[list[dict], list[str]]:
    rows, errors, header = [], [], None
    for n, line in enumerate(text.splitlines(), 1):
        s = line.strip()
        if not s.startswith("|"):
            if header and rows:
                break
            continue
        cells = [c.strip() for c in re.split(r"(?<!\\)\|", s.strip("|"))]
        if header is None:
            header = [c.lower() for c in cells]
            need = {"id", "claim", "source", "status", "code", "wired", "test", "note"}
            if not need <= set(header):
                errors.append(f"CLAIMS.md:{n}: header must have columns {sorted(need)}; has {header}")
                return [], errors
            continue
        if re.fullmatch(r"[\s:|-]+", s):
            continue
        row = dict(zip(header, cells + [""] * (len(header) - len(cells))))
        row["_line"] = n
        rows.append(row)
    if header is None:
        errors.append("CLAIMS.md has no table")
    return rows, errors


def split_refs(cell: str) -> list[str]:
    return [p.strip().strip("`") for p in re.split(r";|<br\s*/?>", cell) if p.strip().strip("`")]


# ------------------------------------------------------------------ symbol resolution

def _py_find(tree: ast.AST, names: list[str]):
    node = tree
    for name in names:
        found = None
        for child in getattr(node, "body", []):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and child.name == name:
                found = child
                break
            if isinstance(child, (ast.Assign, ast.AnnAssign)):
                targets = child.targets if isinstance(child, ast.Assign) else [child.target]
                if any(isinstance(t, ast.Name) and t.id == name for t in targets):
                    found = child
                    break
        if found is None:
            return None
        node = found
    return node


def _is_stub(fn: ast.AST) -> bool:
    body = list(getattr(fn, "body", []))
    if body and isinstance(body[0], ast.Expr) and isinstance(getattr(body[0], "value", None), ast.Constant) \
            and isinstance(body[0].value.value, str):
        body = body[1:]
    if not body:
        return True
    for st in body:
        if isinstance(st, ast.Pass):
            continue
        if isinstance(st, ast.Expr) and isinstance(st.value, ast.Constant) and st.value.value is Ellipsis:
            continue
        if isinstance(st, ast.Raise) and st.exc is not None:
            exc = st.exc.func if isinstance(st.exc, ast.Call) else st.exc
            if isinstance(exc, ast.Name) and exc.id == "NotImplementedError":
                continue
        return False
    return True


def _skipped(fn: ast.AST) -> bool:
    for d in getattr(fn, "decorator_list", []):
        src = ast.unparse(d)
        if re.search(r"\b(xfail|skip|skipif|skipIf|skipUnless|expectedFailure)\b", src):
            return True
    return False


def resolve(repo: Repo, ref: str, want_test: bool = False) -> tuple[str, str]:
    """Return (severity-or-'', message). '' means resolved."""
    m = re.match(r"^(?P<path>[^:]+?)(?:::(?P<sym>.+)|:(?P<line>\d+))?$", ref)
    if not m:
        return BLOCK, f"unreadable reference {ref!r}"
    path, sym, line = m.group("path").strip(), m.group("sym"), m.group("line")
    if not repo.exists(path):
        return BLOCK, f"{path} does not exist"
    text = repo.text(path) or ""
    if line:
        if int(line) > len(text.splitlines()):
            return BLOCK, f"{path} has no line {line}"
        return (BLOCK, f"{ref} must name a test function, not a line") if want_test else ("", "")
    if not sym:
        return (BLOCK, f"{ref} must name the test (path::test_name)") if want_test else \
            (WARN, f"{ref} names a file only; name the symbol (path::name) so the check can see it")
    names = [s.strip().strip('"\'') for s in sym.split("::")]
    if path.endswith(".py"):
        try:
            tree = ast.parse(text)
        except SyntaxError as e:
            return BLOCK, f"{path} does not parse: {e.msg}"
        node = _py_find(tree, names)
        if node is None:
            return BLOCK, f"{path} has no {'::'.join(names)}"
        if want_test and _skipped(node):
            return BLOCK, f"{ref} is skipped or xfailed, so it proves nothing"
        if not want_test and isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if _is_stub(node):
                return BLOCK, f"{ref} is a stub (pass, ..., or raise NotImplementedError)"
            seg = ast.get_source_segment(text, node) or ""
            if re.search(r"(?i)\bTODO\b|not implemented", code_view(path, seg)):
                return WARN, f"{ref} contains TODO or 'not implemented'; check the claim is still true"
        return "", ""
    name = names[-1]
    if want_test:
        if re.search(r"\b(it|test)\s*\(\s*(['\"`])" + re.escape(name) + r"\2", text):
            return "", ""
        if re.search(r"\b(it|test|describe)\.(skip|todo|failing)\s*\(\s*(['\"`])" + re.escape(name), text):
            return BLOCK, f"{ref} is skipped, so it proves nothing"
        if re.search(r"(?m)^\s*func\s+" + re.escape(name) + r"\s*\(", text):
            return "", ""
        return BLOCK, f"{path} has no test titled {name!r}"
    pat = (r"(?m)(\b(function|class|const|let|var|def|fn|func|interface|type|struct|enum|impl)\s+\*?" + re.escape(name)
           + r"\b|\b" + re.escape(name) + r"\s*[:=]\s*(async\s+)?(function|\(|[A-Za-z_]\w*\s*=>)|^\s*(public |private |static |async )*"
           + re.escape(name) + r"\s*\([^)]*\)\s*\{)")
    if not re.search(pat, text):
        return BLOCK, f"{path} defines no {name}"
    return "", ""


def resolve_wired(repo: Repo, cell: str) -> tuple[str, str]:
    c = cell.strip()
    if re.match(r"(?i)^n/?a\s*:\s*\S.{4,}", c):
        return "", ""
    if not c:
        return BLOCK, "wired is empty: say where it is mounted ('path: literal') or 'n/a: <reason>'"
    for part in split_refs(c):
        path, sep, lit = part.partition(":")
        if not sep or not lit.strip():
            return BLOCK, f"wired {part!r} must be 'path: literal text that appears in that file'"
        if not repo.exists(path.strip()):
            return BLOCK, f"wired: {path.strip()} does not exist"
        if lit.strip() not in (repo.text(path.strip()) or ""):
            return BLOCK, f"wired: {path.strip()} does not contain {lit.strip()!r} (not mounted?)"
    return "", ""


def correction_sections(text: str) -> list[str]:
    """The text of every heading section whose title says Correction(s) or Errata."""
    lines, out, i = text.splitlines(), [], 0
    while i < len(lines):
        m = re.match(r"^(#+)\s+(.*)$", lines[i])
        if m and re.search(r"(?i)correction|errat", m.group(2)):
            level, j = len(m.group(1)), i + 1
            while j < len(lines):
                m2 = re.match(r"^(#+)\s", lines[j])
                if m2 and len(m2.group(1)) <= level:
                    break
                j += 1
            out.append("\n".join(lines[i:j]))
            i = j
            continue
        i += 1
    return out


def corrections_text(repo: Repo) -> str:
    out = []
    for name in ("README.md", "CORRECTIONS.md", "CHANGELOG.md"):
        t = repo.text(name) if repo.exists(name) else None
        if t:
            out += [t] if name == "CORRECTIONS.md" else correction_sections(t)
    return "\n".join(out)


def concept_warnings(repo: Repo, files: list[str], r: Result) -> None:
    code = "\n".join(repo.text(f) or "" for f in files
                     if PurePosixPath(f).suffix.lower() in SOURCE_SUFFIXES | {".json", ".yaml", ".yml", ".toml"})
    for doc in ("README.md", "llms.txt"):
        t = repo.text(doc) if repo.exists(doc) else None
        if not t:
            continue
        t = re.sub(r"```[\s\S]*?```|`[^`]*`|\]\([^)]*\)|https?://\S+", " ", t)
        seen = set()
        for m in re.finditer(r"\b[A-Z][A-Z0-9]{1,5}s?\b", t):
            tok = m.group(0)
            base = tok[:-1] if tok.endswith("s") and tok[:-1].isupper() else tok
            if base in STOP or tok in STOP or base in seen or base.isdigit():
                continue
            seen.add(base)
            if base not in code:
                r.add(WARN, f"CLM-7: named concept {base!r} appears in {doc} and in no code file; define it in code, "
                      "mark it as a concept or planned, or remove it", doc, t.count("\n", 0, m.start()) + 1,
                      key=f"concept|{doc}|{base}")


def coverage_warnings(repo: Repo, files: list[str], claims: list[str], r: Result) -> None:
    for rel in files:
        if not PUBLIC_PROSE.match(rel):
            continue
        t = repo.text(rel)
        if not t:
            continue
        in_fence = False
        for n, line in enumerate(t.splitlines(), 1):
            if line.strip().startswith("```"):
                in_fence = not in_fence
                continue
            if in_fence or not TRIGGERS.search(line):
                continue
            nl = norm(line)
            if any(c and c in nl for c in claims) or PLANNED_WORDS.search(line):
                continue
            r.add(WARN, f"CLM-6: capability-like sentence ({TRIGGERS.search(line).group(0)!r}) not covered by a "
                  "CLAIMS.md row", rel, n, key=f"cov|{rel}|{nl[:80]}")


def run(repo: Repo, opts) -> Result:
    r = Result("claims", "Claims-to-code: README/llms.txt/docs capability claims map to code, mount point and test")
    files = repo.tracked()
    cfg = repo.config.get("claims", {}) if isinstance(repo.config.get("claims"), dict) else {}
    has_code = any(PurePosixPath(f).suffix.lower() in SOURCE_SUFFIXES and not is_test_path(f.lower()) for f in files)
    concept_warnings(repo, files, r)
    if not repo.exists("CLAIMS.md"):
        none_reason = str(cfg.get("none", "")).strip()
        if none_reason and len(none_reason) >= 20:
            r.notes.append(f"no CLAIMS.md: the repo declares it makes no capability claims ({none_reason})")
            coverage_warnings(repo, files, [], r)
            return r
        if has_code:
            r.add(BLOCK, "CLM-1: no CLAIMS.md. Every capability the README, llms.txt or docs state needs a row "
                  "mapping it to code, mount point and test (template in the ci-shared README); a repo that claims "
                  "nothing sets [claims] none = \"<why>\" in .gate.toml", key="no-claims")
        else:
            r.add(WARN, "CLM-1: no CLAIMS.md (no source code found, so not blocking)", key="no-claims")
        coverage_warnings(repo, files, [], r)
        return r
    rows, errors = parse_table(repo.text("CLAIMS.md") or "")
    for e in errors:
        r.add(BLOCK, f"CLM-2: {e}", "CLAIMS.md", key=f"table|{e}")
    ids, claim_texts = set(), []
    corr = corrections_text(repo)
    for row in rows:
        ln, cid, status = row["_line"], row.get("id", ""), row.get("status", "").lower()
        claim = norm(row.get("claim", "").strip('"'))
        claim_texts.append(claim)

        def bad(msg, sev=BLOCK):
            r.add(sev, f"{cid or '(no id)'}: {msg}", "CLAIMS.md", ln, key=f"{cid}|{msg}")
        if not cid or cid in ids:
            bad("CLM-2: id missing or duplicated")
        ids.add(cid)
        if status not in STATUSES:
            bad(f"CLM-2: status {status!r} is not one of {sorted(STATUSES)}")
            continue
        if not claim:
            bad("CLM-2: claim text is empty")
            continue
        sources = [s.strip().strip("`") for s in row.get("source", "").split(",") if s.strip()]
        if not sources:
            bad("CLM-2: source is empty: name the file the claim appears in")
        for src in sources:
            if not repo.exists(src):
                bad(f"CLM-2: source {src} does not exist")
                continue
            body = repo.text(src) or ""
            if status in ("withdrawn", "changed"):
                stripped = body
                for sec in correction_sections(body):
                    stripped = stripped.replace(sec, "")
                if claim in norm(stripped) and status == "withdrawn":
                    bad(f"CLM-5: withdrawn claim is still stated in {src}")
                continue
            # match by paragraph (blank-line separated), so a wrapped sentence still matches and a
            # 'planned' marker must sit in the same paragraph as the claim, not a neighbouring one
            paras = [p for p in re.split(r"\n\s*\n|\n(?=\s*[-*|#] )", body) if p.strip()]
            hit = [p for p in paras if claim in norm(p)]
            if not hit:
                bad(f"CLM-2: claim text not found in {src}; the table and the doc have drifted")
                continue
            if status == "planned":
                ok = any(PLANNED_WORDS.search(p) for p in hit)
                if not ok:
                    bad(f"CLM-4: marked planned, but {src} presents it as working (say 'planned' or 'not yet' next to it)")
        if status == "shipped":
            codes = split_refs(row.get("code", ""))
            if not codes:
                bad("CLM-3: shipped claim with no code reference")
            for ref in codes:
                sev, msg = resolve(repo, ref)
                if sev:
                    bad(f"CLM-3: code {msg}", sev)
            sev, msg = resolve_wired(repo, row.get("wired", ""))
            if sev:
                bad(f"CLM-3: {msg}", sev)
            tests = split_refs(row.get("test", ""))
            if not tests:
                bad("CLM-3: shipped claim with no test reference")
            for ref in tests:
                sev, msg = resolve(repo, ref, want_test=True)
                if sev:
                    bad(f"CLM-3: test {msg}", sev)
        if status in ("withdrawn", "changed"):
            note = row.get("note", "")
            d = DATE.search(note)
            if not d:
                bad("CLM-5: withdrawn or changed claim needs a YYYY-MM-DD date in note")
            elif not corr or (cid not in corr and d.group(0) not in corr):
                bad("CLM-5: no dated correction note (a 'Corrections' section in README.md, or CORRECTIONS.md / "
                    "CHANGELOG.md) naming this id or date")
    coverage_warnings(repo, files, claim_texts, r)
    r.notes.append(f"{len(rows)} claim row(s)")
    return r
