"""SEC-5..SEC-8: the estate's own security rules, from Tony's review (2026-10-22).

SEC-5  proxy code forwards the incoming request's headers upstream (Authorization, Cookie and
       API keys leak to a third party). Forward an explicit ALLOWLIST of headers instead.
SEC-6  a secret is printed or logged (a name like api_key/secret/token/password reaches print,
       logging, console.*), unless it passes through a redact/mask/fingerprint call.
SEC-7  authentication can be switched off: a default that leaves auth disabled is blocking; an
       opt-in "disable auth" flag is allowed only if a test names the flag.
SEC-8  code writes another tool's user config (~/.claude, ~/.cursor, ~/.config, shell rc files,
       MCP configs, .gitconfig, .npmrc), or an installer writes anything under the home
       directory, without both a consent prompt and a backup in the same file.

Generic SAST (bandit, semgrep rulepacks) is SEC-10, the bandit and semgrep checks in sast.py;
this module covers what those rulepacks do not express.
"""
from __future__ import annotations

import ast
import re
from pathlib import PurePosixPath

from ..core import BLOCK, WARN, Repo, Result, is_test_path

SECRET_NAME = re.compile(r"(?i)(^|_)(api_?key|apikey|secret|token|password|passwd|private_?key|credential|soulkey|"
                         r"license_?secret|signing_?key|bearer|auth_?header|client_?secret)s?($|_)")
NOT_SECRET = re.compile(r"(?i)(_id|_ids|_name|_names|_path|_file|_env|_url|_len|_length|_count|_type|_types|_limit|_usage|"
                        r"_prefix|_hint|_ttl|_expiry|_expires|_at|_set|_header_name|_field|_kind|_mode|_bucket|_budget)$|"
                        r"^(max_|num_|n_)?tokens?(_count|_used|_limit)?$|(^|_)tokens$|^token_?(count|usage|budget|limit|type)$|tokenizer|"
                        r"^(is|has|use|needs?|require)_")
SECRET_RETURNING = re.compile(r"(?i)^(generate|create|issue|mint|new|make|get|read|load|fetch|decrypt|reveal|export)_?\w*"
                              r"(key|secret|token|password|credential)s?$")
EXAMPLE_DIR = re.compile(r"(?i)(^|/)(examples?|demos?|samples?|docs?|notebooks?)/")
REDACT_CALL = re.compile(r"(?i)redact|mask|fingerprint|fp12|sha256|hashlib|digest|len\(|obfuscat|truncat|\[:\d+\]|\*\*\*")
REQUEST_BASES = re.compile(r"^(request|req|incoming|self\.request|flask\.request|ctx\.request|websocket|ws|scope)$")
OTHER_TOOL_CONFIG = re.compile(r"(?i)(\.claude|claude_desktop_config|\.cursor|\.codex|\.continue|\.windsurf|\.vscode|"
                               r"\.config[/\\]|mcp\.json|\.bashrc|\.zshrc|\.profile|\.bash_profile|\.gitconfig|\.npmrc|"
                               r"\.pypirc|appdata|application support|settings\.json)")
HOME_EXPR = re.compile(r"(expanduser\(|Path\.home\(\)|os\.environ\[?\.?(get\()?['\"](HOME|USERPROFILE|APPDATA|XDG_CONFIG_HOME)|"
                       r"getenv\(['\"](HOME|USERPROFILE|APPDATA|XDG_CONFIG_HOME)|~/|\$HOME|\$env:(USERPROFILE|APPDATA|HOME)|"
                       r"os\.homedir\(\)|process\.env\.(HOME|USERPROFILE|APPDATA))")
CONSENT = re.compile(r"(?i)(\binput\(|read -p|Read-Host|confirm|--yes\b|-y\b|prompt|consent|are you sure|\[y/N\]|\[Y/n\])")
BACKUP = re.compile(r"(?i)(backup|\.bak\b|\.orig\b|copy2?\(|shutil\.copy|cp -p|Copy-Item)")
AUTH_FLAG = re.compile(r"(?i)\b(disable|skip|no|bypass|without)_?auth(entication)?\b|\bauth(entication)?_?(disabled|off|optional)\b|"
                       r"\b(insecure|unauthenticated|no_?login|allow_?anonymous|anonymous_?access)\b")
AUTH_ON = re.compile(r"(?i)\b(require|enable|use)_?auth(entication)?\b|\bauth(entication)?_?(enabled|required|on)\b")
INSTALLER = re.compile(r"(?i)(^|/)(install|installer|setup|bootstrap|init|configure)[\w.-]*\.(py|sh|ps1|js|mjs|ts)$")


def _name_of(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return ""


def _dotted(node: ast.AST) -> str:
    try:
        return ast.unparse(node)
    except Exception:  # noqa: BLE001
        return ""


PASSTHROUGH = {"str", "repr", "format", "bytes", "decode", "encode", "hex", "strip", "upper", "lower", "dumps", "b64encode",
               "urlsafe_b64encode", "join", "replace", "get", "getattr", "f"}


def _leak(node: ast.AST) -> str:
    """The secret-like name whose VALUE this expression prints, or ''.

    A call's arguments are not printed, only its return value: print(verify_token(secret, tok))
    prints a verdict. A call returns a secret when its name says so (generate_api_key()), or when
    it only reformats its input (str(), repr(), .decode(), json.dumps()); then its inputs count.
    """
    if isinstance(node, ast.Call):
        fname = _name_of(node.func)
        if SECRET_RETURNING.search(fname or ""):
            return fname
        if fname in PASSTHROUGH:
            for child in list(node.args) + [k.value for k in node.keywords] + (
                    [node.func.value] if isinstance(node.func, ast.Attribute) else []):
                got = _leak(child)
                if got:
                    return got
        return ""
    if isinstance(node, (ast.Name, ast.Attribute)):
        nm = _name_of(node)
        if nm and SECRET_NAME.search(nm) and not benign(nm):
            return nm
        return _leak(node.value) if isinstance(node, ast.Attribute) else ""
    for child in ast.iter_child_nodes(node):
        got = _leak(child)
        if got:
            return got
    return ""


class PyScan(ast.NodeVisitor):
    def __init__(self, rel: str, text: str):
        self.rel, self.text, self.hits = rel, text, []

    def hit(self, sev, node, msg):
        self.hits.append((sev, getattr(node, "lineno", 0), msg))

    def visit_Call(self, node: ast.Call):
        fn = _dotted(node.func)
        # SEC-5: headers=<incoming request headers>
        for kw in node.keywords:
            if kw.arg == "headers":
                src = _dotted(kw.value)
                base = re.sub(r"^(dict|copy\.copy|copy\.deepcopy)\((.*)\)$", r"\2", src)
                base = re.sub(r"\.(copy|items)\(\)$", "", base)
                m = re.match(r"^(\*\*)?([\w.]+)\.headers$", base)
                if m and REQUEST_BASES.match(m.group(2)):
                    self.hit(BLOCK, node, "SEC-5: forwards the incoming request's headers upstream "
                             f"(headers={src}); Authorization and cookies leak. Forward an explicit allowlist")
                elif isinstance(kw.value, (ast.Dict, ast.DictComp)) and re.search(r"\b(request|req|incoming)\.headers\b", src):
                    if isinstance(kw.value, ast.DictComp) and re.search(r"\bin\s+[A-Z_]{4,}\b|\bin\s+\{", src) \
                            and " not in " not in src:
                        pass  # filtered through an allowlist
                    else:
                        self.hit(BLOCK, node, "SEC-5: builds upstream headers from the incoming request without an allowlist "
                                 "(a denylist is not enough)")
        # SEC-6: secrets reaching print / logging
        is_log = fn == "print" or re.search(r"(^|\.)(log|logger|logging|_log|LOG|LOGGER)\.(debug|info|warning|warn|error|"
                                             r"exception|critical|log)$", fn) or fn.endswith(("console.print", "click.echo",
                                                                                              "typer.echo", "sys.stdout.write"))
        if is_log:
            leaked = ""
            for arg in list(node.args) + [k.value for k in node.keywords]:
                if REDACT_CALL.search(_dotted(arg)):
                    continue
                leaked = _leak(arg)
                if leaked:
                    break
            if leaked:
                self.hit(BLOCK, node, f"SEC-6: {leaked!r} is printed or logged ({fn}); log a fingerprint, never the value")
        self.generic_visit(node)


def py_scan(rel: str, text: str):
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return []
    s = PyScan(rel, text)
    s.visit(tree)
    return s.hits


JS_HEADERS = re.compile(r"headers\s*:\s*(\{\s*\.\.\.\s*)?(req|request|ctx\.request|c\.req|event\.request)\.(headers|raw\.headers)\b")
JS_LOG = re.compile(r"console\.(log|info|warn|error|debug)\s*\(([^)]*)\)")


BENIGN_PARTS = {"id", "ids", "name", "names", "path", "paths", "file", "files", "dir", "url", "urls", "env", "len", "length",
                "count", "counts", "type", "types", "limit", "limits", "usage", "prefix", "hint", "ttl", "expiry", "expires",
                "at", "kind", "mode", "hash", "hashed", "digest", "fingerprint", "fp", "label", "scope", "scopes", "field",
                "today", "total", "issued", "used", "remaining", "left", "budget", "spent", "rate", "policy", "rotation",
                "status", "valid", "invalid", "missing", "required", "header", "length", "version", "algorithm", "alg"}


def benign(name: str) -> bool:
    """A secret-like word inside a name that holds something else: soulkey_id_str, tokens_today."""
    if NOT_SECRET.search(name):
        return True
    parts = [p for p in name.lower().split("_") if p]
    return any(p in BENIGN_PARTS for p in parts[1:]) or (parts[:1] and parts[0] in ("is", "has", "use", "needs", "require", "n", "num", "max", "min"))


def js_code_only(args: str) -> str:
    """Console arguments with string text removed; template ${...} expressions are kept."""
    args = re.sub(r"`((?:\\.|[^`\\])*)`", lambda m: " ".join(re.findall(r"\$\{([^}]*)\}", m.group(1))), args)
    return re.sub(r"'(?:\\.|[^'\\])*'|\"(?:\\.|[^\"\\])*\"", " ", args)


def js_scan(text: str):
    hits = []
    for m in JS_HEADERS.finditer(text):
        hits.append((BLOCK, text.count("\n", 0, m.start()) + 1,
                     "SEC-5: forwards the incoming request's headers upstream; forward an explicit allowlist"))
    for m in JS_LOG.finditer(text):
        for tok in re.findall(r"[A-Za-z_$][\w$]*", js_code_only(m.group(2))):
            snake = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", tok).lower()
            if SECRET_NAME.search(snake) and not benign(snake) and not REDACT_CALL.search(m.group(2)):
                hits.append((BLOCK, text.count("\n", 0, m.start()) + 1, f"SEC-6: {tok!r} is logged to the console"))
                break
    return hits


REGEX_LINE = re.compile(r"re\.(compile|search|match|finditer|findall|sub|fullmatch)\(|new RegExp\(|\(\?i\)")
IDENT_STRING = re.compile(r"^[rbuRBU]{0,2}(['\"])[\w.:/ -]{1,60}\1$")


def code_view(rel: str, text: str) -> str:
    """The text with prose-like and regex string literals blanked, line numbers kept.

    Identifier-like strings ('DISABLE_AUTH', '--no-auth', 'false') stay, because env var names,
    flags and defaults are what SEC-7 reads. Regex sources, messages and docstrings go, so the
    gate does not flag its own patterns or a sentence that mentions auth.
    """
    if rel.endswith(".py"):
        import io
        import tokenize
        try:
            toks = list(tokenize.generate_tokens(io.StringIO(text).readline))
        except (tokenize.TokenError, IndentationError, SyntaxError):
            toks = None
        if toks is not None:
            lines = text.splitlines(keepends=True)
            out = [list(l) for l in lines]
            for t in toks:
                fstring_part = t.type == getattr(tokenize, "FSTRING_MIDDLE", -1)  # 3.12+ splits f-strings
                if fstring_part or (t.type == tokenize.STRING and not IDENT_STRING.match(t.string)):
                    (sr, sc), (er, ec) = t.start, t.end
                    for row in range(sr, er + 1):
                        a = sc if row == sr else 0
                        b = ec if row == er else len(out[row - 1])
                        for i in range(a, min(b, len(out[row - 1]))):
                            if out[row - 1][i] not in "\r\n":
                                out[row - 1][i] = " "
            return "".join("".join(l) for l in out)
    return "\n".join("" if REGEX_LINE.search(l) else l for l in text.splitlines())


def auth_findings(repo: Repo, files: list[str], r: Result) -> None:
    tests = "\n".join(repo.text(f) or "" for f in files if is_test_path(f.lower()))
    for rel in files:
        if is_test_path(rel.lower()) or PurePosixPath(rel).suffix.lower() not in (".py", ".js", ".ts", ".mjs", ".go", ".rs"):
            continue
        text = code_view(rel, repo.text(rel) or "")
        for n, line in enumerate(text.splitlines(), 1):
            if line.strip().startswith(("#", "//")):
                continue
            # auth defaults to OFF: AUTH_ENABLED=False, getenv("REQUIRE_AUTH", "false"), DISABLE_AUTH default true
            m = re.search(r"(?i)\b([\w]*auth[\w]*)\b['\"]?\s*(?:[:=]|,)\s*['\"]?(false|0|no|off)\b['\"]?", line)
            if m and AUTH_ON.search(m.group(1)) and re.search(r"(?i)(getenv|environ|default|=\s*(False|false)|Field\(|option\()", line):
                r.add(BLOCK, f"SEC-7: authentication defaults to off ({m.group(1)} -> {m.group(2)}); auth must be on by "
                      "default, with an explicit opt-out flag and a test", rel, n, key=f"{rel}|authoff|{m.group(1)}")
                continue
            m = AUTH_FLAG.search(line)
            if m and re.search(r"(?i)(getenv|environ|argparse|add_argument|option|flag|Field\(|\bif\b|config)", line):
                flag = m.group(0)
                default_on = re.search(r"(?i)" + re.escape(flag) + r"\b['\"]?\s*[:=,]\s*['\"]?(true|1|yes|on)\b", line)
                if default_on:
                    r.add(BLOCK, f"SEC-7: '{flag}' defaults to true: the service starts unauthenticated", rel, n,
                          key=f"{rel}|authflagon|{flag}")
                elif flag.lower().replace("-", "_") not in tests.lower().replace("-", "_"):
                    r.add(BLOCK, f"SEC-7: unauthenticated mode '{flag}' exists and no test names it; add a test that proves "
                          "auth is on unless the flag is set", rel, n, key=f"{rel}|authflag|{flag.lower()}")
            if re.search(r"(?i)\b(onprem|on_prem|on-prem|local_mode|dev_mode|offline_mode)\b", line) and \
                    re.search(r"(?i)auth", line) and re.search(r"(?i)\b(skip|bypass|none|disable|return|if)\b", line):
                r.add(BLOCK, "SEC-7: a deployment mode appears to switch authentication off; an on-prem or dev mode keeps "
                      "auth on unless an explicit, tested flag turns it off", rel, n, key=f"{rel}|modeauth|{line.strip()[:60]}")


def config_write_findings(repo: Repo, files: list[str], r: Result) -> None:
    for rel in files:
        if is_test_path(rel.lower()) or PurePosixPath(rel).suffix.lower() not in (".py", ".sh", ".ps1", ".js", ".mjs", ".ts", ".bash"):
            continue
        text = repo.text(rel) or ""
        installer = bool(INSTALLER.search(rel))
        writes = []
        for n, line in enumerate(text.splitlines(), 1):
            if line.strip().startswith(("#", "//")):
                continue
            w = re.search(r"(open\([^)]*['\"][wa]\+?b?['\"]|\.write_text\(|\.write_bytes\(|json\.dump\(|shutil\.copy|writeFileSync|"
                          r"writeFile\(|Set-Content|Out-File|Add-Content|>>?\s*[\"']?(~|\$HOME|\$env:)|\btee\b)", line)
            if not w:
                continue
            window = "\n".join(text.splitlines()[max(0, n - 6): n])
            if OTHER_TOOL_CONFIG.search(window) and (HOME_EXPR.search(window) or "~" in window):
                writes.append((n, "another tool's user config"))
            elif installer and HOME_EXPR.search(window):
                writes.append((n, "a file under the user's home directory"))
        if not writes:
            continue
        consent, backup = bool(CONSENT.search(text)), bool(BACKUP.search(text))
        for n, what in writes:
            if consent and backup:
                r.add(WARN, f"SEC-8: writes {what}; consent and backup code are present, check they guard this write",
                      rel, n, key=f"{rel}|cfgwrite-ok|{n}")
            else:
                missing = " and ".join(x for x, ok in (("a consent prompt", consent), ("a backup", backup)) if not ok)
                r.add(BLOCK, f"SEC-8: writes {what} without {missing}; ask first, back up the old file, then write",
                      rel, n, key=f"{rel}|cfgwrite|{what}")


def run(repo: Repo, opts) -> Result:
    r = Result("security", "Estate security rules: header allowlist, no secrets in logs, auth on by default, config consent")
    files = repo.tracked()
    for rel in files:
        if is_test_path(rel.lower()):
            continue
        suffix = PurePosixPath(rel).suffix.lower()
        text = repo.text(rel)
        if not text:
            continue
        hits = py_scan(rel, text) if suffix == ".py" else js_scan(text) if suffix in (".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx") else []
        lines = text.splitlines()
        for sev, ln, msg in hits:
            if msg.startswith("SEC-6") and EXAMPLE_DIR.search(rel):
                sev, msg = WARN, msg + " (example code: people copy it, so prefer a fingerprint here too)"
            src = lines[ln - 1].strip() if 0 < ln <= len(lines) else ""
            r.add(sev, msg, rel, ln, key=f"{rel}|{msg[:40]}|{src[:80]}")
    auth_findings(repo, files, r)
    config_write_findings(repo, files, r)
    r.notes.append("generic SAST (bandit, semgrep) is SEC-10: the bandit and semgrep checks")
    return r
