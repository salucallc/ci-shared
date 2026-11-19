"""SEC-10: generic SAST, bandit (Python) and semgrep rulepacks, run by the gate itself.

Until 2026-10-30 these ran ONLY in CI, through reusable-sast-python.yml (`bandit -r .`) and
reusable-semgrep.yml (`semgrep ... --error .`), which scan the whole tree and never read
`.gate-baseline.json`. A local `gate run` listed SAST as ci-only and could be green while CI was
red, and `gate baseline` could not record SAST debt. tiresias-zt adopted the gate on a green local
run with 989 baseline entries, and main went red on 45 pre-existing findings. Now the same check
code runs here and in CI (merge-gate.yml runs `python -m gate run --only bandit` and
`--only semgrep`), so the two cannot disagree, and SAST findings are baselined like any other.

The tool, its version, its flags and its rulesets are constants below. A repo cannot change
them (config may only narrow). A tool that is missing, is the wrong version, cannot reach the
semgrep registry, or exits with an error is cannot tell (exit 2), never a pass.

Fingerprints carry no line number: a finding's key is the tool, the rule, the path and a hash of
the flagged source text with whitespace collapsed. Moving the code keeps its baseline entry;
editing the flagged lines makes it a new finding, which blocks (touched debt is new debt).

Files scanned: the tracked files the gate reads (`Repo.tracked()`, so the constant exclusions
apply). Untracked files never count, so a local run and a CI checkout see the same set, and the
gate's own checkout in CI (`.merge-gate/`) is not scanned as if it were the repo.
"""
from __future__ import annotations

import contextlib
import hashlib
import json
import os
import platform
import re
import shutil
import signal
import subprocess
import tarfile
import threading
import time
from pathlib import Path

from ..core import BLOCK, WARN, Repo, Result

# The pins. merge-gate.yml installs exactly these (it reads them from this file), and a unit test
# holds the defaults of reusable-sast-python.yml and reusable-semgrep.yml to the same values.
BANDIT_VERSION = "1.9.4"
BANDIT_SEVERITY = "medium"
BANDIT_CONFIDENCE = "medium"
SEMGREP_VERSION = "1.160.0"
# 0 = no per-target limit. Semgrep's default is 5 seconds per rule/target pair, and a target that
# exceeds it is DROPPED. What is left behind is unreliable: measured 2026-11-01 on saluca-content,
# one scan of `tools/` reported the timeouts as `Type: Timeout` entries in `errors`, while a wider
# scan missed `tools/push_in.py:313,327` entirely - no `errors` entry, no `skipped_rules`, no
# `paths.skipped`, and no evidence at all except the finding that was not there, though
# `paths.scanned` listed the file. The same image found both findings on the file alone and with
# `--timeout 120`. Two consecutive runs of the same command on the same tree then returned 28
# findings and 21 errors, then 29 findings and 23 errors. So the result depends on how many files
# are in the walk and how loaded the machine is, two machines disagree about what the repo
# contains, and a baseline written on one is wrong for the other - which is exactly how PR 163
# went red on a tree that was green locally. A slow repository should be slow, not quietly
# smaller; the 3600 s subprocess cap below is the backstop, and a remaining semgrep error is
# cannot tell rather than a note.
SEMGREP_TIMEOUT_SECONDS = "0"
SEMGREP_CONFIGS = ("p/owasp-top-ten", "p/python", "p/secrets", "p/ci")
SEMGREP_SEVERITY = "ERROR"
SEMGREP_IMAGE = f"semgrep/semgrep:{SEMGREP_VERSION}"
# Resource caps (2026-11-18). A Docker semgrep scan of one worktree took about 7 of the
# workstation's 16 cores for 90 minutes and made the machine unusable for Cristian. The scan is
# shared with a person at the keyboard, so it gets at most SEMGREP_MAX_CPUS cores, a low CPU
# weight, a memory ceiling, and the same number of semgrep jobs. These limit speed, never coverage:
# the per-target timeout stays 0, so a slower scan is still a complete scan.
# GATE_SEMGREP_CPUS may only LOWER the core cap; a value above it is clamped, a non-integer raises.
SEMGREP_MAX_CPUS = 4
SEMGREP_MEMORY = "8g"
SEMGREP_CPU_SHARES = "256"  # Docker's default is 1024: interactive work wins under contention
SEMGREP_RUN_SECONDS = 3600
# The scan reads a COPY of the tracked files, not a bind mount (2026-11-19). Measured on saluca-content (4,333 tracked
# files): `semgrep` over a Docker Desktop bind mount of the Windows checkout used about 0.1 of a core and had not
# finished after 20 minutes (three gate runs killed by their caller's `timeout`, exit 124, each leaving a container);
# the same scan over the same files streamed into the container as a tar finished in 30 seconds with the same 28
# findings and no errors. The bind mount's per-file latency, not semgrep's analysis, was the whole cost. The tar holds
# exactly the tracked files the gate reads (working-tree content, so uncommitted edits count), without the files
# semgrep itself skips as too large, so what is scanned is what a CI checkout would scan.
SEMGREP_MAX_TARGET_BYTES = 1_000_000   # semgrep's own default --max-target-bytes: larger files are skipped by it anyway
SEMGREP_UNPACK = 'mkdir -p /src && cd /src && tar x || { echo "saluca-gate: could not unpack the sources" >&2; exit 2; }; '

# Orphaned scans (2026-11-19). The cap above only helps when THIS process survives to enforce it. A caller's
# `timeout 1200 python gate.py` (exit 124) kills the gate with no chance to clean up, `docker run` is only a client,
# and the container goes on holding 4 cores until it finishes, so three timed-out gate runs on saluca-content left
# three scans running. Three layers, each covering what the one before cannot:
#   1. the container watches its owner: the gate writes a heartbeat file (a counter, every SEMGREP_BEAT_SECONDS) into a
#      directory mounted read-only at /hb, and the guard script inside the container kills semgrep and exits when the
#      counter has not changed for SEMGREP_STALE_SECONDS. A gate killed by `timeout` stops beating, so its scan ends
#      within minutes, not an hour. Backstop: busybox `timeout -s KILL` a minute after the host-side cap;
#   2. the gate removes its container when it exits any way it can notice (exception, SIGINT, SIGTERM, SIGBREAK);
#   3. every run begins by removing scans whose owner is gone: labelled `saluca-gate=semgrep`, with the owner's pid
#      and start time, an orphan is a labelled container whose owner pid is dead or that outlived the cap.
SEMGREP_LABEL = "saluca-gate=semgrep"
SEMGREP_SELF_KILL_SECONDS = SEMGREP_RUN_SECONDS + 60
SEMGREP_ORPHAN_AGE_SECONDS = SEMGREP_SELF_KILL_SECONDS + 120
SEMGREP_BEAT_SECONDS = 15
SEMGREP_STALE_SECONDS = 180
# The guard the container runs instead of bare semgrep. It compares the heartbeat's CONTENT, not its mtime, so a clock
# that differs between the host and the container's VM cannot make a live gate look dead. $@ is semgrep's arguments.
# GATE_HB_FILE, GATE_HB_STALE and GATE_HB_POLL exist so a test can use seconds instead of minutes; the defaults are the constants.
SEMGREP_GUARD = (
    'timeout -s KILL "${GATE_HB_DEADLINE:-%d}" semgrep "$@" & p=$!; last=; since=$(date +%%s); '
    'while kill -0 $p 2>/dev/null; do '
    'cur=$(cat "${GATE_HB_FILE:-/hb/beat}" 2>/dev/null); now=$(date +%%s); '
    '[ "$cur" != "$last" ] && last=$cur && since=$now; '
    'if [ $((now - since)) -gt "${GATE_HB_STALE:-%d}" ]; then '
    'echo "saluca-gate: owner heartbeat lost, semgrep killed" >&2; kill -9 $p 2>/dev/null; wait $p 2>/dev/null; exit 124; fi; '
    'sleep "${GATE_HB_POLL:-5}"; done; wait $p; exit $?'
) % (SEMGREP_SELF_KILL_SECONDS, SEMGREP_STALE_SECONDS)

CACHE = Path.home() / ".cache" / "saluca-gate"
BANDIT_SUFFIXES = (".py", ".pyw")  # what `bandit -r` picks up
BANDIT_CHUNK = 150  # files per bandit call: keeps a Windows command line well under its limit
_RANK = {"low": 0, "medium": 1, "high": 2}


def _bin(venv_dir: Path, name: str) -> Path:
    return venv_dir / ("Scripts" if platform.system() == "Windows" else "bin") / (
        name + (".exe" if platform.system() == "Windows" else ""))


def _version(cmd: list[str], pattern: str) -> str:
    try:
        out = subprocess.run(cmd + ["--version"], capture_output=True, text=True, encoding="utf-8", errors="replace",
                             timeout=120)
    except (OSError, subprocess.TimeoutExpired):
        return ""
    m = re.search(pattern, out.stdout + out.stderr)
    return m.group(1) if m else ""


def bandit_command() -> tuple[list[str] | None, str]:
    """The pinned bandit as a command prefix, or (None, why). Candidates: GATE_BANDIT, the gate
    cache venv (`python -m gate bootstrap`), then PATH. A wrong version is not a candidate."""
    cands = []
    if os.environ.get("GATE_BANDIT"):
        cands.append(os.environ["GATE_BANDIT"])
    cands.append(str(_bin(CACHE / "venv", "bandit")))
    which = shutil.which("bandit")
    if which:
        cands.append(which)
    seen = []
    for c in cands:
        if not Path(c).is_file():
            continue
        v = _version([c], r"(?i)bandit\S*\s+(\d+\.\d+\.\d+)")  # it prints its argv[0]: "bandit.EXE 1.9.4"
        if v == BANDIT_VERSION:
            return [c], ""
        seen.append(f"{c} is {v or 'unknown'}")
    why = f"bandit {BANDIT_VERSION} not found" + (f" ({'; '.join(seen)})" if seen else "")
    return None, why + "; run `python -m gate bootstrap` (installs it into a venv under the gate cache) or set GATE_BANDIT"


def semgrep_cpus() -> int:
    """The core cap for one scan. GATE_SEMGREP_CPUS can only narrow SEMGREP_MAX_CPUS; an
    unparseable value raises rather than falling back to a default."""
    raw = os.environ.get("GATE_SEMGREP_CPUS")
    if raw is None or raw.strip() == "":
        return SEMGREP_MAX_CPUS
    try:
        n = int(raw.strip())
    except ValueError:
        raise ValueError(f"GATE_SEMGREP_CPUS={raw!r} is not an integer") from None
    return max(1, min(n, SEMGREP_MAX_CPUS))


def docker_semgrep_prefix(docker: str, root: Path, name: str | None = None) -> list[str]:
    """`docker run` for the pinned image, with the resource caps. `name` lets a timed-out scan be
    removed: killing the docker CLI does NOT stop its container, which is how a scan outlived the
    3600 s cap and kept 7 cores busy for 90 minutes."""
    cmd = [docker, "run", "--rm"]
    if name:
        cmd += ["--name", name, "--label", SEMGREP_LABEL, "--label", f"saluca-gate-pid={os.getpid()}",
                "--label", f"saluca-gate-started={int(time.time())}"]
    cmd += ["--cpus", str(semgrep_cpus()), "--cpu-shares", SEMGREP_CPU_SHARES, "--memory", SEMGREP_MEMORY]
    if not name:  # the version probe reads nothing of the repo
        return cmd + ["-v", f"{root}:/src", "-w", "/src", SEMGREP_IMAGE, "semgrep"]
    # The real scan: the sources arrive on stdin as a tar (see pack_sources), and it runs under the guard, so it ends
    # even when the gate that started it was killed without a chance to remove it.
    hb = CACHE / "heartbeats" / name
    hb.mkdir(parents=True, exist_ok=True)
    (hb / "beat").write_text("0", encoding="utf-8")
    cmd.insert(2, "-i")
    return cmd + ["-v", f"{hb}:/hb:ro", "-w", "/", SEMGREP_IMAGE, "sh", "-c", SEMGREP_UNPACK + SEMGREP_GUARD,
                  "saluca-gate-guard"]


def pack_sources(repo: Repo, dest: Path) -> tuple[int, int]:
    """Write the tracked files the gate reads, as the working tree has them, to the tar `dest`: (packed, too large).
    Files over SEMGREP_MAX_TARGET_BYTES are left out because semgrep skips them. A tracked file that is gone from the
    working tree is left out (the bind mount did not have it either); any other read error raises OSError, and the
    caller turns it into cannot tell rather than scanning a partial copy."""
    packed = big = 0
    dest.parent.mkdir(parents=True, exist_ok=True)
    with tarfile.open(dest, "w") as tf:
        for rel in repo.tracked():
            f = repo.root / rel
            try:
                st = f.lstat()
            except FileNotFoundError:
                continue
            if f.is_symlink() or not f.is_file():
                continue
            if st.st_size > SEMGREP_MAX_TARGET_BYTES:
                big += 1
                continue
            tf.add(str(f), arcname=rel.replace("\\", "/"), recursive=False)
            packed += 1
    return packed, big


def _heartbeat_file(cmd: list[str]) -> Path | None:
    for i, a in enumerate(cmd):
        if a == "-v" and i + 1 < len(cmd) and cmd[i + 1].endswith(":/hb:ro"):
            return Path(cmd[i + 1][: -len(":/hb:ro")]) / "beat"
    return None


@contextlib.contextmanager
def heartbeat(cmd: list[str]):
    """While the block runs, write an increasing counter to the scan's heartbeat file every SEMGREP_BEAT_SECONDS."""
    f = _heartbeat_file(cmd)
    if f is None:
        yield
        return
    stop = threading.Event()

    def beat():
        n = 0
        while not stop.wait(SEMGREP_BEAT_SECONDS):
            n += 1
            try:
                f.write_text(str(n), encoding="utf-8")
            except OSError:
                pass  # a missed beat is tolerated; STALE_SECONDS is many beats

    t = threading.Thread(target=beat, daemon=True)
    t.start()
    try:
        yield
    finally:
        stop.set()
        shutil.rmtree(f.parent, ignore_errors=True)


def _pid_alive(pid: int) -> bool:
    """Is `pid` a running process? Cannot tell counts as alive: a live gate's scan must never be removed."""
    if pid <= 0:
        return False
    if platform.system() == "Windows":
        try:
            import ctypes
            k32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
            h = k32.OpenProcess(0x1000, False, pid)  # PROCESS_QUERY_LIMITED_INFORMATION
            if not h:
                return k32.GetLastError() == 5  # access denied: it exists
            try:
                code = ctypes.c_ulong()
                return bool(k32.GetExitCodeProcess(h, ctypes.byref(code))) and code.value == 259  # STILL_ACTIVE
            finally:
                k32.CloseHandle(h)
        except Exception:  # noqa: BLE001
            return True
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except OSError:
        return True
    return True


def reap_orphan_scans(docker: str, now: float | None = None) -> list[str]:
    """Remove semgrep containers the gate started whose owner is gone: the owner pid is dead, or the scan is older than
    its own deadline. Returns the names removed. Best effort by design: a docker that cannot be asked removes nothing,
    and a container of a LIVE gate (another terminal, CI on this host) is left alone."""
    now = time.time() if now is None else now
    try:
        out = subprocess.run([docker, "ps", "--filter", f"label={SEMGREP_LABEL}", "--format",
                              '{{.Names}}|{{.Label "saluca-gate-pid"}}|{{.Label "saluca-gate-started"}}'],
                             capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=60)
    except (OSError, subprocess.TimeoutExpired):
        return []
    if out.returncode != 0:
        return []
    _prune_cache(now)
    removed = []
    for line in out.stdout.splitlines():
        parts = line.strip().split("|")
        if len(parts) != 3 or not parts[0]:
            continue
        name, pid_s, started_s = parts
        try:
            pid, started = int(pid_s), int(started_s)
        except ValueError:
            continue  # not ours to judge
        if _pid_alive(pid) and now - started <= SEMGREP_ORPHAN_AGE_SECONDS:
            continue
        if _rm_container(docker, name):
            removed.append(name)
    return removed


def _prune_cache(now: float) -> None:
    """Heartbeat directories and source tars left by a gate that was killed without cleanup, once a day old."""
    for d in (CACHE / "heartbeats", CACHE / "src-tars"):
        try:
            for p in d.iterdir():
                if now - p.stat().st_mtime > 86400:
                    shutil.rmtree(p, ignore_errors=True) if p.is_dir() else p.unlink(missing_ok=True)
        except OSError:
            pass


def _rm_container(docker: str, name: str) -> bool:
    try:
        return subprocess.run([docker, "rm", "-f", name], capture_output=True, timeout=60).returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


class GateInterrupted(SystemExit):
    """Raised by the signal handler so the stack unwinds (subprocess.run kills its child, `finally` removes the
    container) instead of the process dying with the scan still running."""


@contextlib.contextmanager
def removes_container_on_exit(cmd: list[str]):
    """However the block ends - normally, by an exception, SIGINT, SIGTERM or SIGBREAK - the named scan container is
    removed. (A kill that gives no chance to run any of this is what the self-kill and the orphan reaper are for.)"""
    name = _container_name(cmd)
    if not name:
        yield
        return
    saved = {}
    if threading.current_thread() is threading.main_thread():
        def handler(signum, _frame):
            raise GateInterrupted(128 + signum)
        for sig in (getattr(signal, n, None) for n in ("SIGINT", "SIGTERM", "SIGBREAK")):
            if sig is not None:
                try:
                    saved[sig] = signal.signal(sig, handler)
                except (OSError, ValueError):
                    pass
    try:
        yield
    finally:
        for sig, old in saved.items():
            try:
                signal.signal(sig, old)
            except (OSError, ValueError):
                pass
        _rm_container(cmd[0], name)


def _container_name(cmd: list[str]) -> str | None:
    return cmd[cmd.index("--name") + 1] if "--name" in cmd and cmd.index("--name") + 1 < len(cmd) else None


def semgrep_command(root: Path) -> tuple[list[str] | None, str]:
    """The pinned semgrep as a command prefix run from `root`, or (None, why). Candidates:
    GATE_SEMGREP, the gate cache venv, PATH, then the official image under Docker (semgrep has no
    native Windows build; this is how the 1.160.0 runs on Windows hosts are reproduced)."""
    cands = []
    if os.environ.get("GATE_SEMGREP"):
        cands.append(os.environ["GATE_SEMGREP"])
    cands.append(str(_bin(CACHE / f"semgrep-{SEMGREP_VERSION}", "semgrep")))
    which = shutil.which("semgrep")
    if which:
        cands.append(which)
    seen = []
    for c in cands:
        if not Path(c).is_file():
            continue
        v = _version([c], r"(\d+\.\d+\.\d+)")
        if v == SEMGREP_VERSION:
            return [c], ""
        seen.append(f"{c} is {v or 'unknown'}")
    docker = shutil.which("docker")
    if docker and not os.environ.get("GATE_SEMGREP"):
        v = _version(docker_semgrep_prefix(docker, root), r"(\d+\.\d+\.\d+)")
        if v == SEMGREP_VERSION:
            return docker_semgrep_prefix(docker, root, f"saluca-gate-semgrep-{os.getpid()}-{os.urandom(4).hex()}"), ""
        seen.append(f"docker {SEMGREP_IMAGE} did not run ({v or 'no version printed; is the daemon up?'})")
    why = f"semgrep {SEMGREP_VERSION} not found" + (f" ({'; '.join(seen)})" if seen else "")
    return None, why + ("; run `python -m gate bootstrap`, install semgrep==" + SEMGREP_VERSION +
                        f", set GATE_SEMGREP, or start Docker for {SEMGREP_IMAGE}")


def _norm(p: str) -> str:
    p = p.replace("\\", "/")
    while p.startswith("./"):
        p = p[2:]
    return p


def snippet_hash(repo: Repo, rel: str, first: int, last: int) -> str:
    """A hash of the flagged lines, whitespace collapsed: the line-number-free part of the key."""
    lines = (repo.text(rel) or "").splitlines()
    first, last = max(first, 1), max(last, first)
    body = "\n".join(" ".join(ln.split()) for ln in lines[first - 1:last] if ln.strip())
    return hashlib.sha256(body.encode("utf-8", "replace")).hexdigest()[:16]


def run_bandit(repo: Repo, opts) -> Result:
    r = Result("bandit", f"Generic SAST: bandit {BANDIT_VERSION} (severity and confidence >= {BANDIT_SEVERITY})")
    files = [f for f in repo.tracked() if f.lower().endswith(BANDIT_SUFFIXES)]
    if not files:
        return r.na("no tracked Python files")
    cmd, why = bandit_command()
    if not cmd:
        return r.cannot(why)
    unparsed = 0
    for i in range(0, len(files), BANDIT_CHUNK):
        chunk = files[i:i + BANDIT_CHUNK]
        try:
            out = subprocess.run(cmd + ["-r", *chunk, "-f", "json", "-q", "--severity-level", BANDIT_SEVERITY,
                                        "--confidence-level", BANDIT_CONFIDENCE], cwd=repo.root, capture_output=True,
                                 text=True, encoding="utf-8", errors="replace", timeout=1800)
        except (OSError, subprocess.TimeoutExpired) as e:
            return r.cannot(f"bandit did not run: {type(e).__name__}: {e}")
        try:
            data = json.loads(out.stdout)
        except json.JSONDecodeError:
            return r.cannot(f"bandit exited {out.returncode} without a JSON report: {out.stderr.strip()[-300:]}")
        if out.returncode not in (0, 1):
            return r.cannot(f"bandit exited {out.returncode}: {out.stderr.strip()[-300:]}")
        for e in data.get("errors", []):
            unparsed += 1
            rel = _norm(str(e.get("filename", "")))
            r.add(WARN, f"SEC-10: bandit could not scan this file ({e.get('reason', 'no reason given')}); "
                  "CI's bandit skips it the same way", rel, key=f"bandit-error|{rel}")
        for f in data.get("results", []):
            sev, conf = str(f.get("issue_severity", "")).lower(), str(f.get("issue_confidence", "")).lower()
            if _RANK.get(sev, -1) < _RANK[BANDIT_SEVERITY] or _RANK.get(conf, -1) < _RANK[BANDIT_CONFIDENCE]:
                continue
            rel = _norm(str(f.get("filename", "")))
            rng = f.get("line_range") or [f.get("line_number", 0)]
            line = int(f.get("line_number") or rng[0] or 0)
            tid = f.get("test_id", "?")
            h = snippet_hash(repo, rel, int(min(rng)), int(max(rng)))
            r.add(BLOCK, f"SEC-10: bandit {tid} {f.get('test_name', '')} ({sev}/{conf}): {f.get('issue_text', '').strip()}",
                  rel, line, key=f"bandit|{tid}|{rel}|{h}")
    r.notes.append(f"bandit {BANDIT_VERSION} over {len(files)} tracked Python file(s); `# nosec <id>` with a reason "
                   "suppresses one line" + (f"; {unparsed} file(s) could not be parsed" if unparsed else ""))
    return r


def semgrep_argv(cmd: list[str]) -> list[str]:
    """The full argument list, so the flags are one testable thing rather than a literal in a call."""
    args = []
    for c in SEMGREP_CONFIGS:
        args += ["--config", c]
    return cmd + args + [f"--severity={SEMGREP_SEVERITY}", "--error", "--json", "--quiet",
                         "--disable-version-check", "--timeout", SEMGREP_TIMEOUT_SECONDS,
                         "--jobs", str(semgrep_cpus()), "."]


def run_semgrep(repo: Repo, opts) -> Result:
    r = Result("semgrep", f"Generic SAST: semgrep {SEMGREP_VERSION} ({', '.join(SEMGREP_CONFIGS)}; {SEMGREP_SEVERITY})")
    tracked = set(repo.tracked())
    if not tracked:
        return r.na("no tracked files")
    if getattr(opts, "offline", False):
        return r.cannot("--offline: semgrep fetches its rulepacks from the registry")
    try:
        cmd, why = semgrep_command(repo.root)
        argv = semgrep_argv(cmd) if cmd else None
    except ValueError as e:
        return r.cannot(str(e))
    if not cmd:
        return r.cannot(why)
    if _container_name(cmd):
        reaped = reap_orphan_scans(cmd[0])
        if reaped:
            r.notes.append(f"removed {len(reaped)} orphaned semgrep container(s) of earlier gate runs: {', '.join(reaped)}")
    name = _container_name(cmd)
    tar_path = CACHE / "src-tars" / f"{name}.tar" if name else None
    stdin = None
    try:
        if tar_path is not None:
            packed, big = pack_sources(repo, tar_path)
            r.notes.append(f"scanned a copy of {packed} tracked file(s) ({big} over {SEMGREP_MAX_TARGET_BYTES} bytes left "
                           "to semgrep's own size skip)")
            stdin = tar_path.open("rb")
        with removes_container_on_exit(cmd), heartbeat(cmd):  # the CLI dying does not stop its container; this does
            out = subprocess.run(argv, cwd=repo.root, stdin=stdin, capture_output=True,
                                 text=True, encoding="utf-8", errors="replace", timeout=SEMGREP_RUN_SECONDS)
    except (OSError, subprocess.TimeoutExpired) as e:
        return r.cannot(f"semgrep did not run: {type(e).__name__}: {e}")
    finally:
        if stdin is not None:
            stdin.close()
        if tar_path is not None:
            tar_path.unlink(missing_ok=True)
    if out.returncode not in (0, 1):
        return r.cannot(f"semgrep exited {out.returncode} (0 clean, 1 findings; anything else is an error): "
                        f"{(out.stderr or out.stdout).strip()[-400:]}")
    try:
        data = json.loads(out.stdout)
    except json.JSONDecodeError:
        return r.cannot(f"semgrep exited {out.returncode} without a JSON report: {out.stderr.strip()[-300:]}")
    if not isinstance(data, dict) or "results" not in data:
        return r.cannot("semgrep printed JSON with no results list")
    outside = 0
    for f in data["results"]:
        rel = _norm(str(f.get("path", "")))
        if rel not in tracked:
            outside += 1  # untracked or excluded: neither a local run nor CI judges it
            continue
        start = int((f.get("start") or {}).get("line") or 0)
        end = int((f.get("end") or {}).get("line") or start)
        rule = str(f.get("check_id", "?"))
        msg = " ".join(str((f.get("extra") or {}).get("message", "")).split())
        h = snippet_hash(repo, rel, start, end)
        r.add(BLOCK, f"SEC-10: semgrep {rule}: {msg[:300]}", rel, start, key=f"semgrep|{rule}|{rel}|{h}")
    r.notes.append(f"semgrep {SEMGREP_VERSION} via {'docker ' + SEMGREP_IMAGE if 'docker' in Path(cmd[0]).name else cmd[0]}; "
                   "`# nosemgrep: <rule-id>` with a reason suppresses one line"
                   + (f"; {outside} result(s) in untracked or excluded files ignored" if outside else ""))
    errs = [e for e in data.get("errors", []) if isinstance(e, dict)]
    # PartialParsing is the one error that names exactly what was not analysed: semgrep parsed the
    # file, and one rule could not parse a sub-snippet of it (in practice `${{ ... }}` inside a
    # workflow `run:` block, read as Bash by gha-curl-pipe-shell's metavariable-pattern). Each
    # named span becomes a BLOCKING finding keyed by the hash of its lines: it is never a pass, a
    # baseline records it like any other finding and lists it in the PR, and an edit to the span
    # is a new finding. Found 2026-11-08: tiresias-report and tiresias-watch read cannot-tell on
    # every run, so `gate baseline` refused and neither repo could adopt. Every other error kind
    # (timeouts above all, which name no span) stays cannot tell.
    unparsed: set[str] = set()
    rest = []
    for e in errs:
        kind = e.get("type")
        spans = kind[1] if isinstance(kind, list) and len(kind) > 1 and kind[0] == "PartialParsing" else None
        if not (isinstance(spans, list) and spans and all(isinstance(s, dict) and s.get("path") for s in spans)):
            rest.append(e)
            continue
        m = re.search(r"in rule '([^']+)'", str(e.get("message") or ""))
        rule = str(e.get("rule_id") or (m.group(1) if m else "") or "a rule")
        for s in spans:
            rel = _norm(str(s.get("path")))
            start = int((s.get("start") or {}).get("line") or 0)
            end = int((s.get("end") or {}).get("line") or start)
            key = f"semgrep-unparsed|{rule}|{rel}|{snippet_hash(repo, rel, start, end)}"
            if rel not in tracked or key in unparsed:
                continue
            unparsed.add(key)
            r.add(BLOCK, f"SEC-10: semgrep could not parse lines {start}-{end} for {rule}, so that rule did "
                  "not analyse them; rewrite the span (in a workflow, pass `${{ }}` values through `env:`) "
                  "or record it in the baseline", rel, start, key=key)
    errs = rest
    if errs:
        # A semgrep error means part of the tree was NOT analysed, so the absence of a finding
        # there proves nothing. This used to be a note and the check still passed, which is how
        # two consecutive runs of the same command on the same tree disagreed: saluca-content,
        # 2026-11-01, 28 findings with 21 errors, then 29 findings with 23 ("non-fatal") errors.
        # Cannot tell is never a pass.
        kinds = {}
        for e in errs:
            kinds[str(e.get("type") or "error")] = kinds.get(str(e.get("type") or "error"), 0) + 1
        detail = ", ".join(f"{n} {k}" for k, n in sorted(kinds.items()))
        first = next((e for e in errs if e.get("message")), errs[0])
        where = _norm(str(first.get("path") or "")) or "the tree"
        return r.cannot(f"semgrep reported {len(errs)} error(s) ({detail}), so part of the tree was not "
                        f"analysed and a missing finding there means nothing; first: {where}: "
                        f"{' '.join(str(first.get('message') or '').split())[:300]}")
    return r
