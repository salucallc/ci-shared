"""LIC-1..LIC-4: one licence, stated the same way everywhere, and no silent change.

LIC-1  exactly one root licence file (LICENSE, LICENCE, COPYING, with any extension), or a
       dual-licence pair whose ids the README states as an SPDX expression.
LIC-2  the licence the file contains is the one the README, pyproject/setup.cfg/package.json/
       Cargo.toml, CITATION.cff, .zenodo.json and NOTICE state. With --online, also the live
       Zenodo record's licence for any Zenodo DOI in CITATION.cff or .zenodo.json.
LIC-3  a change of licence in the last 90 days carries a dated note (README, CHANGELOG.md or
       LICENSE-CHANGES.md: a line naming the licence change and a YYYY-MM-DD date on or after it).
       Cristian approves a licence change; that half is the PR checklist, not code.
LIC-4  (warning) more than one licence change in 90 days. Tony's review, 2026-10-22: a licence
       changed twice in three weeks.
"""
from __future__ import annotations

import datetime as dt
import json
import re
import urllib.error
import urllib.request
from pathlib import PurePosixPath

from ..core import BLOCK, WARN, Repo, Result

FILE_RE = re.compile(r"(?i)^(licen[cs]e|copying|unlicense)([.-][\w.-]*)?$")
SIGNATURES = [  # order matters: the more specific text first
    # FSL first: its text quotes the Apache or MIT licence it converts to
    ("FSL-1.1-ALv2", [r"Functional Source License,? Version 1\.1", r"Apache (License,? Version )?2\.0 Future License"]),
    ("FSL-1.1-MIT", [r"Functional Source License,? Version 1\.1", r"MIT Future License"]),
    ("AGPL-3.0", [r"GNU AFFERO GENERAL PUBLIC LICENSE"]),
    ("LGPL-3.0", [r"GNU LESSER GENERAL PUBLIC LICENSE", r"Version 3"]),
    ("LGPL-2.1", [r"GNU LESSER GENERAL PUBLIC LICENSE", r"Version 2\.1"]),
    ("GPL-3.0", [r"GNU GENERAL PUBLIC LICENSE", r"Version 3"]),
    ("GPL-2.0", [r"GNU GENERAL PUBLIC LICENSE", r"Version 2"]),
    ("Apache-2.0", [r"Apache License", r"Version 2\.0"]),
    ("MPL-2.0", [r"Mozilla Public License,? (Version|v\.?) ?2\.0"]),
    ("BUSL-1.1", [r"Business Source License 1\.1"]),
    ("Elastic-2.0", [r"Elastic License 2\.0"]),
    ("PolyForm-Noncommercial-1.0.0", [r"PolyForm Noncommercial License 1\.0\.0"]),
    ("PolyForm-Small-Business-1.0.0", [r"PolyForm Small Business License 1\.0\.0"]),
    ("PolyForm-Shield-1.0.0", [r"PolyForm Shield License 1\.0\.0"]),
    ("CC-BY-NC-SA-4.0", [r"Attribution-NonCommercial-ShareAlike 4\.0"]),
    ("CC-BY-NC-4.0", [r"Attribution-NonCommercial 4\.0"]),
    ("CC-BY-SA-4.0", [r"Attribution-ShareAlike 4\.0"]),
    ("CC-BY-4.0", [r"Attribution 4\.0 International"]),
    ("CC0-1.0", [r"CC0 1\.0 Universal"]),
    ("Unlicense", [r"This is free and unencumbered software"]),
    ("ISC", [r"Permission to use, copy, modify, and(/or)? distribute this software for any purpose with or without fee"]),
    ("BSD-3-Clause", [r"Redistribution and use in source and binary forms", r"(Neither the name|names of its\s+contributors)"]),
    ("BSD-2-Clause", [r"Redistribution and use in source and binary forms"]),
    ("MIT", [r"Permission is hereby granted, free of charge"]),
]
ALIASES = {
    "mit": "MIT", "mit license": "MIT", "the mit license": "MIT", "expat": "MIT",
    "apache-2.0": "Apache-2.0", "apache 2.0": "Apache-2.0", "apache-2": "Apache-2.0", "apache license 2.0": "Apache-2.0",
    "apache license, version 2.0": "Apache-2.0", "apache software license": "Apache-2.0", "apache2": "Apache-2.0",
    "bsd-3-clause": "BSD-3-Clause", "bsd 3-clause": "BSD-3-Clause", "bsd-2-clause": "BSD-2-Clause", "bsd license": "BSD-3-Clause",
    "gpl-3.0": "GPL-3.0", "gpl-3.0-only": "GPL-3.0", "gpl-3.0-or-later": "GPL-3.0", "gplv3": "GPL-3.0", "gpl v3": "GPL-3.0",
    "gnu general public license v3 (gplv3)": "GPL-3.0", "agpl-3.0": "AGPL-3.0", "agpl-3.0-only": "AGPL-3.0",
    "agpl-3.0-or-later": "AGPL-3.0", "agplv3": "AGPL-3.0", "gnu affero general public license v3": "AGPL-3.0",
    "lgpl-3.0": "LGPL-3.0", "mpl-2.0": "MPL-2.0", "mozilla public license 2.0 (mpl 2.0)": "MPL-2.0",
    "cc-by-4.0": "CC-BY-4.0", "cc by 4.0": "CC-BY-4.0", "cc-by 4.0": "CC-BY-4.0", "creative commons attribution 4.0 international": "CC-BY-4.0",
    "cc-by-sa-4.0": "CC-BY-SA-4.0", "cc-by-nc-4.0": "CC-BY-NC-4.0", "cc-by-nc-sa-4.0": "CC-BY-NC-SA-4.0", "cc0-1.0": "CC0-1.0",
    "cc0": "CC0-1.0", "unlicense": "Unlicense", "isc": "ISC", "busl-1.1": "BUSL-1.1", "elastic-2.0": "Elastic-2.0",
    "polyform-noncommercial-1.0.0": "PolyForm-Noncommercial-1.0.0", "polyform noncommercial": "PolyForm-Noncommercial-1.0.0",
    "polyform-small-business-1.0.0": "PolyForm-Small-Business-1.0.0", "polyform-shield-1.0.0": "PolyForm-Shield-1.0.0",
    "fsl-1.1-alv2": "FSL-1.1-ALv2", "fsl-1.1-apache-2.0": "FSL-1.1-ALv2", "licenseref-fsl-1.1-apache-2.0": "FSL-1.1-ALv2",
    "functional source license, version 1.1, apache 2.0 future license": "FSL-1.1-ALv2", "fsl-1.1-mit": "FSL-1.1-MIT",
    "licenseref-fsl-1.1-mit": "FSL-1.1-MIT",
}
MENTION = re.compile(r"(?i)\b(MIT|Apache[- ]?(License,? )?(Version )?2(\.0)?|BSD[- ][23][- ]Clause|A?GPL-?v?[23](\.0)?(-only|-or-later)?|"
                     r"LGPL-?v?[23](\.[01])?|MPL-?2\.0|CC[- ]BY(-NC)?(-SA)?[- ]4\.0|CC0(-1\.0)?|Unlicense|ISC|BUSL-1\.1|"
                     r"Elastic-2\.0|PolyForm[- ](Noncommercial|Small[- ]Business|Shield)(-1\.0\.0)?|"
                     r"FSL-1\.1-(ALv2|MIT|Apache-2\.0))\b")


def mentioned(text: str) -> set[str]:
    """SPDX ids a prose section names. An FSL licence names its future licence (Apache 2.0 or MIT)
    in the same breath; that is part of FSL, not a second licence."""
    ids = {canon(m.group(0)) for m in MENTION.finditer(text)} - {None}
    if re.search(r"(?i)functional source license|\bFSL-1\.1", text):
        ids.add("FSL-1.1-MIT" if re.search(r"(?i)MIT Future License|FSL-1\.1-MIT", text) else "FSL-1.1-ALv2")
        ids -= {"Apache-2.0", "MIT"}
    return ids
CLASSIFIER = re.compile(r"License :: (?:OSI Approved :: )?([^\"'\n]+)")


def canon(name: str) -> str | None:
    s = re.sub(r"\s+", " ", name.strip().strip("'\"").lower())
    if s in ALIASES:
        return ALIASES[s]
    s2 = s.replace(" ", "-")
    for k, v in ALIASES.items():
        if s2 == k.replace(" ", "-"):
            return v
    if re.fullmatch(r"a?gpl-?v?3.*", s2):
        return "AGPL-3.0" if s2.startswith("a") else "GPL-3.0"
    if re.fullmatch(r"apache.*2.*", s2):
        return "Apache-2.0"
    if re.fullmatch(r"bsd-?3.*", s2):
        return "BSD-3-Clause"
    if re.fullmatch(r"cc-?by-?4.*", s2):
        return "CC-BY-4.0"
    if re.fullmatch(r"polyform-noncommercial.*", s2):
        return "PolyForm-Noncommercial-1.0.0"
    return None


def identify(text: str) -> str | None:
    m = re.search(r"SPDX-License-Identifier:\s*([\w.+-]+)", text)
    if m:
        return canon(m.group(1)) or m.group(1)
    for spdx, pats in SIGNATURES:
        if all(re.search(p, text, re.I) for p in pats):
            return spdx
    if re.search(r"(?i)all rights reserved", text) and not re.search(r"(?i)permission is hereby granted", text):
        return "LicenseRef-Proprietary"
    return None


def readme_licence_section(text: str) -> str:
    m = re.search(r"(?ims)^#{1,3}\s*licen[cs]e\b.*?(?=^#{1,3}\s|\Z)", text)
    return m.group(0) if m else ""


def declared(repo: Repo) -> list[tuple[str, str]]:
    """(where, canonical id or 'unrecognised: raw')."""
    out = []

    def add(where, raw):
        c = canon(raw)
        out.append((where, c or f"unrecognised: {raw.strip()[:60]}"))
    if repo.exists("pyproject.toml"):
        t = repo.text("pyproject.toml") or ""
        try:
            import tomllib
            data = tomllib.loads(t)
            lic = data.get("project", {}).get("license") or data.get("tool", {}).get("poetry", {}).get("license")
            if isinstance(lic, dict):
                lic = lic.get("text") or ""
                if lic and len(lic) > 80:
                    lic = identify(lic) or ""
            if lic:
                for part in re.split(r"\s+(?:OR|AND)\s+", str(lic)):
                    add("pyproject.toml", part.strip("() "))
            for cl in data.get("project", {}).get("classifiers", []):
                m = CLASSIFIER.search(cl)
                if m:
                    add("pyproject.toml classifier", m.group(1))
        except Exception as e:  # noqa: BLE001 - a broken pyproject is a finding, not a crash
            out.append(("pyproject.toml", f"unrecognised: unparseable ({type(e).__name__})"))
    if repo.exists("setup.cfg"):
        m = re.search(r"(?m)^license\s*=\s*(.+)$", repo.text("setup.cfg") or "")
        if m:
            add("setup.cfg", m.group(1))
    if repo.exists("setup.py"):
        m = re.search(r"license\s*=\s*['\"]([^'\"]+)['\"]", repo.text("setup.py") or "")
        if m:
            add("setup.py", m.group(1))
    for pj in [f for f in repo.tracked() if PurePosixPath(f).name == "package.json" and f.count("/") <= 1]:
        try:
            data = json.loads(repo.text(pj) or "{}")
        except json.JSONDecodeError:
            continue
        if data.get("private") is True and not data.get("license"):
            continue
        lic = data.get("license")
        if isinstance(lic, str) and lic and lic.upper() != "UNLICENSED":
            for part in re.split(r"\s+(?:OR|AND)\s+", lic):
                add(pj, part.strip("() "))
    if repo.exists("Cargo.toml"):
        m = re.search(r"(?m)^license\s*=\s*\"([^\"]+)\"", repo.text("Cargo.toml") or "")
        if m:
            for part in re.split(r"\s+(?:OR|AND)\s+|/", m.group(1)):
                add("Cargo.toml", part)
    if repo.exists("CITATION.cff"):
        m = re.search(r"(?m)^license:\s*['\"]?([^'\"\n]+)", repo.text("CITATION.cff") or "")
        if m:
            add("CITATION.cff", m.group(1))
    if repo.exists(".zenodo.json"):
        try:
            z = json.loads(repo.text(".zenodo.json") or "{}")
            lic = z.get("license")
            if isinstance(lic, dict):
                lic = lic.get("id")
            if lic:
                add(".zenodo.json", lic)
        except json.JSONDecodeError:
            out.append((".zenodo.json", "unrecognised: unparseable"))
    if repo.exists("README.md"):
        sec = readme_licence_section(repo.text("README.md") or "")
        ids = mentioned(sec)
        for i in sorted(ids):
            out.append(("README.md License section", i))
    if repo.exists("NOTICE") or repo.exists("NOTICE.md"):
        name = "NOTICE" if repo.exists("NOTICE") else "NOTICE.md"
        ids = mentioned(repo.text(name) or "")
        for i in sorted(ids):
            out.append((name, i))
    return out


def zenodo_licences(repo: Repo) -> list[tuple[str, str]]:
    # Only the code's OWN record: CITATION.cff's top-level doi. A README often cites the paper the code
    # reproduces, whose record carries the paper's licence (CC-BY), not the code's.
    dois = set()
    if repo.exists("CITATION.cff"):
        dois |= set(re.findall(r"(?m)^doi:\s*['\"]?10\.5281/zenodo\.(\d+)", repo.text("CITATION.cff") or ""))
    out = []
    for recid in sorted(dois):
        url = f"https://zenodo.org/api/records/{recid}"
        try:
            with urllib.request.urlopen(urllib.request.Request(url, headers={"Accept": "application/json"}), timeout=20) as resp:  # nosec B310  (fixed https host)
                data = json.loads(resp.read())
        except urllib.error.HTTPError as e:
            out.append((f"zenodo {recid}", f"gone: HTTP {e.code}" if e.code in (404, 410) else f"error: HTTP {e.code}"))
            continue
        except OSError as e:
            out.append((f"zenodo {recid}", f"error: {e}"))
            continue
        lic = (data.get("metadata") or {}).get("license") or {}
        raw = lic.get("id") if isinstance(lic, dict) else str(lic)
        out.append((f"zenodo record {recid}", canon(raw or "") or f"unrecognised: {raw}"))
    return out


def history(repo: Repo, path: str) -> list[tuple[str, str, str | None]]:
    """(commit, date, licence id) per change to the licence file, oldest first."""
    try:
        log = repo.git("log", "--follow", "--format=%H %cs", "--", path)
    except RuntimeError:
        return []
    rows = []
    for line in reversed(log.splitlines()):
        sha, _, date = line.partition(" ")
        try:
            body = repo.git("show", f"{sha}:{path}", check=True)
        except RuntimeError:
            body = ""
        rows.append((sha, date, identify(body) if body else None))
    return rows


def run(repo: Repo, opts) -> Result:
    r = Result("licence", "Licence: one file, consistent with README, metadata, NOTICE and Zenodo; dated note on change")
    roots = [f for f in repo.all_tracked() if "/" not in f and FILE_RE.match(f)]
    if not roots:
        r.add(BLOCK, "LIC-1: no licence file at the repo root; a public repo without one is all-rights-reserved", key="none")
        return r
    ids = {}
    for f in roots:
        i = identify(repo.text(f) or "")
        ids[f] = i
        if not i:
            r.add(BLOCK, f"LIC-1: cannot identify the licence in {f}; add an 'SPDX-License-Identifier: <id>' line", f,
                  key=f"unknown|{f}")
    file_ids = {i for i in ids.values() if i}
    # REUSE layout: LICENSES/<SPDX-id>.txt declares a licence that covers part of the repo
    reuse_ids = {canon(PurePosixPath(f).stem) or PurePosixPath(f).stem for f in repo.all_tracked()
                 if f.startswith("LICENSES/") and f.count("/") == 1}
    if reuse_ids:
        r.notes.append("REUSE LICENSES/: " + ", ".join(sorted(reuse_ids)))
    if len(roots) > 1 and len(file_ids) > 1:
        readme = repo.text("README.md") or ""
        expr = re.search(r"(?i)\b([\w.-]+)\s+(OR|AND)\s+([\w.-]+)\b", readme_licence_section(readme))
        if not expr:
            r.add(BLOCK, f"LIC-1: {len(roots)} licence files ({', '.join(roots)}) and the README states no SPDX "
                  "expression ('MIT OR Apache-2.0') joining them", key="multi")
    elif len(roots) > 1:
        r.add(WARN, f"LIC-1: {len(roots)} licence files with the same licence ({', '.join(roots)}); keep one", key="dupe")
    decl = declared(repo)
    if getattr(opts, "online", True) and not getattr(opts, "offline", False):
        z = zenodo_licences(repo)
        for where, val in z:
            if val.startswith("error:"):
                r.cannot(f"{where}: {val}")
            elif val.startswith("gone:"):
                r.add(WARN, f"LIC-2: CITATION.cff cites {where}, which no longer resolves ({val[6:]}); cite the concept DOI",
                      "CITATION.cff", key=f"gone|{where}")
        decl += [d for d in z if not d[1].startswith(("error:", "gone:"))]
    for where, val in decl:
        if val.startswith("unrecognised"):
            r.add(BLOCK, f"LIC-2: {where} states a licence the gate cannot map to SPDX ({val[14:]}); use an SPDX id",
                  where.split()[0], key=f"unrec|{where}")
        elif file_ids and val not in file_ids | reuse_ids:
            hint = ""
            if val.startswith("CC-") or val == "CC0-1.0":
                hint = (f". If part of the repo (a paper, data, docs) is under {val}, make the split explicit: add "
                        f"LICENSES/{val}.txt (REUSE layout) and say in the README which paths it covers")
            r.add(BLOCK, f"LIC-2: {where} says {val}, the licence file says {', '.join(sorted(file_ids))}{hint}",
                  where.split()[0], key=f"mismatch|{where}|{val}")
    if not any(w.startswith("README") for w, _ in decl):
        r.add(WARN, "LIC-2: the README's License section names no licence", "README.md", key="readme-none")
    today = dt.date.fromisoformat(getattr(opts, "today", None) or dt.date.today().isoformat())
    for f in roots:
        rows = history(repo, f)
        changes = [(sha, date, i) for (sha, date, i), prev in zip(rows[1:], rows[:-1]) if i != prev[2]]
        recent = [c for c in changes if (today - dt.date.fromisoformat(c[1])).days <= 90]
        notes_text = "\n".join(repo.text(n) or "" for n in ("README.md", "CHANGELOG.md", "LICENSE-CHANGES.md", "NOTICE")
                               if repo.exists(n))
        for sha, date, i in recent:
            ok = any(re.search(r"(?i)licen[cs]e", line) and any(d >= date for d in re.findall(r"20\d\d-[01]\d-[0-3]\d", line))
                     for line in notes_text.splitlines())
            if not ok:
                r.add(BLOCK, f"LIC-3: {f} changed to {i or 'an unidentified licence'} on {date} ({sha[:10]}) with no dated "
                      "note (README, CHANGELOG.md or LICENSE-CHANGES.md). A licence change also needs Cristian's approval",
                      f, key=f"change|{sha}")
        if len(recent) > 1:
            r.add(WARN, f"LIC-4: {f} changed licence {len(recent)} times in 90 days", f, key=f"churn|{f}")
    r.notes.append("licence file(s): " + ", ".join(f"{k}={v}" for k, v in ids.items()))
    return r
