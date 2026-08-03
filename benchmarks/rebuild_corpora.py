#!/usr/bin/env python3
"""Recreate every corpus directory too large to transfer, from committed pin files.

    benchmarks/agentzoo_corpus/   4.6 GB   81 repos   <- pinned by THIS script
    benchmarks/corpus/            3.6 GB   56 repos   <- already pinned (corpus_shas.json)
    benchmarks/realvuln_corpus/   235 MB   26 repos   <- already pinned (RealVuln commit_sha)

Together that is 8.4 GB of the repo's 8.5 GB. Everything else is under 2 MB per file and
transfers normally; `venv/` (291 MB) rebuilds from pyproject.toml.

WHY THIS NEEDS TO BE MORE THAN A DOWNLOAD LOOP
----------------------------------------------
`agentzoo_precision.py` fetches `archive/refs/heads/{main,master}.zip` — a MOVING branch
head — and its `download_records` recorded `branch: "cached"`, i.e. no version at all.
So the exact bytes that our 73 holdout verdicts were adjudicated against were never
recorded anywhere.

That matters because a verdict key is `repo::file::LINE::rule`. If upstream adds an import
above a flagged call, the line moves, the key stops matching, and `phase_b()` silently drops
that finding from the denominator (this is the same silent-skip that produced the withdrawn
58%). A naive "re-download main" script would therefore appear to work while quietly
changing the published precision.

So this script does three things, and the order is the point:

  --pin      Record the CURRENT on-disk state: the resolved upstream SHA for each repo,
             plus a sha256 of every .py file the harness actually scans. RUN THIS BEFORE
             DELETING ANYTHING — after deletion the ground truth is gone for good.
  --verify   Compare on-disk state against the pin file, per repo and per file, and call
             out drift in the files that carry adjudicated verdicts specifically.
  --rebuild  Re-fetch by SHA (not by branch), restore the original directory layout so
             existing keys and paths stay valid, then verify and report honestly.

The other two corpora were already reproducible and are driven, not reimplemented:
`benchmarks/corpus/` is pinned 56/56 in `corpus_shas.json` and fetched by
`fetch_corpus.py` via `/archive/<sha>.zip`; RealVuln ships `commit_sha` per target and
`realvuln_eval.py:261 fetch_target()` fetches exactly that commit.

USAGE
-----
    # BEFORE deleting the corpora on the old machine:
    venv/bin/python benchmarks/rebuild_corpora.py --pin
    #   -> writes benchmarks/agentzoo_pins.json  (COMMIT THIS; it is ~100 KB)

    # On the new machine:
    venv/bin/python benchmarks/rebuild_corpora.py --rebuild            # all three corpora
    venv/bin/python benchmarks/rebuild_corpora.py --rebuild agentzoo   # just one
    venv/bin/python benchmarks/rebuild_corpora.py --verify             # check without fetching

Expect roughly 8.4 GB of download. Re-running is safe and cheap: present repos are skipped
unless --force.

Network notes for this environment: `git clone` is broken here (global config rewrites
HTTPS->SSH, port 22 blocked), so everything goes over plain HTTPS. SHA resolution uses git's
smart-HTTP ref advertisement rather than the REST API, because the unauthenticated API allows
60 requests/hour and this needs 81 -- an API-based pin silently left 46 of 81 repos
unreproducible on the first attempt. No token required.
"""

from __future__ import annotations

import argparse
import concurrent.futures as cf
import hashlib
import json
import os
import shutil
import ssl
import sys
import time
import urllib.error
import urllib.request
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BENCH = ROOT / "benchmarks"
AGENTZOO_DIR = BENCH / "agentzoo_corpus"
REALVULN_DIR = BENCH / "realvuln_corpus"
PIN_FILE = BENCH / "agentzoo_pins.json"

DL_TIMEOUT = 180
API = "https://api.github.com"
UA = {"User-Agent": "lucin-rebuild-corpora/1.0"}

sys.path.insert(0, str(BENCH))


def _ssl_ctx():
    """Mirror agentzoo_precision's context so corporate TLS behaves identically."""
    try:
        from agentzoo_precision import _ssl_ctx as up
        return up()
    except Exception:
        return ssl.create_default_context()


def _auth_headers() -> dict:
    h = dict(UA)
    tok = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if tok:
        h["Authorization"] = f"Bearer {tok}"
    return h


def _select_py_files(root: Path) -> list[Path]:
    """The exact file set the precision harness scans — hashing anything else is noise."""
    from agentzoo_precision import _select_py_files as up
    return up(root)


def _repo_list() -> list[str]:
    from agentzoo_precision import REPOS
    return list(REPOS)


def _safe_name(owner_repo: str) -> str:
    from agentzoo_precision import _safe_name as up
    return up(owner_repo)


def _sha256_file(p: Path) -> str:
    h = hashlib.sha256()
    with p.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _adjudicated_files() -> dict[str, set[str]]:
    """repo -> {relative file paths that carry a verdict}.

    These are the files whose CONTENT must not drift, because a line shift in one of them
    silently voids a verdict and moves the published precision.
    """
    out: dict[str, set[str]] = {}
    try:
        import agentzoo_precision as ap
        keyed = set(ap.HOLDOUT_ADJUDICATIONS) | set(ap.TUNING_ADJUDICATIONS)
    except Exception:
        return out
    for key in keyed:
        parts = key.split("::")
        if len(parts) >= 2:
            out.setdefault(parts[0], set()).add(parts[1])
    return out


# ---------------------------------------------------------------------------
# --pin
# ---------------------------------------------------------------------------

def _resolve_head_sha(owner_repo: str,
                      prefer_branch: str | None = None) -> tuple[str | None, str | None]:
    """Head SHA + the ref it came from, or (None, reason).

    `prefer_branch` is the branch the corpus was ORIGINALLY downloaded from, recovered from
    the extracted directory name (`NeMo-Agent-Toolkit-main` -> `main`). It must win over the
    repo's current default branch, because those diverge: NVIDIA/NeMo-Agent-Toolkit was
    downloaded from `main` but has since made `develop` its default, and pinning `develop`
    fetched genuinely different code (82 files added, 82 removed) on rebuild. Pinning the
    default branch instead of the downloaded one is a silent corpus swap.

    Uses git's smart-HTTP advertisement (`/info/refs?service=git-upload-pack`) rather than
    the REST API. Deliberate: the unauthenticated REST API allows 60 requests/hour and this
    needs 81, so an API-based pin silently failed on 46 of 81 repos and left them
    unreproducible. The git endpoint is unauthenticated and not rate-limited, and it also
    reports the symref for HEAD, so we learn the real default branch instead of guessing
    "main or master" from a directory name.

    `git clone` itself is unusable in this environment (global config rewrites HTTPS->SSH,
    port 22 blocked) but this is a plain HTTPS GET, so it works.
    """
    url = f"https://github.com/{owner_repo}.git/info/refs?service=git-upload-pack"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "git/2.39"})
        with urllib.request.urlopen(req, timeout=45, context=_ssl_ctx()) as r:
            raw = r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return None, f"HTTP {e.code}"
    except Exception as e:
        return None, f"{type(e).__name__}: {e}"

    head_ref, refs = None, {}
    for line in raw.split("\n"):
        if "symref=HEAD:" in line:
            head_ref = line.split("symref=HEAD:")[1].split()[0].split("\x00")[0]
        parts = line.strip().split()
        for i, tok in enumerate(parts):
            cand = tok[-40:]
            if len(cand) == 40 and all(c in "0123456789abcdef" for c in cand):
                if i + 1 < len(parts) and parts[i + 1].startswith("refs/heads/"):
                    refs[parts[i + 1]] = cand
    if prefer_branch:
        want = f"refs/heads/{prefer_branch}"
        if want in refs:
            return refs[want], want
    if head_ref and head_ref in refs:
        return refs[head_ref], head_ref
    for fallback in ("refs/heads/main", "refs/heads/master"):
        if fallback in refs:
            return refs[fallback], fallback
    return None, "no matching ref advertised"


def cmd_pin() -> int:
    if not AGENTZOO_DIR.exists():
        print(f"  agentzoo_corpus/ not present at {AGENTZOO_DIR} — nothing to pin.")
        print("  --pin must run on the machine that still HAS the corpus.")
        return 2

    repos = _repo_list()
    adj = _adjudicated_files()
    print(f"  pinning {len(repos)} repos from {AGENTZOO_DIR}")
    print(f"  {sum(len(v) for v in adj.values())} files carry a verdict and will be "
          f"flagged as adjudication-critical\n")

    # Recover the branch each repo was actually downloaded from, so we pin THAT ref rather
    # than whatever the repo's default branch happens to be today (see _resolve_head_sha).
    orig_branch: dict[str, str | None] = {}
    for repo in repos:
        ed = AGENTZOO_DIR / _safe_name(repo)
        subs = sorted((p for p in ed.iterdir() if p.is_dir()),
                      key=lambda p: p.name) if ed.exists() else []
        orig_branch[repo] = subs[0].name.rsplit("-", 1)[-1] if subs and "-" in subs[0].name else None

    # Resolve SHAs concurrently (network-bound -> threads are the right tool here).
    with cf.ThreadPoolExecutor(max_workers=8) as ex:
        shas = dict(zip(repos, ex.map(lambda r: _resolve_head_sha(r, orig_branch.get(r)),
                                      repos)))

    pins, unresolved, missing = {}, [], []
    for i, repo in enumerate(repos, 1):
        safe = _safe_name(repo)
        extract_dir = AGENTZOO_DIR / safe
        subs = sorted((p for p in extract_dir.iterdir() if p.is_dir()),
                      key=lambda p: p.name) if extract_dir.exists() else []
        if not subs:
            missing.append(repo)
            continue
        root = subs[0]
        files = _select_py_files(root)
        crit = adj.get(repo, set())
        fh = {}
        for p in files:
            rel = str(p.relative_to(root))
            fh[rel] = _sha256_file(p)
        digest = hashlib.sha256(
            "".join(f"{k}:{fh[k]}" for k in sorted(fh)).encode()).hexdigest()
        sha, meta = shas.get(repo, (None, "not attempted"))
        if not sha:
            unresolved.append((repo, meta))
        pins[repo] = {
            "safe": safe,
            "root_name": root.name,          # e.g. "babyagi-main" — MUST be restored
            "head_sha": sha,
            "head_ref": meta if sha else None,
            "sha_resolve_error": None if sha else meta,
            "n_py_scanned": len(files),
            "corpus_digest": digest,
            "adjudication_critical": sorted(crit),
            "file_sha256": fh,
        }
        if i % 20 == 0 or i == len(repos):
            print(f"    [{i:3d}/{len(repos)}] {repo}")

    payload = {
        "_README": (
            "Pin manifest for benchmarks/agentzoo_corpus. head_sha is the upstream default "
            "branch head AT PIN TIME, which is NOT provably the state that was downloaded "
            "originally (the harness fetched a moving branch head and recorded no version). "
            "file_sha256 IS ground truth for what was scanned and adjudicated. After a "
            "rebuild, trust file_sha256 over head_sha: if they disagree, upstream moved "
            "between the original download and this pin, and any verdict on a changed file "
            "is void."
        ),
        "pinned_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "n_repos": len(pins),
        "repos_missing_on_disk": missing,
        "repos_with_unresolved_sha": [{"repo": r, "why": w} for r, w in unresolved],
        "pins": pins,
    }
    PIN_FILE.write_text(json.dumps(payload, indent=1, sort_keys=True))
    size_kb = PIN_FILE.stat().st_size // 1024
    print(f"\n  -> {PIN_FILE.relative_to(ROOT)} ({size_kb} KB, {len(pins)} repos)")
    print(f"     files hashed: {sum(p['n_py_scanned'] for p in pins.values())}")
    if missing:
        print(f"  WARNING {len(missing)} repo(s) absent on disk, not pinned: {missing[:4]}")
    if unresolved:
        print(f"  WARNING {len(unresolved)} repo(s) have NO resolved SHA — they can only be "
              f"re-fetched by branch, so their content is not guaranteed:")
        for r, w in unresolved[:6]:
            print(f"      {r}: {w}")
        if not (os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")):
            print("     Set GITHUB_TOKEN and re-run --pin to resolve these.")
    print("\n  COMMIT THIS FILE. It is the only record of what the verdicts were read against.")
    return 0


# ---------------------------------------------------------------------------
# --verify
# ---------------------------------------------------------------------------

def _verify_repo(repo: str, pin: dict) -> dict:
    extract_dir = AGENTZOO_DIR / pin["safe"]
    root = extract_dir / pin["root_name"]
    if not root.exists():
        subs = sorted((p for p in extract_dir.iterdir() if p.is_dir()),
                      key=lambda p: p.name) if extract_dir.exists() else []
        if not subs:
            return {"repo": repo, "status": "absent"}
        root = subs[0]
    files = {str(p.relative_to(root)): p for p in _select_py_files(root)}
    expected = pin["file_sha256"]
    changed, gone, added = [], [], []
    for rel, want in expected.items():
        p = files.get(rel)
        if p is None:
            gone.append(rel)
        elif _sha256_file(p) != want:
            changed.append(rel)
    added = [r for r in files if r not in expected]
    crit = set(pin.get("adjudication_critical") or [])
    crit_broken = sorted(crit & (set(changed) | set(gone)))
    return {
        "repo": repo,
        "status": "identical" if not (changed or gone) else "drifted",
        "changed": changed, "missing": gone, "added": added,
        "adjudication_critical_broken": crit_broken,
    }


def cmd_verify(quiet: bool = False) -> int:
    if not PIN_FILE.exists():
        print(f"  no pin file at {PIN_FILE.relative_to(ROOT)} — run --pin first "
              f"(on a machine that has the corpus).")
        return 2
    payload = json.loads(PIN_FILE.read_text())
    pins = payload["pins"]
    with cf.ThreadPoolExecutor(max_workers=8) as ex:
        results = list(ex.map(lambda kv: _verify_repo(*kv), pins.items()))

    identical = [r for r in results if r["status"] == "identical"]
    drifted = [r for r in results if r["status"] == "drifted"]
    absent = [r for r in results if r["status"] == "absent"]
    crit = [r for r in drifted if r["adjudication_critical_broken"]]

    print(f"\n  VERIFY agentzoo_corpus against {PIN_FILE.name} "
          f"(pinned {payload.get('pinned_at_utc')})")
    print(f"    identical : {len(identical)}/{len(pins)}")
    print(f"    drifted   : {len(drifted)}")
    print(f"    absent    : {len(absent)}")
    if absent and not quiet:
        for r in absent[:8]:
            print(f"        absent: {r['repo']}")
    if drifted and not quiet:
        for r in drifted[:12]:
            print(f"        {r['repo']}: {len(r['changed'])} changed, "
                  f"{len(r['missing'])} missing, {len(r['added'])} added")
    if crit:
        print(f"\n  *** {len(crit)} repo(s) drifted in a file that CARRIES A VERDICT. ***")
        for r in crit:
            for f in r["adjudication_critical_broken"][:4]:
                print(f"        {r['repo']}::{f}")
        print("      Verdicts on those files are VOID: the code adjudicated is not the code")
        print("      on disk. Re-adjudicate them, or exclude them, before quoting precision.")
        print("      Do NOT publish a precision figure computed over a drifted corpus.")
        return 1
    if drifted or absent:
        print("\n  Drift outside adjudicated files: precision keys are intact, but the")
        print("  population differs, so total finding counts may move.")
        return 1
    print("\n  PASS — corpus is byte-identical to the pinned state. Verdicts remain valid.")
    return 0


# ---------------------------------------------------------------------------
# --rebuild
# ---------------------------------------------------------------------------

def _fetch_zip(url: str) -> bytes:
    req = urllib.request.Request(url, headers=_auth_headers())
    with urllib.request.urlopen(req, timeout=DL_TIMEOUT, context=_ssl_ctx()) as r:
        return r.read()


def _rebuild_one(repo: str, pin: dict, force: bool) -> dict:
    safe, root_name, sha = pin["safe"], pin["root_name"], pin.get("head_sha")
    extract_dir = AGENTZOO_DIR / safe
    final_root = extract_dir / root_name
    if final_root.exists() and not force:
        return {"repo": repo, "status": "cached"}

    # By SHA when we have one (exact), else fall back to the branch implied by root_name
    # (e.g. "babyagi-main" -> "main"), which is NOT reproducible and is reported as such.
    attempts = []
    if sha:
        attempts.append(("sha", f"https://github.com/{repo}/archive/{sha}.zip"))
    branch = root_name.rsplit("-", 1)[-1] if "-" in root_name else "main"
    for b in dict.fromkeys([branch, "main", "master"]):
        attempts.append(("branch", f"https://github.com/{repo}/archive/refs/heads/{b}.zip"))

    tmp_zip = AGENTZOO_DIR / f".{safe}.partial.zip"
    for kind, url in attempts:
        try:
            tmp_zip.write_bytes(_fetch_zip(url))
        except urllib.error.HTTPError as e:
            if e.code == 404:
                continue
            return {"repo": repo, "status": "dl_error", "error": f"HTTP {e.code}"}
        except Exception as e:
            return {"repo": repo, "status": "dl_error", "error": f"{type(e).__name__}: {e}"}

        staging = AGENTZOO_DIR / f".{safe}.staging"
        shutil.rmtree(staging, ignore_errors=True)
        staging.mkdir(parents=True, exist_ok=True)
        try:
            with zipfile.ZipFile(tmp_zip) as z:
                z.extractall(staging)
        except Exception as e:
            shutil.rmtree(staging, ignore_errors=True)
            tmp_zip.unlink(missing_ok=True)
            return {"repo": repo, "status": "extract_error", "error": str(e)}
        tmp_zip.unlink(missing_ok=True)

        subs = sorted((p for p in staging.iterdir() if p.is_dir()), key=lambda p: p.name)
        if not subs:
            shutil.rmtree(staging, ignore_errors=True)
            continue
        # A SHA archive extracts to "<repo>-<sha>"; the pinned layout expects
        # "<repo>-<branch>". Restore the recorded name so every relative path, abs_path
        # and verdict key in the manifests keeps resolving.
        shutil.rmtree(extract_dir, ignore_errors=True)
        extract_dir.mkdir(parents=True, exist_ok=True)
        shutil.move(str(subs[0]), str(final_root))
        shutil.rmtree(staging, ignore_errors=True)
        return {"repo": repo, "status": "ok", "by": kind,
                "reproducible": kind == "sha"}

    return {"repo": repo, "status": "not_found"}


def cmd_rebuild(which: str, force: bool, jobs: int) -> int:
    rc = 0
    if which in ("agentzoo", "all"):
        if not PIN_FILE.exists():
            print(f"  MISSING {PIN_FILE.relative_to(ROOT)}.")
            print("  Without it a rebuild fetches moving branch heads and the 73 holdout")
            print("  verdicts cannot be trusted. Run --pin on the source machine first.")
            return 2
        payload = json.loads(PIN_FILE.read_text())
        pins = payload["pins"]
        AGENTZOO_DIR.mkdir(parents=True, exist_ok=True)
        print(f"  rebuilding agentzoo_corpus: {len(pins)} repos, {jobs} parallel "
              f"(network-bound, so threads)")
        done = []
        with cf.ThreadPoolExecutor(max_workers=jobs) as ex:
            futs = {ex.submit(_rebuild_one, r, p, force): r for r, p in pins.items()}
            for i, fut in enumerate(cf.as_completed(futs), 1):
                rec = fut.result()
                done.append(rec)
                if rec["status"] not in ("ok", "cached"):
                    print(f"    [{i:3d}] FAIL {rec['repo']}: {rec['status']} "
                          f"{rec.get('error','')}")
                elif i % 20 == 0 or i == len(pins):
                    print(f"    [{i:3d}/{len(pins)}]")
        ok = [r for r in done if r["status"] in ("ok", "cached")]
        by_branch = [r for r in done if r.get("by") == "branch"]
        bad = [r for r in done if r["status"] not in ("ok", "cached")]
        print(f"\n    fetched/cached: {len(ok)}/{len(pins)}   failed: {len(bad)}")
        if by_branch:
            print(f"    {len(by_branch)} fetched by BRANCH, not SHA — not reproducible:")
            for r in by_branch[:6]:
                print(f"        {r['repo']}")
        rc |= cmd_verify()

    if which in ("benign", "all"):
        print("\n  rebuilding benchmarks/corpus (benign; pinned 56/56 in corpus_shas.json)")
        shas = BENCH / "corpus_shas.json"
        if not shas.exists():
            print(f"    MISSING {shas.name} — cannot rebuild reproducibly.")
            rc |= 2
        else:
            n = len(json.loads(shas.read_text()).get("pins", {}))
            print(f"    {n} pinned SHAs; delegating to fetch_corpus.py (fetches /archive/<sha>.zip)")
            import subprocess
            r = subprocess.run([sys.executable, str(BENCH / "fetch_corpus.py")],
                               cwd=str(ROOT))
            if r.returncode != 0:
                print(f"    fetch_corpus.py exited {r.returncode}")
                rc |= 1
            else:
                chk = subprocess.run(
                    [sys.executable, str(BENCH / "pin_corpus_shas.py"), "--check"],
                    cwd=str(ROOT))
                if chk.returncode != 0:
                    print("    WARNING lockfile does not cover the corpus (see --check output)")
                    rc |= 1

    if which in ("realvuln", "all"):
        print("\n  rebuilding realvuln_corpus (already SHA-pinned by the benchmark itself)")
        try:
            import realvuln_eval as rv
            bench = rv.fetch_benchmark()
            print(f"    benchmark: {bench.get('status', bench)}")
            gts = rv.load_ground_truth() if hasattr(rv, "load_ground_truth") else None
            if gts:
                with cf.ThreadPoolExecutor(max_workers=min(8, jobs)) as ex:
                    recs = list(ex.map(rv.fetch_target, gts))
                okc = sum(1 for r in recs if r.get("status") in ("ok", "cached"))
                ver = sum(1 for r in recs if r.get("sha_verified"))
                print(f"    targets: {okc}/{len(recs)} present, {ver} SHA-verified")
                if ver < okc:
                    print(f"    WARNING {okc - ver} target(s) not SHA-verified")
                    rc |= 1
            else:
                print("    driving realvuln_eval.py directly instead:")
                print("      venv/bin/python benchmarks/realvuln_eval.py")
        except Exception as e:
            print(f"    could not drive realvuln_eval: {type(e).__name__}: {e}")
            print("      fall back to: venv/bin/python benchmarks/realvuln_eval.py")
            rc |= 1
    return rc


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Pin, verify and recreate the agentzoo/realvuln corpora.")
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--pin", action="store_true",
                   help="record current on-disk state (RUN BEFORE DELETING)")
    g.add_argument("--verify", action="store_true",
                   help="compare on-disk state against the pin file")
    g.add_argument("--rebuild", nargs="?", const="all",
                   choices=["all", "agentzoo", "benign", "realvuln"],
                   help="re-fetch from the pin file, then verify")
    ap.add_argument("--force", action="store_true", help="re-fetch even if present")
    ap.add_argument("--jobs", type=int, default=8, help="parallel fetches (default 8)")
    a = ap.parse_args()

    if a.pin:
        return cmd_pin()
    if a.verify:
        return cmd_verify()
    return cmd_rebuild(a.rebuild, a.force, a.jobs)


if __name__ == "__main__":
    sys.exit(main())
