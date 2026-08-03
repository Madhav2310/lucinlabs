"""GUARD admission gate on a REAL third-party prompt-injection corpus.

    python benchmarks/admission_real_corpus.py

Deterministic (NO LLM). Fetches the public HuggingFace corpus
`deepset/prompt-injections` (546 rows, features: text + label; label 1 =
injection, 0 = legitimate) via the HF datasets-server REST API, then runs every
string through the deterministic admission gate in guard/admission.py.

Reports, on the REAL corpus, NOT tuned to it (default gate settings):
  - injection detection / recall  = fraction of label==1 the gate catches
  - benign false-trigger rate     = fraction of label==0 the gate blocks

"Caught" is reported two ways for honesty:
  block-only          — the gate hard-blocks
  block + abstain     — abstain = "escalate to human", a softer catch

If the network/mirror is unreachable, the script says so and exits non-zero
(no silent fallback to author-written strings — those would not be third-party).
"""

from __future__ import annotations

import sys
from pathlib import Path

import httpx

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT / "src"))
from lucin.guard.admission import AdmissionGate

DATASET = "deepset/prompt-injections"
_ROWS_URL = "https://datasets-server.huggingface.co/rows"


def _resolve_verify() -> object:
    """Pick a CA bundle that works behind a TLS-intercepting proxy, if any.

    Order: LUCIN_LLM_CA_BUNDLE env var (optionally sourced from an
    env.properties file via LUCIN_LLM_ENV_FILE), then certifi, then default.
    """
    import os

    candidates: list[str] = []
    if os.environ.get("LUCIN_LLM_CA_BUNDLE"):
        candidates.append(os.environ["LUCIN_LLM_CA_BUNDLE"])
    envp = Path(os.environ.get("LUCIN_LLM_ENV_FILE", ""))
    if envp.exists():
        for line in envp.read_text().splitlines():
            line = line.strip()
            if line.startswith("LUCIN_LLM_CA_BUNDLE") and "=" in line:
                candidates.append(line.split("=", 1)[1].strip())
    try:
        import certifi
        candidates.append(certifi.where())
    except ImportError:
        pass
    for c in candidates:
        if c and Path(c).exists():
            return c
    return True


def fetch_corpus(split: str = "train", timeout: float = 30.0) -> list[tuple[str, int]]:
    """Pull all rows of the corpus via the HF datasets-server (paginated)."""
    client = httpx.Client(timeout=timeout, verify=_resolve_verify())
    out: list[tuple[str, int]] = []
    offset, page = 0, 100
    total = None
    while True:
        r = client.get(_ROWS_URL, params={
            "dataset": DATASET, "config": "default", "split": split,
            "offset": offset, "length": page,
        })
        r.raise_for_status()
        data = r.json()
        total = data.get("num_rows_total", total)
        rows = data.get("rows", [])
        if not rows:
            break
        for item in rows:
            row = item["row"]
            out.append((row["text"], int(row["label"])))
        offset += page
        if total is not None and offset >= total:
            break
    return out


def _bucket(gate: AdmissionGate, text: str) -> str:
    d = gate.admit(text)
    if d.abstain:
        return "abstain"
    return "block" if not d.allow else "allow"


def main() -> int:
    print("=" * 72)
    print("GUARD admission gate — REAL third-party corpus (deterministic, no LLM)")
    print("=" * 72)
    try:
        corpus = fetch_corpus()
    except (httpx.HTTPError, Exception) as e:  # noqa: BLE001
        print(f"\nNETWORK/MIRROR UNREACHABLE: {type(e).__name__}: {e}")
        print(f"Could not fetch third-party corpus '{DATASET}'. Aborting rather than")
        print("substituting author-written strings (those are not external truth).")
        return 2

    injections = [t for t, y in corpus if y == 1]
    benign = [t for t, y in corpus if y == 0]
    print(f"\nCorpus source: HuggingFace `{DATASET}` (train split)")
    print(f"  total rows: {len(corpus)}   injections(label=1): {len(injections)}"
          f"   benign(label=0): {len(benign)}")

    gate = AdmissionGate()   # DEFAULT settings — not tuned to this corpus

    inj = {"allow": 0, "block": 0, "abstain": 0}
    ben = {"allow": 0, "block": 0, "abstain": 0}
    for t in injections:
        inj[_bucket(gate, t)] += 1
    for t in benign:
        ben[_bucket(gate, t)] += 1

    n_i, n_b = len(injections), len(benign)
    det_block = inj["block"] / n_i
    det_soft = (inj["block"] + inj["abstain"]) / n_i
    fp_block = ben["block"] / n_b
    fp_soft = (ben["block"] + ben["abstain"]) / n_b

    print("\nINJECTIONS (label=1):")
    print(f"  block {inj['block']}  abstain {inj['abstain']}  allow(MISS) {inj['allow']}")
    print(f"  recall  block-only:       {det_block:.1%}")
    print(f"  recall  block+abstain:    {det_soft:.1%}")
    print("\nBENIGN (label=0):")
    print(f"  allow {ben['allow']}  abstain {ben['abstain']}  block(FP) {ben['block']}")
    print(f"  false-trigger block-only: {fp_block:.1%}   (want low)")
    print(f"  false-trigger block+abstain: {fp_soft:.1%}  (incl. escalation friction)")
    print("=" * 72)
    print("Honest note: the default classifier is REGEX (guard/admission.py). It is")
    print("table-stakes triage UNDER the deterministic IFC gate, not a trained model.")
    print("Numbers above are on the untouched third-party corpus; gate is at defaults.")
    print("=" * 72)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
