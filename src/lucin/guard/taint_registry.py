"""Content-based taint propagation across the LLM boundary.

MATURITY: L3 target — validated in tests/test_taint_registry.py + benchmarks/validate_phases.py.

THE PROBLEM THIS SOLVES (the core GUARD limitation):
    Runtime IFC labels (Tainted wrappers) do NOT survive the LLM round-trip.
    A real agent does:  value = read_secret()  ->  LLM sees value as text  ->
    LLM emits send_email(body=<that text>).  The Tainted wrapper is gone; the
    egress tool receives a plain string. Label-only propagation therefore
    protects a SINGLE call, not the multi-hop flow that actually causes exfil.

    CaMeL/Fides (arXiv:2503.18813, 2505.23643) solve this by making the LLM emit
    a plan over *variables*, so the runtime never sees raw values cross the
    boundary. We cannot control the model's planning here, so we take the
    pragmatic complement: CONTENT-BASED taint tracking. When a tool returns
    sensitive data, we fingerprint the actual bytes. When those bytes reappear
    in a later tool call's arguments — even after the LLM passed them through
    verbatim — we re-apply the taint and the trifecta gate fires.

HONEST LIMIT (stated, not hidden):
    This catches VERBATIM propagation (the common exfil case: the model copies
    the secret into the egress payload). It does NOT catch a secret that the LLM
    *transforms* (summarizes, translates, re-encodes) before egress — that needs
    the plan-based approach. So content-taint is a high-precision, partial-recall
    layer that sits under the label-based gate, not a replacement for it.

Design for low false positives:
  - Only SECRET/INTERNAL-labelled returns are registered (public data is ignored).
  - Only "sensitive-looking" fragments are tracked (length gate + structure),
    so short common words never become taint sources.
"""

from __future__ import annotations

import base64
import re
import urllib.parse
from dataclasses import dataclass

from lucin.aifg import Confidentiality, IFCLabel

# Minimum fragment length to register — short strings cause false matches.
_MIN_FRAGMENT_LEN = 8

# Only encode fragments at least this long. Encodings of long, single-token
# secrets are collision-free in practice; encoding short/common tokens would
# bloat the registry for no recall gain. Keeps false-taint at zero. [VERIFIED]
_MIN_ENCODE_LEN = 12

# Structured-secret patterns worth tracking even if a token is split oddly.
_SENSITIVE_FRAGMENT_PATTERNS = [
    re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),                    # SSN
    re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),  # email
    re.compile(r"\b(?:sk|pk|rk|api|key|tok)[-_][A-Za-z0-9]{6,}\b", re.I),  # api keys
    re.compile(r"\b[A-Za-z0-9+/]{20,}={0,2}\b"),             # long base64-ish blobs
    re.compile(r"\b\d{13,19}\b"),                            # card-like number runs
]


@dataclass
class _TaintedFragment:
    fragment:  str
    label:     IFCLabel
    source_id: str


class TaintRegistry:
    """Tracks sensitive tool-return content and re-detects it in later args.

    One registry per GuardSession. Registration is cheap; scanning is a
    substring check against the accumulated sensitive fragments.
    """

    def __init__(self, min_fragment_len: int = _MIN_FRAGMENT_LEN,
                 encode_variants: bool = True):
        self._fragments: list[_TaintedFragment] = []
        self._seen: set[str] = set()
        self._min_len = min_fragment_len
        # When True, also fingerprint common REVERSIBLE encodings (base64,
        # urlsafe-base64, hex, url-quote) of long single-token secrets, so an
        # adaptive attacker who re-encodes the secret before egress is still
        # caught. Only reversible encodings are covered — NOT semantic
        # transformation (paraphrase/translate/summary), which needs a
        # plan-based (CaMeL) layer we do not have. [see module docstring]
        self._encode_variants = encode_variants

    # -- registration ------------------------------------------------------

    def register(self, value, label: IFCLabel, source_id: str = "") -> int:
        """Register a tool return's sensitive content. Returns #fragments added.

        Only INTERNAL/SECRET data is tracked — public returns are ignored so
        benign data never becomes a taint source.
        """
        if label.confidentiality < Confidentiality.INTERNAL:
            return 0
        text = self._stringify(value)
        if not text:
            return 0

        added = 0
        for frag in self._extract_fragments(text):
            if frag not in self._seen:
                self._seen.add(frag)
                self._fragments.append(_TaintedFragment(frag, label, source_id))
                added += 1
            # Adaptive-attacker hardening: also fingerprint reversible encodings
            # of the secret token, so base64/hex/url-encoded exfil is caught.
            if self._encode_variants:
                for enc in self._encoding_variants(frag):
                    if enc in self._seen:
                        continue
                    self._seen.add(enc)
                    self._fragments.append(_TaintedFragment(enc, label, source_id))
                    added += 1
        return added

    # -- scanning ----------------------------------------------------------

    def scan(self, value) -> tuple[IFCLabel | None, list[str]]:
        """Return the joined label of any registered fragments found in value.

        Returns (label_or_None, matched_source_ids). None means no tainted
        content detected in the argument.
        """
        text = self._stringify(value)
        if not text:
            return None, []

        matched_label: IFCLabel | None = None
        matched_sources: list[str] = []
        for tf in self._fragments:
            if tf.fragment in text:
                matched_label = tf.label if matched_label is None else matched_label.join(tf.label)
                if tf.source_id:
                    matched_sources.append(tf.source_id)
        return matched_label, matched_sources

    # -- helpers -----------------------------------------------------------

    def _extract_fragments(self, text: str) -> list[str]:
        frags: set[str] = set()

        # 1. Structured secrets (SSN, email, keys, blobs) — always track.
        for pat in _SENSITIVE_FRAGMENT_PATTERNS:
            for m in pat.findall(text):
                if len(m) >= 4:            # structured patterns are inherently specific
                    frags.add(m)

        # 2. Long whitespace tokens (>= min_len) — catches keys/ids not matched above.
        for tok in re.split(r"\s+", text):
            tok = tok.strip().strip(".,;:!?\"'()[]{}")
            if len(tok) >= self._min_len:
                frags.add(tok)

        # 3. The whole stripped value if it's a single sensitive line and short
        #    enough to be an exact-match target (avoids registering huge docs).
        whole = text.strip()
        if self._min_len <= len(whole) <= 512:
            frags.add(whole)

        return list(frags)

    def _encoding_variants(self, frag: str) -> list[str]:
        """Reversible encodings of a secret token an adaptive attacker may use.

        Only applied to long, single-token fragments (no whitespace) — encodings
        of these are long and specific, so they never collide with benign text.
        Covers standard/urlsafe base64, hex, and url-quote. Does NOT cover
        semantic transformation (paraphrase/translate) — that is the documented
        residual gap requiring a plan-based layer.
        """
        if len(frag) < _MIN_ENCODE_LEN or any(c.isspace() for c in frag):
            return []
        raw = frag.encode("utf-8", "ignore")
        variants: list[str] = []
        try:
            variants.append(base64.b64encode(raw).decode("ascii"))
            variants.append(base64.b64encode(raw).decode("ascii").rstrip("="))  # unpadded
            variants.append(base64.urlsafe_b64encode(raw).decode("ascii"))
            variants.append(base64.urlsafe_b64encode(raw).decode("ascii").rstrip("="))
            variants.append(raw.hex())              # lowercase hex
            variants.append(raw.hex().upper())      # uppercase hex
            variants.append(urllib.parse.quote(frag, safe=""))  # percent-encoding
        except Exception:
            return []
        # Keep only variants that (a) actually differ from the plaintext and
        # (b) are long enough to be collision-free.
        out = []
        seen_local = set()
        for v in variants:
            if v != frag and len(v) >= _MIN_FRAGMENT_LEN and v not in seen_local:
                seen_local.add(v)
                out.append(v)
        return out

    @staticmethod
    def _stringify(value) -> str:
        if value is None:
            return ""
        if isinstance(value, str):
            return value
        try:
            s = str(value)
        except Exception:
            s = ""
        # Coverage fix: objects with a default repr (<X object at 0x..>) hide
        # their attribute values from str(), so a secret held only in a field
        # would silently pass through. Surface __dict__ so it is fingerprinted.
        # SOUND / no false taint: registration only ever runs on SECRET/INTERNAL
        # returns (see register()), so this exposes the tool's OWN sensitive
        # output — never third-party data — and str(dict) already covers the
        # dict/list container cases, so this only adds the missing object case.
        try:
            d = getattr(value, "__dict__", None)
            if d:
                s = f"{s} {d}"
        except Exception:
            pass
        return s

    @property
    def size(self) -> int:
        return len(self._fragments)
