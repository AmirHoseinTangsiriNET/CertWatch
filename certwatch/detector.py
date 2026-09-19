"""Brand-impersonation detection. Pure logic - no network, no I/O."""
from __future__ import annotations

import math
import re
import unicodedata
from collections import Counter
from dataclasses import dataclass
from typing import Iterable, List, Optional, Set, Tuple

import tldextract

from .models import Finding

# Offline: use the Public Suffix List snapshot bundled with tldextract.
_TLD = tldextract.TLDExtract(
    suffix_list_urls=(), cache_dir=None, include_psl_private_domains=True
)

PHISHING_KEYWORDS = (
    "login", "logon", "signin", "secure", "security", "auth", "verify",
    "verification", "account", "update", "support", "helpdesk", "wallet",
    "payment", "billing", "confirm", "online", "portal", "service", "banking",
    "otp", "token", "recovery", "unlock", "refund", "invoice",
    "claim", "reward", "gift",
)

SUSPICIOUS_TLDS = frozenset({
    "xyz", "top", "click", "zip", "mov", "tk", "ml", "ga", "cf", "gq", "icu",
    "buzz", "cyou", "monster", "rest", "work", "support", "loan", "live",
    "shop", "site", "online", "cam", "sbs", "cfd", "lol", "bond",
})

# Look-alike characters -> ASCII skeleton (digits/leetspeak, Cyrillic, Greek).
_CONFUSABLES = {
    "0": "o", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b", "$": "s", "@": "a",
    "\u0430": "a", "\u0435": "e", "\u043e": "o", "\u0440": "p", "\u0441": "c",
    "\u0445": "x", "\u0443": "y", "\u0456": "i", "\u0458": "j", "\u0455": "s",
    "\u04bb": "h", "\u0501": "d", "\u051b": "q", "\u051d": "w",
    "\u03bf": "o", "\u03b1": "a", "\u03bd": "v", "\u03c1": "p", "\u03b9": "i",
    "\u03ba": "k", "\u0131": "i", "\u0261": "g",
}

_HOST_RE = re.compile(r"^[a-z0-9_.-]+$")
_IPV4_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #
def normalize_domain(raw: str) -> str:
    """Lowercase, strip wildcards/trailing dot, convert IDN to ASCII (A-label)."""
    d = raw.strip().lower().rstrip(".")
    while d.startswith("*."):
        d = d[2:]
    if not d:
        return ""
    if not d.isascii():
        try:
            d = d.encode("idna").decode("ascii")
        except UnicodeError:
            return ""
    if "." not in d or len(d) > 253 or not _HOST_RE.match(d) or _IPV4_RE.match(d):
        return ""
    return d


def decode_label(label: str) -> str:
    """Decode a punycode label (xn--...) to Unicode; return as-is otherwise."""
    if label.startswith("xn--"):
        try:
            return label[4:].encode("ascii").decode("punycode")
        except (UnicodeError, ValueError):
            return label
    return label


def _strip_marks(text: str) -> str:
    decomposed = unicodedata.normalize("NFKD", text)
    return "".join(c for c in decomposed if not unicodedata.combining(c))


def skeletons(text: str) -> Set[str]:
    """ASCII 'skeletons' of a string: what it looks like to a human eye."""
    text = _strip_marks(text.lower())
    base = "".join(_CONFUSABLES.get(c, c) for c in text)
    base = base.replace("rn", "m").replace("vv", "w")
    return {base.replace("1", "l"), base.replace("1", "i")}


def shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    n = len(text)
    return -sum((c / n) * math.log2(c / n) for c in Counter(text).values())


def edit_distance(a: str, b: str, max_dist: Optional[int] = None) -> Optional[int]:
    """Damerau-Levenshtein (optimal string alignment) with early exit.

    Returns None when the distance exceeds ``max_dist``.
    """
    if a == b:
        return 0
    la, lb = len(a), len(b)
    if max_dist is not None and abs(la - lb) > max_dist:
        return None
    prev2: List[int] = []
    prev = list(range(lb + 1))
    for i in range(1, la + 1):
        cur = [i] + [0] * lb
        for j in range(1, lb + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            v = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost)
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                v = min(v, prev2[j - 2] + 1)
            cur[j] = v
        if max_dist is not None and min(cur) > max_dist:
            return None
        prev2, prev = prev, cur
    d = prev[lb]
    return d if (max_dist is None or d <= max_dist) else None


def parse_target(raw: str) -> Tuple[str, Optional[str]]:
    """'examplebank.com' -> ('examplebank', 'examplebank.com'); 'examplebank' -> ('examplebank', None)."""
    raw = raw.strip().lower()
    if "." in raw:
        ext = _TLD(raw)
        if ext.domain and ext.suffix:
            return ext.domain, f"{ext.domain}.{ext.suffix}"
    return raw, None


# --------------------------------------------------------------------------- #
# detector
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class Brand:
    name: str
    skeletons: frozenset


@dataclass
class _Ctx:
    ascii_core: str
    suffix: str
    core: str            # decoded registered label, e.g. "bank-login"
    compact: str         # core without hyphens
    sub: str             # decoded sub-domain, e.g. "www.login"
    sub_compact: str
    core_skels: Set[str]
    is_idn: bool


class BrandDetector:
    def __init__(self, brands: Iterable[str], allowlist: Iterable[str] = (), threshold: float = 0.8):
        names: List[str] = []
        for b in brands:
            b = b.strip().lower()
            if len(b) >= 3 and b not in names:
                names.append(b)
        if not names:
            raise ValueError("at least one brand of 3+ characters is required")
        self.brands = [Brand(n, frozenset(skeletons(n))) for n in names]
        self.allowlist = tuple(sorted({normalize_domain(a) for a in allowlist if a.strip()} - {""}))
        self.threshold = min(max(threshold, 0.5), 1.0)

    # -- public ------------------------------------------------------------ #
    def analyze(self, raw_domain: str) -> Optional[Finding]:
        domain = normalize_domain(raw_domain)
        if not domain or self._allowed(domain):
            return None
        ext = _TLD(domain)
        if not ext.domain or not ext.suffix:
            return None

        core = decode_label(ext.domain)
        sub = ".".join(decode_label(x) for x in ext.subdomain.split(".")) if ext.subdomain else ""
        ctx = _Ctx(
            ascii_core=ext.domain,
            suffix=ext.suffix,
            core=core,
            compact=core.replace("-", ""),
            sub=sub,
            sub_compact=sub.replace("-", ""),
            core_skels=skeletons(core) | skeletons(core.replace("-", "")),
            is_idn="xn--" in domain,
        )

        best: Optional[Tuple[int, int, Brand, List[str]]] = None
        for brand in self.brands:
            hit = self._match(brand, ctx)
            if not hit:
                continue
            base, reasons = hit
            for pts, why in self._bonuses(brand, ctx):
                base += pts
                reasons.append(why)
            score = min(100, base)
            key = (score, len(brand.name))
            if best is None or key > (best[0], best[1]):
                best = (score, len(brand.name), brand, reasons)

        if best is None:
            return None
        score, _, brand, reasons = best
        unicode_domain = ".".join(decode_label(x) for x in domain.split("."))
        return Finding(
            domain=domain,
            target=brand.name,
            registered_domain=f"{ext.domain}.{ext.suffix}",
            score=score,
            reasons=reasons,
            unicode_domain=unicode_domain if unicode_domain != domain else None,
        )

    # -- internals --------------------------------------------------------- #
    def _allowed(self, domain: str) -> bool:
        return any(domain == a or domain.endswith("." + a) for a in self.allowlist)

    def _match(self, brand: Brand, c: _Ctx) -> Optional[Tuple[int, List[str]]]:
        t = brand.name
        base = 0
        reasons: List[str] = []

        if c.core == t:
            base = 70
            reasons.append(f"Exact brand label on unofficial domain ({c.ascii_core}.{c.suffix})")
        elif t in c.core:
            base = 65
            reasons.append("Brand name inside registered domain")
        elif t in c.compact:
            base = 62
            reasons.append("Brand name inside registered domain (hyphen-separated)")
        elif any(s in cs for s in brand.skeletons for cs in c.core_skels):
            base = 75
            reasons.append("Homoglyph / look-alike characters (IDN or leetspeak)")
        else:
            fuzzy = self._fuzzy(t, c)
            if fuzzy:
                ratio, dist = fuzzy
                span = max(1e-9, 1.0 - self.threshold)
                base = int(40 + (ratio - self.threshold) / span * 20)
                reasons.append(f"Typosquat of '{t}' (edit distance {dist}, similarity {ratio:.2f})")

        if c.sub and (t in c.sub or t in c.sub_compact):
            if base == 0:
                base = 55
                reasons.append("Brand name in sub-domain of an unrelated domain")
            else:
                reasons.append("Brand name also used in sub-domain")

        return (base, reasons) if base else None

    def _fuzzy(self, t: str, c: _Ctx) -> Optional[Tuple[float, int]]:
        if len(t) < 5:  # too short: fuzzy matching would be pure noise
            return None
        max_d = max(1, int(len(t) * (1.0 - self.threshold)))
        candidates = {c.core, c.compact}
        candidates.update(tok for tok in c.core.split("-") if len(tok) >= 4)
        best: Optional[Tuple[float, int]] = None
        for cand in candidates:
            d = edit_distance(cand, t, max_d)
            if not d:  # None (too far) or 0 (exact, handled elsewhere)
                continue
            ratio = 1.0 - d / max(len(cand), len(t))
            if ratio >= self.threshold and (best is None or ratio > best[0]):
                best = (ratio, d)
        return best

    def _bonuses(self, brand: Brand, c: _Ctx) -> List[Tuple[int, str]]:
        out: List[Tuple[int, str]] = []

        # Remove the brand itself first so it can never trigger a keyword or the entropy check.
        hay = f"{c.core}.{c.sub}".replace(brand.name, " ")
        tokens = set(re.split(r"[-.]", hay))
        flat = f"{c.compact}.{c.sub_compact}".replace(brand.name, " ").replace(".", "")
        kws = [k for k in PHISHING_KEYWORDS if k in tokens or (len(k) >= 5 and k in flat)]
        if kws:
            out.append((15, "Phishing keyword: " + ", ".join(kws[:3])))

        tld = c.suffix.rsplit(".", 1)[-1]
        if tld in SUSPICIOUS_TLDS:
            out.append((10, f"Frequently abused TLD (.{tld})"))

        if c.is_idn:
            out.append((10, "IDN / punycode label"))

        if self._random_looking(brand, c):
            out.append((8, "Random-looking label (possible DGA)"))

        if c.core.count("-") >= 3:
            out.append((5, "Excessive hyphens"))
        return out

    @staticmethod
    def _random_looking(brand: Brand, c: _Ctx) -> bool:
        """Heuristic DGA check on each label, after removing the brand and phishing words.

        Random strings mix digits into letters and have high Shannon entropy; concatenated
        English words do not, so raw entropy alone would be far too noisy.
        """
        labels = [c.compact] + [x.replace("-", "") for x in c.sub.split(".")] if c.sub else [c.compact]
        for label in labels:
            label = label.replace(brand.name, "")
            for kw in PHISHING_KEYWORDS:
                label = label.replace(kw, "")
            label = re.sub(r"[^a-z0-9]", "", label)
            digits = sum(ch.isdigit() for ch in label)
            entropy = shannon_entropy(label)
            if len(label) >= 10 and digits >= 3 and len(label) - digits >= 3 and entropy >= 3.0:
                return True
            if len(label) >= 18 and entropy >= 3.7:
                return True
        return False
