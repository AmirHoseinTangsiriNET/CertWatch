import pytest

from certwatch.detector import (BrandDetector, edit_distance, normalize_domain,
                                parse_target, shannon_entropy)


@pytest.fixture
def det():
    return BrandDetector(["examplebank"], allowlist=["examplebank.com"])


def test_official_domain_and_subdomains_are_allowed(det):
    assert det.analyze("examplebank.com") is None
    assert det.analyze("www.examplebank.com") is None
    assert det.analyze("*.examplebank.com") is None


def test_unrelated_domains_are_ignored(det):
    for d in ("google.com", "www.wikipedia.org", "example.org", "bank.com", "192.168.1.1", "localhost"):
        assert det.analyze(d) is None


def test_brand_inside_registered_domain(det):
    f = det.analyze("examplebank-secure-login.xyz")
    assert f and f.severity == "CRITICAL"
    assert any("Phishing keyword" in r for r in f.reasons)
    assert any("abused TLD" in r for r in f.reasons)


def test_exact_label_on_other_tld(det):
    f = det.analyze("examplebank.co.uk")
    assert f and f.registered_domain == "examplebank.co.uk"


def test_typosquat_transposition(det):
    f = det.analyze("examplebnak.com")
    assert f and any("Typosquat" in r for r in f.reasons)


def test_leetspeak_homoglyph(det):
    f = det.analyze("exampleb4nk.net")
    assert f and any("Homoglyph" in r for r in f.reasons)


def test_idn_homograph(det):
    puny = "\u0435xamplebank.com".encode("idna").decode()  # Cyrillic 'e'
    f = det.analyze(puny)
    assert f and f.unicode_domain == "\u0435xamplebank.com"
    assert any("IDN" in r for r in f.reasons)


def test_brand_in_subdomain_of_unrelated_domain(det):
    f = det.analyze("examplebank.login.evil-site.top")
    assert f and any("sub-domain" in r for r in f.reasons)
    assert f.registered_domain == "evil-site.top"


def test_brand_not_counted_as_phishing_keyword():
    # the brand contains "bank"/"ebank"; it must not trigger keyword bonuses by itself
    d = BrandDetector(["examplebank"])
    f = d.analyze("examplebank.co.uk")
    assert f and not any("Phishing keyword" in r for r in f.reasons)


def test_random_looking_label():
    d = BrandDetector(["examplebank"])
    f = d.analyze("kdj39fkq0xz81mvpwq7.example-bank.icu")
    assert f and any("Random-looking" in r for r in f.reasons)
    g = d.analyze("verify-account.examplebank.xyz")
    assert g and not any("Random-looking" in r for r in g.reasons)


def test_short_brands_do_not_fuzzy_match():
    d = BrandDetector(["abc"])
    assert d.analyze("abd.com") is None       # 1 edit away, but brand is too short for fuzzy
    assert d.analyze("abc-login.com") is not None


def test_multiple_brands_pick_best():
    d = BrandDetector(["maskan", "bankmaskan"])
    f = d.analyze("bankmaskan-login.top")
    assert f and f.target == "bankmaskan"


def test_threshold_controls_fuzziness():
    strict = BrandDetector(["examplebank"], threshold=0.95)
    assert strict.analyze("examplebnak.com") is None


def test_parse_target():
    assert parse_target("examplebank.com") == ("examplebank", "examplebank.com")
    assert parse_target("ExampleBank") == ("examplebank", None)
    assert parse_target("bank.co.uk") == ("bank", "bank.co.uk")


def test_normalize_domain():
    assert normalize_domain("*.Example.COM.") == "example.com"
    assert normalize_domain("nodots") == ""
    assert normalize_domain("bad domain.com") == ""


def test_edit_distance():
    assert edit_distance("kitten", "sitting") == 3
    assert edit_distance("ab", "ba") == 1            # transposition counts as one edit
    assert edit_distance("abcdef", "uvwxyz", 2) is None
    assert edit_distance("same", "same") == 0


def test_entropy():
    assert shannon_entropy("aaaa") == 0
    assert shannon_entropy("abcd") == pytest.approx(2.0)
