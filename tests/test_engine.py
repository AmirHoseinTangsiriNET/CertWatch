import json

from certwatch.detector import BrandDetector
from certwatch.engine import Engine
from certwatch.outputs import JsonlOutput, Output, format_alert


class Collector(Output):
    name = "collector"

    def __init__(self, min_severity="LOW"):
        super().__init__(min_severity)
        self.items = []

    def emit(self, finding):
        self.items.append(finding)


def cert(*domains, issuer="Test CA"):
    return {
        "leaf_cert": {
            "all_domains": list(domains),
            "issuer": {"O": issuer},
            "fingerprint": "AA:BB",
            "not_before": 1_700_000_000,
        },
        "source": {"name": "Test Log"},
    }


def make_engine(*outs, **kw):
    det = BrandDetector(["examplebank"], allowlist=["examplebank.com"])
    return Engine(det, outs, workers=1, drop_when_full=False, **kw)


def test_pipeline_enriches_and_deduplicates():
    sink = Collector()
    eng = make_engine(sink)
    eng.handle_certificate(cert("examplebank-login.xyz", "www.google.com"))
    eng.handle_certificate(cert("examplebank-login.xyz"))  # precert + final cert -> same domain
    eng.drain()
    assert len(sink.items) == 1
    f = sink.items[0]
    assert f.issuer == "Test CA" and f.log_source == "Test Log"
    assert f.not_before.startswith("2023-11-14")
    assert f.san_count == 2 and eng.stats.certs == 2 and eng.stats.matches == 1


def test_severity_filters():
    low, high = Collector("LOW"), Collector("CRITICAL")
    eng = make_engine(low, high)
    eng.handle_certificate(cert("examplebnak.com"))               # MEDIUM
    eng.handle_certificate(cert("examplebank-secure-login.xyz"))  # CRITICAL
    eng.drain()
    assert len(low.items) == 2 and len(high.items) == 1

    only_high = Collector()
    eng2 = make_engine(only_high, min_severity="HIGH")
    eng2.handle_certificate(cert("examplebnak.com"))
    eng2.drain()
    assert only_high.items == []


def test_failing_output_does_not_break_others():
    class Boom(Output):
        name = "boom"

        def emit(self, finding):
            raise RuntimeError("nope")

    sink = Collector()
    eng = make_engine(Boom(), sink)
    eng.handle_certificate(cert("examplebank-login.xyz"))
    eng.drain()
    assert len(sink.items) == 1


def test_resolve_marks_live_domains(monkeypatch):
    monkeypatch.setattr("certwatch.engine.resolve_ips", lambda d: ["203.0.113.7"])
    sink = Collector()
    eng = make_engine(sink, resolve=True)
    eng.handle_certificate(cert("examplebank-login.xyz"))
    eng.drain()
    assert sink.items[0].ips == ["203.0.113.7"] and sink.items[0].resolved is True


def test_jsonl_output(tmp_path):
    path = tmp_path / "out.jsonl"
    eng = make_engine(JsonlOutput(str(path)))
    eng.handle_certificate(cert("examplebank-login.xyz"))
    eng.drain()
    rec = json.loads(path.read_text().strip())
    assert rec["domain"] == "examplebank-login.xyz" and rec["severity"] in {"HIGH", "CRITICAL"}
    assert rec["target"] == "examplebank"


def test_alert_text_is_defanged():
    sink = Collector()
    eng = make_engine(sink)
    eng.handle_certificate(cert("examplebank-login.xyz"))
    eng.drain()
    text = format_alert(sink.items[0])
    assert "examplebank-login[.]xyz" in text and "examplebank-login.xyz" not in text


def test_apex_and_www_in_one_cert_are_one_incident():
    sink = Collector()
    eng = make_engine(sink)
    eng.handle_certificate(cert("examplebank-login.xyz", "www.examplebank-login.xyz"))
    eng.drain()
    assert len(sink.items) == 1 and sink.items[0].san_count == 2
