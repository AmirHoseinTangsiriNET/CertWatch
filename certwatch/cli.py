"""Command-line interface."""
from __future__ import annotations

import argparse
import logging
import os
import signal
import sys
import threading
from typing import List, Optional, Sequence

from rich.console import Console
from rich.logging import RichHandler
from rich.panel import Panel

from . import __version__
from .detector import BrandDetector, parse_target
from .engine import Engine
from .models import Finding, SEVERITIES
from .outputs import (ConsoleOutput, JsonlOutput, Output, SplunkHecOutput,
                      WebhookOutput)

log = logging.getLogger("certwatch")

DEFAULT_URL = "wss://certstream.calidog.io"

EXAMPLES = """\
examples:
  certwatch -t examplebank.com                         watch one brand (official domain auto-allowlisted)
  certwatch -t examplebank -t "example pay" -a examplebank.com --resolve
  certwatch -t examplebank.com -o findings.jsonl --quiet     daemon mode, JSONL only
  certwatch -t examplebank.com --slack-webhook https://hooks.slack.com/...
  certwatch -t examplebank.com --url ws://localhost:8080     self-hosted certstream server
  certwatch -t examplebank.com --from-file domains.txt       offline scan of a domain list
"""


def _env(name: str) -> Optional[str]:
    return os.environ.get(name) or None


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="certwatch",
        description="Real-time Certificate Transparency monitor for brand impersonation and phishing domains.",
        epilog=EXAMPLES,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    g = p.add_argument_group("what to watch")
    g.add_argument("-t", "--target", action="append", default=[], metavar="BRAND",
                   help="brand keyword or official domain (repeatable, comma-separated ok)")
    g.add_argument("--targets-file", metavar="FILE", help="file with one brand per line")
    g.add_argument("-a", "--allow", action="append", default=[], metavar="DOMAIN",
                   help="official domain(s) to ignore, incl. sub-domains (repeatable)")
    g.add_argument("--allow-file", metavar="FILE", help="file with one allowed domain per line")

    d = p.add_argument_group("detection")
    d.add_argument("--threshold", type=float, default=0.80,
                   help="typosquat similarity threshold 0.5-1.0 (default: 0.80)")
    d.add_argument("--min-severity", choices=[s.lower() for s in SEVERITIES], default="low",
                   help="minimum severity to report at all (default: low)")
    d.add_argument("--workers", type=int, default=4, help="worker threads for DNS/outputs (default: 4)")
    d.add_argument("--resolve", action="store_true",
                   help="DNS-resolve matches (marks live domains; the attacker's NS can see the lookup)")

    s = p.add_argument_group("source")
    s.add_argument("--url", default=_env("CERTSTREAM_URL") or DEFAULT_URL,
                   help=f"CertStream websocket URL (default: {DEFAULT_URL}, env CERTSTREAM_URL)")
    s.add_argument("--from-file", metavar="FILE",
                   help="scan a file of domains (one per line) instead of the live stream")

    o = p.add_argument_group("outputs")
    o.add_argument("-o", "--output", metavar="FILE", help="append findings as JSON Lines")
    o.add_argument("--details", action="store_true", help="print a full panel per finding")
    o.add_argument("--quiet", action="store_true", help="no banner and no console findings (use with -o / alerts)")
    o.add_argument("--no-banner", action="store_true", help="do not print the start-up banner")
    o.add_argument("--no-color", action="store_true", help="disable colours")
    o.add_argument("--stats-interval", type=int, default=60, metavar="SEC",
                   help="log throughput stats every SEC seconds, 0 = off (default: 60)")

    sp = p.add_argument_group("splunk HEC")
    sp.add_argument("--splunk-url", default=_env("SPLUNK_HEC_URL"), help="e.g. https://splunk:8088 (env SPLUNK_HEC_URL)")
    sp.add_argument("--splunk-token", default=_env("SPLUNK_HEC_TOKEN"), help="HEC token (env SPLUNK_HEC_TOKEN)")
    sp.add_argument("--splunk-index", default=_env("SPLUNK_HEC_INDEX"))
    sp.add_argument("--splunk-insecure", action="store_true", help="skip TLS verification (self-signed HEC)")

    al = p.add_argument_group("alerts (prefer environment variables for secrets)")
    al.add_argument("--slack-webhook", default=_env("CERTWATCH_SLACK_WEBHOOK"))
    al.add_argument("--discord-webhook", default=_env("CERTWATCH_DISCORD_WEBHOOK"))
    al.add_argument("--teams-webhook", default=_env("CERTWATCH_TEAMS_WEBHOOK"))
    al.add_argument("--telegram-token", default=_env("CERTWATCH_TELEGRAM_TOKEN"))
    al.add_argument("--telegram-chat-id", default=_env("CERTWATCH_TELEGRAM_CHAT_ID"))
    al.add_argument("--alert-min-severity", choices=[s.lower() for s in SEVERITIES], default="high",
                    help="minimum severity for chat alerts (default: high)")
    al.add_argument("--test-alert", action="store_true",
                    help="send one synthetic finding to every configured output and exit")

    p.add_argument("-v", "--verbose", action="store_true", help="debug logging")
    p.add_argument("--version", action="version", version=f"certwatch {__version__}")
    return p


def _read_lines(path: str) -> List[str]:
    with open(path, encoding="utf-8") as fh:
        return [ln.strip() for ln in fh if ln.strip() and not ln.lstrip().startswith("#")]


def _split(values: Sequence[str]) -> List[str]:
    return [part.strip() for v in values for part in v.split(",") if part.strip()]


def collect_targets(args: argparse.Namespace):
    raw = _split(args.target)
    if args.targets_file:
        raw += _read_lines(args.targets_file)
    allow = _split(args.allow)
    if args.allow_file:
        allow += _read_lines(args.allow_file)
    brands: List[str] = []
    for item in raw:
        brand, official = parse_target(item)
        brands.append(brand)
        if official:
            allow.append(official)  # "-t examplebank.com" implies the official domain
    return brands, allow


def build_outputs(args: argparse.Namespace, console: Console) -> List[Output]:
    outs: List[Output] = []
    if not args.quiet:
        outs.append(ConsoleOutput(console, details=args.details))
    if args.output:
        outs.append(JsonlOutput(args.output))
    if args.splunk_url and args.splunk_token:
        outs.append(SplunkHecOutput(args.splunk_url, args.splunk_token, args.splunk_index,
                                    verify=not args.splunk_insecure))
    elif args.splunk_url or args.splunk_token:
        raise SystemExit("error: Splunk needs both --splunk-url and --splunk-token")
    sev = args.alert_min_severity.upper()
    if args.slack_webhook:
        outs.append(WebhookOutput("slack", url=args.slack_webhook, min_severity=sev))
    if args.discord_webhook:
        outs.append(WebhookOutput("discord", url=args.discord_webhook, min_severity=sev))
    if args.teams_webhook:
        outs.append(WebhookOutput("teams", url=args.teams_webhook, min_severity=sev))
    if args.telegram_token and args.telegram_chat_id:
        outs.append(WebhookOutput("telegram", token=args.telegram_token,
                                  chat_id=args.telegram_chat_id, min_severity=sev))
    elif args.telegram_token or args.telegram_chat_id:
        raise SystemExit("error: Telegram needs both --telegram-token and --telegram-chat-id")
    return outs


def run_test_alert(outputs: Sequence[Output]) -> int:
    finding = Finding(
        domain="examplebank-secure-login.xyz", target="examplebank",
        registered_domain="examplebank-secure-login.xyz", score=92,
        reasons=["Brand name inside registered domain", "Phishing keyword: secure, login",
                 "Frequently abused TLD (.xyz)", "(synthetic finding from --test-alert)"],
        issuer="Test CA",
    )
    failures = 0
    for out in outputs:
        try:
            out.emit(finding)
            log.info("test alert -> %s: OK", out.name)
        except Exception as exc:  # noqa: BLE001
            failures += 1
            log.error("test alert -> %s: FAILED (%s)", out.name, exc)
    return 1 if failures else 0


def run_from_file(engine: Engine, path: str) -> None:
    for domain in _read_lines(path):
        engine.handle_certificate({
            "leaf_cert": {"all_domains": [domain], "issuer": {"O": "file-input"}},
            "source": {"name": "file"},
        })


def setup_logging(verbose: bool) -> None:
    handler = RichHandler(console=Console(stderr=True), show_path=False, markup=False)
    logging.basicConfig(level=logging.DEBUG if verbose else logging.INFO,
                        format="%(message)s", handlers=[handler], force=True)
    logging.getLogger("websocket").setLevel(logging.DEBUG if verbose else logging.CRITICAL)


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    setup_logging(args.verbose)
    console = Console(no_color=args.no_color)

    brands, allow = collect_targets(args)
    if not brands and not args.test_alert:
        parser.error("at least one target is required (-t BRAND or --targets-file)")

    try:
        detector = BrandDetector(brands or ["examplebank"], allowlist=allow, threshold=args.threshold)
    except ValueError as exc:
        parser.error(str(exc))
    outputs = build_outputs(args, console)

    if args.test_alert:
        return run_test_alert([o for o in outputs if o.name != "console"] or outputs)

    if not allow:
        log.warning("No official domains allow-listed (-a / -t domain.tld): your own certificates will be reported too.")

    # Offline scans without DNS use one worker so the output order matches the input order.
    workers = 1 if (args.from_file and not args.resolve) else args.workers
    engine = Engine(detector, outputs, resolve=args.resolve, min_severity=args.min_severity.upper(),
                    workers=workers, drop_when_full=not args.from_file)

    if not (args.quiet or args.no_banner):
        info = (f"[bold cyan]CertWatch[/] [green]v{__version__}[/]  |  Certificate Transparency brand monitor\n"
                f"[yellow]Brands:[/] {', '.join(b.name for b in detector.brands)}   "
                f"[yellow]Allow-listed:[/] {len(detector.allowlist)}   "
                f"[yellow]Threshold:[/] {detector.threshold}   [yellow]DNS:[/] {args.resolve}")
        console.print(Panel(info, border_style="blue", expand=False))

    # ---- offline mode -------------------------------------------------------
    if args.from_file:
        run_from_file(engine, args.from_file)
        engine.drain()
        log.info("done: %s", engine.stats.summary())
        return 0

    # ---- live mode ----------------------------------------------------------
    from .stream import CertStreamClient  # imported lazily: offline mode needs no websocket

    client = CertStreamClient(args.url, engine.handle_certificate)
    stop = threading.Event()

    def _shutdown(signum, _frame):
        log.info("Signal %s received - shutting down ...", signum)
        stop.set()
        client.stop()

    signal.signal(signal.SIGINT, _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)

    if args.stats_interval > 0:
        def _stats_loop():
            while not stop.wait(args.stats_interval):
                log.info("stats: %s", engine.stats.summary())
        threading.Thread(target=_stats_loop, daemon=True).start()

    log.info("Listening on %s (Ctrl+C to stop)", args.url)
    try:
        client.run()
    finally:
        engine.drain()
        log.info("final: %s", engine.stats.summary())
    return 0
