"""Output sinks: console, JSONL, Splunk HEC and chat/alert webhooks."""
from __future__ import annotations

import json
import socket
import threading
import time
from typing import Optional

import requests
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from . import __version__
from .models import Finding, severity_rank

SEVERITY_STYLE = {
    "LOW": "cyan",
    "MEDIUM": "yellow",
    "HIGH": "bold red",
    "CRITICAL": "bold white on red",
}


def defang(value: str) -> str:
    """Make a domain safe to paste into chat (no auto-links / accidental clicks)."""
    return value.replace(".", "[.]")


class Output:
    """Base class. ``min_rank`` filters by severity (0=LOW ... 3=CRITICAL)."""

    name = "output"

    def __init__(self, min_severity: str = "LOW"):
        self.min_rank = severity_rank(min_severity)

    def emit(self, finding: Finding) -> None:  # pragma: no cover - interface
        raise NotImplementedError

    def close(self) -> None:
        pass


# --------------------------------------------------------------------------- #
# local sinks
# --------------------------------------------------------------------------- #
class ConsoleOutput(Output):
    name = "console"

    def __init__(self, console: Console, details: bool = False):
        super().__init__("LOW")
        self.console = console
        self.details = details
        self._lock = threading.Lock()

    def emit(self, f: Finding) -> None:
        with self._lock:
            if self.details:
                self._print_details(f)
            else:
                self._print_line(f)

    def _print_line(self, f: Finding) -> None:
        line = Text()
        line.append(time.strftime("%H:%M:%S "), style="dim")
        line.append(f"{f.severity:<8}", style=SEVERITY_STYLE[f.severity])
        line.append(f" {f.score:>3} ", style="bold")
        line.append(f.domain, style="bold yellow")
        if f.unicode_domain:
            line.append(f" ({f.unicode_domain})", style="magenta")
        line.append(f"  ~{f.target}", style="cyan")
        line.append("  " + "; ".join(f.reasons), style="dim")
        if f.ips:
            line.append("  ip=" + ",".join(f.ips[:3]), style="green")
        if f.issuer:
            line.append(f"  ca={f.issuer}", style="dim")
        self.console.print(line, soft_wrap=True)

    def _print_details(self, f: Finding) -> None:
        table = Table(show_header=False, box=None, pad_edge=False)
        table.add_column(style="cyan", no_wrap=True)
        table.add_column()
        table.add_row("Domain", Text(f.domain, style="bold yellow"))
        if f.unicode_domain:
            table.add_row("Unicode", Text(f.unicode_domain, style="magenta"))
        table.add_row("Brand", f.target)
        table.add_row("Score", f"{f.score}/100")
        table.add_row("Reasons", Text("\n".join(f"- {r}" for r in f.reasons)))
        table.add_row("Issuer", f.issuer or "unknown")
        table.add_row("Valid from", f.not_before or "unknown")
        if f.resolved is not None:
            table.add_row("DNS", ", ".join(f.ips) if f.ips else "does not resolve (yet)")
        if f.sans:
            more = f" (+{f.san_count - len(f.sans)} more)" if f.san_count > len(f.sans) else ""
            table.add_row("SANs", Text(", ".join(f.sans[:5]) + more))
        style = SEVERITY_STYLE[f.severity]
        self.console.print(Panel(table, title=f"[{style}] {f.severity} [/]", border_style="red", expand=False))


class JsonlOutput(Output):
    name = "jsonl"

    def __init__(self, path: str):
        super().__init__("LOW")
        self._fh = open(path, "a", encoding="utf-8", buffering=1)
        self._lock = threading.Lock()

    def emit(self, f: Finding) -> None:
        line = json.dumps(f.to_dict(), ensure_ascii=False)
        with self._lock:
            self._fh.write(line + "\n")

    def close(self) -> None:
        self._fh.close()


# --------------------------------------------------------------------------- #
# network sinks
# --------------------------------------------------------------------------- #
def _post(session: requests.Session, url: str, label: str, **kwargs) -> None:
    """POST with small retry. Never leaks the URL (it may contain a secret) in errors."""
    last = "unknown error"
    for attempt in range(3):
        try:
            resp = session.post(url, timeout=10, **kwargs)
            if resp.status_code == 429:
                time.sleep(min(float(resp.headers.get("Retry-After", 2)), 5))
                last = "rate limited (HTTP 429)"
                continue
            if resp.status_code >= 500:
                last = f"HTTP {resp.status_code}"
                time.sleep(1 + attempt)
                continue
            resp.raise_for_status()
            return
        except requests.HTTPError as exc:
            raise RuntimeError(f"{label}: HTTP {exc.response.status_code}") from None
        except requests.RequestException as exc:
            last = type(exc).__name__
            time.sleep(1 + attempt)
    raise RuntimeError(f"{label}: failed after retries ({last})")


class SplunkHecOutput(Output):
    name = "splunk"

    def __init__(self, url: str, token: str, index: Optional[str] = None,
                 verify: bool = True, min_severity: str = "LOW"):
        super().__init__(min_severity)
        if "/services/collector" not in url:
            url = url.rstrip("/") + "/services/collector/event"
        self.url, self.index, self.verify = url, index, verify
        self.host = socket.gethostname()
        self.session = requests.Session()
        self.session.headers["Authorization"] = f"Splunk {token}"

    def emit(self, f: Finding) -> None:
        payload = {
            "time": time.time(),
            "host": self.host,
            "source": "certwatch",
            "sourcetype": "certwatch:finding",
            "event": f.to_dict(),
        }
        if self.index:
            payload["index"] = self.index
        _post(self.session, self.url, "splunk", json=payload, verify=self.verify)


def format_alert(f: Finding) -> str:
    lines = [
        f"[{f.severity}] Possible brand impersonation - score {f.score}/100",
        f"Domain : {defang(f.domain)}",
    ]
    if f.unicode_domain:
        lines.append(f"Unicode: {defang(f.unicode_domain)}")
    lines += [
        f"Brand  : {f.target}",
        "Why    : " + "; ".join(f.reasons),
        f"CA     : {f.issuer or 'unknown'}",
    ]
    if f.resolved is not None:
        lines.append("IP     : " + (", ".join(f.ips) if f.ips else "not resolving yet"))
    lines.append(f"Seen   : {f.timestamp}")
    return "\n".join(lines)


class WebhookOutput(Output):
    """Slack / Discord / Microsoft Teams / Telegram alerts."""

    def __init__(self, kind: str, url: str = "", token: str = "", chat_id: str = "",
                 min_severity: str = "HIGH"):
        super().__init__(min_severity)
        if kind not in {"slack", "discord", "teams", "telegram"}:
            raise ValueError(f"unknown webhook kind: {kind}")
        self.kind, self.name = kind, kind
        self.url, self.token, self.chat_id = url, token, chat_id
        self.session = requests.Session()
        self.session.headers["User-Agent"] = f"certwatch/{__version__}"

    def emit(self, f: Finding) -> None:
        text = format_alert(f)
        if self.kind == "slack":
            _post(self.session, self.url, self.kind, json={"text": f"```{text}```"})
        elif self.kind == "discord":
            _post(self.session, self.url, self.kind, json={"content": f"```{text}```"[:1990]})
        elif self.kind == "teams":
            _post(self.session, self.url, self.kind, json={"text": text.replace("\n", "<br>")})
        else:  # telegram
            url = f"https://api.telegram.org/bot{self.token}/sendMessage"
            _post(self.session, url, self.kind,
                  json={"chat_id": self.chat_id, "text": text, "disable_web_page_preview": True})
