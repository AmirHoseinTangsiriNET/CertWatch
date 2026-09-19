"""CertStream websocket client with auto-reconnect and a stall watchdog."""
from __future__ import annotations

import json
import logging
import socket
import threading
import time
from typing import Any, Callable, Dict, Optional

import websocket

log = logging.getLogger("certwatch.stream")


class CertStreamClient:
    def __init__(
        self,
        url: str,
        on_certificate: Callable[[Dict[str, Any]], None],
        ping_interval: int = 25,
        ping_timeout: int = 10,
        stall_timeout: int = 120,
        max_backoff: int = 60,
    ):
        self.url = url
        self._on_certificate = on_certificate
        self.ping_interval = ping_interval
        self.ping_timeout = ping_timeout
        self.stall_timeout = stall_timeout
        self.max_backoff = max_backoff
        self._stop = threading.Event()
        self._ws: Optional[websocket.WebSocketApp] = None
        self._last_msg = time.monotonic()

    # -- public ------------------------------------------------------------ #
    def run(self) -> None:
        """Block until :meth:`stop` is called. Reconnects with exponential backoff."""
        backoff = 1
        while not self._stop.is_set():
            got_data = False

            def on_open(_ws):
                log.info("Connected to %s", self.url)
                self._last_msg = time.monotonic()

            def on_message(_ws, message):
                nonlocal got_data
                got_data = True
                self._last_msg = time.monotonic()
                self._dispatch(message)

            def on_error(_ws, error):
                if not self._stop.is_set():
                    log.warning("Stream error: %s", error)

            ws = websocket.WebSocketApp(
                self.url, on_open=on_open, on_message=on_message, on_error=on_error
            )
            self._ws = ws
            threading.Thread(target=self._watchdog, args=(ws,), daemon=True).start()
            try:
                ws.run_forever(ping_interval=self.ping_interval, ping_timeout=self.ping_timeout)
            except Exception as exc:  # noqa: BLE001 - keep the monitor alive no matter what
                log.warning("Stream crashed: %s", exc)
            self._ws = None
            if self._stop.is_set():
                break
            backoff = 1 if got_data else min(backoff * 2, self.max_backoff)
            log.warning("Disconnected. Reconnecting in %ss ...", backoff)
            self._stop.wait(backoff)

    def stop(self) -> None:
        self._stop.set()
        ws = self._ws
        if ws is not None:
            self._kill(ws)

    @staticmethod
    def _kill(ws: "websocket.WebSocketApp") -> None:
        """Abort the connection right now.

        shutdown() wakes the blocked read loop immediately; run_forever() then closes the
        socket itself. (Calling close() straight after would drop the fd from epoll before
        the reader wakes, delaying shutdown by up to ping_timeout seconds.)
        """
        ws.keep_running = False
        try:
            ws.sock.send_close()  # tell the server we are leaving; do not wait for its reply
        except Exception:  # noqa: BLE001
            pass
        raw = getattr(getattr(ws, "sock", None), "sock", None)
        if raw is not None:
            try:
                raw.shutdown(socket.SHUT_RDWR)
                return
            except OSError:
                pass
        try:
            ws.close()
        except Exception:  # noqa: BLE001
            pass

    # -- internals --------------------------------------------------------- #
    def _dispatch(self, raw: str) -> None:
        try:
            msg = json.loads(raw)
        except ValueError:
            return
        if msg.get("message_type") != "certificate_update":
            return  # heartbeats etc.
        try:
            self._on_certificate(msg.get("data") or {})
        except Exception:  # noqa: BLE001
            log.exception("Certificate handler failed")

    def _watchdog(self, ws: "websocket.WebSocketApp") -> None:
        while not self._stop.wait(5):
            if self._ws is not ws:
                return
            if time.monotonic() - self._last_msg > self.stall_timeout:
                log.warning("No data for %ss - forcing reconnect", self.stall_timeout)
                self._kill(ws)
                return
