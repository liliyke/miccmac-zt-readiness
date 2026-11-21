"""Connector interface: a connector's job is to collect facts about a target
device and return them in the shape check modules expect via
context["facts"] -- the extensibility seam documented in the README and
docs/methodology.md. Connectors never evaluate checks themselves.
"""
from __future__ import annotations

import socket
import time
from typing import Callable, Protocol, Tuple

# Longest error message kept for a failed extended-fact item.
EXTRA_ERROR_MAX_CHARS = 500
# How often read_extra_command checks whether the exit status has arrived.
_EXIT_STATUS_POLL_SECONDS = 0.01


class ConnectorError(RuntimeError):
    """Raised when a connector cannot reach or query a target."""


class Connector(Protocol):
    def collect_facts(self, target: str, extended: bool = False) -> dict:
        """Return a facts dict, e.g.:

            {
                "os": {"platform": "ubuntu", "name": "Ubuntu", "version": "26.04"},
                "system_info": {...},          # raw osquery system_info row
                "deb_packages": [...],         # raw osquery deb_packages rows
            }

        Raises ConnectorError if the target can't be reached or one of the
        main queries fails.

        extended=True (used by ``assess --save-facts``) also collects the
        connector's extended facts, after all the main queries and commands,
        and stores them under facts["extra"], one entry per item:

            {"ok": True, "data": <parsed rows or text>}
            {"ok": False, "error": "<short message>"}

        Every extended item is non-fatal: any failure (non-zero exit,
        timeout, exception, unparseable output) is recorded as ok=False and
        collection carries on. Each item is bounded by the connector's
        channel timeout (read_extra_command), so a stalled command becomes a
        recorded timeout instead of stopping the run. Extended items are
        queries and read-only commands; they request no elevation (no sudo
        or run-as), and some report a permission error without it, which is
        recorded as their answer or as ok=False. One Windows item can change
        state on the target: asking the Microsoft.Update.AutoUpdate COM
        object for its results may start the Windows Update service
        (wuauserv) on demand, as any Windows Update client can. It runs after
        the main queries and after the update_services item, so no service
        state in the same run's facts can reflect it, but a second live
        collection from the same snapshot could see the service running
        (collect live once per revert). No check reads
        facts["extra"] in this version; it is saved so that later fixes to
        check logic can be re-tested from the same saved facts file. With
        extended=False (the default) the facts, and the commands sent to
        the target, are exactly what they were before extended facts
        existed.
        """
        ...


def short_error(exc: BaseException) -> str:
    """One-line description of an exception for an extended-fact item:
    'Type: message', whitespace collapsed, at most EXTRA_ERROR_MAX_CHARS."""
    message = " ".join(str(exc).split())
    text = f"{type(exc).__name__}: {message}" if message else type(exc).__name__
    if len(text) > EXTRA_ERROR_MAX_CHARS:
        text = text[:EXTRA_ERROR_MAX_CHARS - 3] + "..."
    return text


def collect_extra_item(func: Callable[..., object], *args: object) -> dict:
    """Run one extended-fact collector, func(*args), and wrap the result for
    facts["extra"]: {"ok": True, "data": result}, or {"ok": False, "error":
    short message} if it raised anything at all. Never raises, so one
    failing item cannot stop the collection or lose the main facts."""
    try:
        return {"ok": True, "data": func(*args)}
    except Exception as exc:  # deliberately broad: every extended item is non-fatal
        return {"ok": False, "error": short_error(exc)}


def _close_quietly(channel) -> None:
    try:
        channel.close()
    except Exception:  # closing is best effort; the original error is what matters
        pass


def read_extra_command(stdout, stderr, timeout: float) -> Tuple[int, str, str]:
    """(exit status, stdout text, stderr text) of an extended-fact command
    started with client.exec_command(command, timeout=timeout), bounded by
    that channel timeout.

    The output is read before the exit status is asked for, so every read
    waits at most `timeout` seconds for more output (paramiko raises
    socket.timeout then). Once the output has ended, the exit status is
    awaited for at most `timeout` seconds more, by polling
    exit_status_ready(): paramiko's recv_exit_status() alone has no timeout
    and, called first, can wait forever. A timeout raises ConnectorError,
    which collect_extra_item records as ok=False; on any failure the channel
    is closed, so a stalled command does not keep it open. The main queries
    do not use this reader: their code is unchanged."""
    channel = stdout.channel
    try:
        out = stdout.read()
        err = stderr.read()
        deadline = time.monotonic() + timeout
        while not channel.exit_status_ready():
            if time.monotonic() >= deadline:
                raise ConnectorError(f"timed out: no exit status {timeout:g} s after the output ended")
            time.sleep(_EXIT_STATUS_POLL_SECONDS)
        exit_status = channel.recv_exit_status()
    except socket.timeout as exc:
        _close_quietly(channel)
        raise ConnectorError(f"timed out: no output for {timeout:g} s") from exc
    except BaseException:
        _close_quietly(channel)
        raise
    return exit_status, out.decode("utf-8", errors="replace"), err.decode("utf-8", errors="replace")
