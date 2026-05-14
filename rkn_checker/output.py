from __future__ import annotations

import os
import sys
from collections import Counter
from http import HTTPStatus

from .models import BLOCKED_VERDICTS, CheckResult, Confidence, Verdict


class C:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    CYAN = "\033[36m"
    GRAY = "\033[90m"


def _colors_enabled() -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    return sys.stdout.isatty()


if not _colors_enabled():
    for _attr in ("RESET", "BOLD", "DIM", "RED", "GREEN", "YELLOW", "CYAN", "GRAY"):
        setattr(C, _attr, "")


def _label_for(verdict: Verdict, confidence: Confidence) -> tuple[str, str]:
    if verdict == Verdict.OK:
        return C.GREEN, "✓ OK"
    if verdict == Verdict.DOWN:
        return C.GRAY, "· DOWN"
    if verdict == Verdict.UNKNOWN:
        return C.GRAY, "? UNK"

    # (пояснение, что именно режет трафик)
    base, ru = {
        Verdict.DNS_BLOCK: ("DNS BLOCK",  "провайдер подменяет DNS"),
        Verdict.TCP_RESET: ("TCP RESET",  "провайдер рвёт TCP-соединение"),
        Verdict.TLS_BLOCK: ("TLS DPI",    "DPI режет по SNI в TLS"),
        Verdict.HTTP_STUB: ("HTTP STUB",  "провайдер подставляет заглушку"),
        Verdict.TIMEOUT:   ("TIMEOUT",    "IP заблокирован / нет маршрута"),
    }.get(verdict, (verdict.value, ""))

    if confidence == Confidence.HIGH:
        return C.RED, f"✗ {base}"
    if confidence == Confidence.MEDIUM:
        return C.YELLOW, f"# {base}?"
    return C.GRAY, f"? {base}?"


def print_header(info: dict) -> None:
    print(f"\n{C.BOLD}{C.CYAN}{'=' * 54}{C.RESET}")
    print(f"{C.BOLD}{C.CYAN}  RKN Block Checker{C.RESET}")
    print(f"{C.BOLD}{C.CYAN}{'=' * 54}{C.RESET}")
    if info:
        print(f"  {C.DIM}IP:{C.RESET}       {info.get('ip', '?')}")
        print(f"  {C.DIM}ISP:{C.RESET}      {info.get('org', '?')}")
        loc = f"{info.get('city', '?')}, {info.get('region', '?')}, {info.get('country', '?')}"
        print(f"  {C.DIM}Location:{C.RESET} {loc}")
    else:
        print(f"  {C.YELLOW}couldn't fetch IP info{C.RESET}")
    print(f"{C.BOLD}{C.CYAN}{'-' * 54}{C.RESET}")


def print_section(title: str) -> None:
    print(f"\n{C.BOLD}{title}{C.RESET}")
    print(
        f"{C.DIM}{'name':<12}{'verdict':<12}"
        f"{'TCP':>8}{'TLS':>8}{'PLT':>8}  {'code':<4}{C.RESET}"
    )
    print(f"{C.DIM}{'-' * 54}{C.RESET}")


def print_result(r: CheckResult) -> None:
    color, label = _label_for(r.verdict, r.confidence)

    status = str(r.status_code) if r.status_code else "-"
    status_col = _colored_http_status(f"{status:<4}", r.status_code)
    tcp = f"{r.tcp_time_ms:.0f}ms" if r.tcp_time_ms is not None else "-"
    tls = f"{r.tls_time_ms:.0f}ms" if r.tls_time_ms is not None else "-"
    plt = f"{r.plt_ms:.0f}ms" if r.plt_ms is not None else "-"

    name_col = r.name[:12].ljust(12)
    label_col = label[:12].ljust(12)
    print(
        f"{name_col}"
        f"{color}{label_col}{C.RESET}"
        f"{tcp:>8}{tls:>8}{plt:>8}  "
        f"{status_col}"
    )
    for note in r.notes:
        print(f"  {C.DIM}└ {note}{C.RESET}")
    status_note = _http_status_note(r.status_code)
    if status_note:
        print(f"  {C.DIM}└ {status_note}{C.RESET}")


def _http_status_note(status_code: int | None) -> str | None:
    if status_code is None or status_code == 200:
        return None
    try:
        phrase = HTTPStatus(status_code).phrase
    except ValueError:
        phrase = "Unknown Status"
    return f"HTTP code {status_code} {phrase}"


def _colored_http_status(status: str, status_code: int | None) -> str:
    if status_code is not None and 400 <= status_code <= 499:
        return f"{C.RED}{status}{C.RESET}"
    return status


def print_summary(white: list[CheckResult], black: list[CheckResult]) -> None:
    white_ok = sum(1 for r in white if r.verdict == Verdict.OK)
    black_ok = sum(1 for r in black if r.verdict == Verdict.OK)
    black_blocked = sum(
        1 for r in black
        if r.verdict in BLOCKED_VERDICTS and r.verdict != Verdict.TIMEOUT
    )
    black_timeout = sum(1 for r in black if r.verdict == Verdict.TIMEOUT)
    black_high_conf = sum(
        1 for r in black
        if r.verdict in BLOCKED_VERDICTS and r.confidence == Confidence.HIGH
    )

    print(f"\n{C.BOLD}{C.CYAN}{'=' * 54}{C.RESET}")
    print(f"{C.BOLD}  Summary{C.RESET}")
    print(f"{C.BOLD}{C.CYAN}{'-' * 54}{C.RESET}")
    print(f"  Whitelist: {white_ok}/{len(white)} working")
    print(
        f"  Blacklist: {black_ok}/{len(black)} open, "
        f"{black_blocked}/{len(black)} blocked"
        + (f", {black_timeout} timed out" if black_timeout else "")
    )

    color, verdict, conf_note = _summary_verdict(
        white_ok, len(white), black_ok, black_blocked, len(black),
        black_high_conf, black_timeout,
    )
    print(f"\n  {color}{C.BOLD}→ {verdict}{C.RESET}")
    if conf_note:
        print(f"  {C.DIM}  {conf_note}{C.RESET}")

    types = Counter(r.verdict for r in black if r.verdict in BLOCKED_VERDICTS)
    if types:
        print(f"\n  {C.DIM}Block types in the blacklist:{C.RESET}")
        for verdict_type, count in types.most_common():
            type_color, label = _label_for(verdict_type, Confidence.HIGH)
            print(f"    {type_color}{label}{C.RESET}: {count}")

    print(f"{C.BOLD}{C.CYAN}{'=' * 54}{C.RESET}\n")


def _summary_verdict(
    white_ok: int,
    white_total: int,
    black_ok: int,
    black_blocked: int,
    black_total: int,
    black_high_conf: int = 0,
    black_timeout: int = 0,
) -> tuple[str, str, str]:
    """Return (color, verdict line, confidence note).

    The confidence note explains *why* we report what we report - and in
    particular whether the whitelist control is healthy enough for the
    blacklist signal to be trustworthy.
    """
    effective_total = black_total - black_timeout

    if white_total > 0 and white_ok < white_total / 2:
        return (
            C.YELLOW,
            "Inconclusive - control whitelist is also failing.",
            "Can't separate censorship from a broken uplink without a working "
            "baseline. Try a different network, or check the local connection.",
        )

    if effective_total <= 0:
        return (
            C.YELLOW,
            "Inconclusive - all blacklist probes timed out.",
            "Cannot determine blocking status when every probe times out.",
        )

    if black_blocked == 0 and black_ok == effective_total:
        return (
            C.GREEN,
            "Likely NOT in an RKN-blocked zone (or VPN is masking it).",
            "All blacklisted sites loaded - either you're outside the blocked "
            "zone, or your VPN/proxy is intercepting the traffic.",
        )

    if black_blocked >= effective_total * 0.7:
        if effective_total > 0 and black_high_conf >= effective_total * 0.5:
            return (
                C.RED,
                "Likely in an RKN-blocked zone (high confidence).",
                f"{black_high_conf}/{effective_total} blacklist failures match "
                "high-confidence patterns (DNS poisoning confirmed by DoH, "
                "HTTP 451, known stub-page markers).",
            )
        return (
            C.RED,
            "Likely in an RKN-blocked zone (medium confidence).",
            "Most blacklist failures match censorship patterns (TLS DPI, "
            "TCP RST), but those signals can also be caused by server-side "
            "issues. A control vantage point would confirm.",
        )

    return (
        C.YELLOW,
        "Partial blocks - some blacklisted sites still load.",
        "Mixed signals. May indicate selective filtering, a mix of real "
        "blocks and unrelated server issues, or a CDN flake.",
    )
