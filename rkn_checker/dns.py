from __future__ import annotations

import json
import logging
import socket
import struct
import time
from typing import Optional

import requests

logger = logging.getLogger(__name__)

DOH_ENDPOINTS = [
    "https://cloudflare-dns.com/dns-query",
    "https://freedns.controld.com/dns-query",
    "https://dns.quad9.net/dns-query",
    "https://dns.google/dns-query",
    "https://dns.alidns.com/dns-query",
    "https://dns.nextdns.io",
]
DOH_TIMEOUT = 5.0


def _unique(items: list[str]) -> list[str]:
    return list(dict.fromkeys(items))


def resolve_system_all(host: str) -> list[str]:
    try:
        records = socket.getaddrinfo(host, None, family=socket.AF_INET)
        return _unique([record[4][0] for record in records])
    except socket.gaierror as e:
        logger.debug("system DNS failed for %s: %s", host, e)
        return []


def resolve_system(host: str) -> Optional[str]:
    ips = resolve_system_all(host)
    return ips[0] if ips else None


def _skip_dns_name(data: bytes, pos: int) -> int:
    while pos < len(data):
        length = data[pos]
        pos += 1
        if length == 0:
            return pos
        if length >= 0xC0:
            return pos + 1
        pos += length
    return pos


def _parse_dns_wire_a_records(data: bytes) -> list[str]:
    """Extract all A records from a binary DNS response."""
    records: list[str] = []
    try:
        if len(data) < 12:
            return []
        qdcount = struct.unpack("!H", data[4:6])[0]
        ancount = struct.unpack("!H", data[6:8])[0]
        if ancount == 0:
            return []

        pos = 12
        for _ in range(qdcount):
            pos = _skip_dns_name(data, pos) + 4  # QTYPE + QCLASS

        for _ in range(ancount):
            pos = _skip_dns_name(data, pos)
            if pos + 10 > len(data):
                break
            rtype, _rclass, _ttl, rdlen = struct.unpack("!HHIH", data[pos:pos + 10])
            pos += 10
            if pos + rdlen > len(data):
                break
            if rtype == 1 and rdlen == 4:
                records.append(socket.inet_ntoa(data[pos:pos + 4]))
            pos += rdlen
    except Exception as exc:
        logger.debug("dns wire parse error: %s", exc)
    return _unique(records)


def _parse_dns_wire_a(data: bytes) -> Optional[str]:
    records = _parse_dns_wire_a_records(data)
    return records[0] if records else None


def resolve_doh_all(
    host: str, timeout: float = DOH_TIMEOUT
) -> tuple[list[str], Optional[str], Optional[float]]:
    """Return (ips, endpoint, latency_ms) for the first DoH server with A records."""
    for endpoint in DOH_ENDPOINTS:
        try:
            t0 = time.perf_counter()
            r = requests.get(
                endpoint,
                params={"name": host, "type": "A"},
                headers={"accept": "application/dns-json"},
                timeout=timeout,
            )
            latency_ms = (time.perf_counter() - t0) * 1000
            if not r.ok:
                logger.debug("DoH %s returned %s for %s", endpoint, r.status_code, host)
                continue

            ct = r.headers.get("content-type", "")
            if "dns-message" in ct:
                ips = _parse_dns_wire_a_records(r.content)
                if ips:
                    logger.debug(
                        "DoH (wire) resolved %s via %s -> %s (%.0fms)",
                        host, endpoint, ips, latency_ms,
                    )
                    return ips, endpoint, latency_ms
                continue

            ips = _unique(
                [
                    ans.get("data")
                    for ans in r.json().get("Answer", [])
                    if ans.get("type") == 1 and ans.get("data")
                ]
            )
            if ips:
                logger.debug(
                    "DoH (json) resolved %s via %s -> %s (%.0fms)",
                    host, endpoint, ips, latency_ms,
                )
                return ips, endpoint, latency_ms
        except (requests.RequestException, json.JSONDecodeError) as e:
            logger.debug("DoH %s failed for %s: %s", endpoint, host, e)
    return [], None, None


def resolve_doh(
    host: str, timeout: float = DOH_TIMEOUT
) -> tuple[Optional[str], Optional[str], Optional[float]]:
    """Return (ip, endpoint, latency_ms) for the first DoH server with an A record."""
    ips, endpoint, latency_ms = resolve_doh_all(host, timeout=timeout)
    return (ips[0], endpoint, latency_ms) if ips else (None, None, None)
