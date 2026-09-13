"""
DNS Intelligence Service.
Resolves DNS records for a given domain using dnspython.
All failures are handled gracefully — a DNS error never crashes a scan.
"""
from __future__ import annotations

import asyncio
from typing import Dict, Any, List, Optional

from app.utils.logger import get_logger

logger = get_logger(__name__)

DNS_TIMEOUT = 5  # seconds


async def resolve_dns(domain: str) -> Dict[str, Any]:
    """
    Resolve common DNS record types for a domain.
    Returns a structured dict. Never raises — returns status='error' on failure.
    """
    try:
        import dns.resolver
        import dns.exception

        result: Dict[str, Any] = {
            "a": [],
            "aaaa": [],
            "mx": [],
            "ns": [],
            "txt": [],
            "cname": None,
            "status": "ok",
        }

        resolver = dns.resolver.Resolver()
        resolver.timeout = DNS_TIMEOUT
        resolver.lifetime = DNS_TIMEOUT

        async def query(rtype: str) -> List[str]:
            try:
                loop = asyncio.get_event_loop()
                answers = await loop.run_in_executor(
                    None, lambda: resolver.resolve(domain, rtype)
                )
                return [str(r) for r in answers]
            except (
                dns.resolver.NXDOMAIN,
                dns.resolver.NoAnswer,
                dns.resolver.Timeout,
                dns.resolver.NoNameservers,
                dns.exception.DNSException,
            ):
                return []
            except Exception:
                return []

        a_res, aaaa_res, mx_res, ns_res, txt_res, cname_res = await asyncio.gather(
            query("A"),
            query("AAAA"),
            query("MX"),
            query("NS"),
            query("TXT"),
            query("CNAME"),
            return_exceptions=True,
        )

        result["a"] = a_res if isinstance(a_res, list) else []
        result["aaaa"] = aaaa_res if isinstance(aaaa_res, list) else []
        result["mx"] = mx_res if isinstance(mx_res, list) else []
        result["ns"] = ns_res if isinstance(ns_res, list) else []
        result["txt"] = txt_res if isinstance(txt_res, list) else []
        result["cname"] = cname_res[0] if isinstance(cname_res, list) and cname_res else None

        return result

    except ImportError:
        logger.warning("dnspython not installed — DNS resolution unavailable")
        return {"status": "unavailable"}
    except Exception as exc:
        logger.warning(f"DNS resolution failed for {domain}: {exc}")
        return {"status": "error", "detail": str(exc)}


def format_dns_for_display(dns_info: Dict[str, Any]) -> str:
    """Format DNS info as text for the frontend whois/dns tab display."""
    if dns_info.get("status") in ("error", "unavailable", "not_configured"):
        return f"DNS lookup unavailable: {dns_info.get('status', 'unknown')}"

    lines = []
    if dns_info.get("a"):
        for ip in dns_info["a"]:
            lines.append(f"A\t\t{ip}")
    if dns_info.get("aaaa"):
        for ip in dns_info["aaaa"]:
            lines.append(f"AAAA\t\t{ip}")
    if dns_info.get("mx"):
        for mx in dns_info["mx"]:
            lines.append(f"MX\t\t{mx}")
    if dns_info.get("ns"):
        for ns in dns_info["ns"]:
            lines.append(f"NS\t\t{ns}")
    if dns_info.get("txt"):
        for txt in dns_info["txt"]:
            lines.append(f"TXT\t\t{txt}")
    if dns_info.get("cname"):
        lines.append(f"CNAME\t\t{dns_info['cname']}")

    return "\n".join(lines) if lines else "No DNS records found"


async def get_primary_ip(domain: str) -> Optional[str]:
    """Get the first A record IP for a domain."""
    try:
        info = await resolve_dns(domain)
        a_records = info.get("a", [])
        return a_records[0] if a_records else None
    except Exception:
        return None
