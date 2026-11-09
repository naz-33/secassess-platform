"""Pluggable scanner execution adapters."""
from app.modules.scans.adapters.base import ToolAdapter
from app.modules.scans.adapters.nmap import NmapAdapter
from app.modules.scans.adapters.dns import DnsAdapter, is_ip_or_localhost

__all__ = ["ToolAdapter", "NmapAdapter", "DnsAdapter", "is_ip_or_localhost"]

