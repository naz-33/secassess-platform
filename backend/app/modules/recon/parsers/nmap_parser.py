"""Nmap XML output parser for extracting discovered hosts, ports, and services."""
import xml.etree.ElementTree as ET
from typing import List, Dict, Any


class NmapParser:
    """Parses raw Nmap XML output into structured candidate assets."""

    def parse(self, raw_output: str) -> List[Dict[str, Any]]:
        """
        Parse raw Nmap XML string into a list of structured asset dicts.

        Args:
            raw_output: XML string produced by Nmap '-oX -'.

        Returns:
            List of dictionaries with keys: 'type', 'value', 'details'.

        Raises:
            ValueError: If XML is malformed or unparseable.
        """
        if not raw_output or not raw_output.strip():
            return []

        try:
            root = ET.fromstring(raw_output.strip())
        except ET.ParseError as exc:
            raise ValueError(f"Failed to parse Nmap XML output: {exc}") from exc

        assets: List[Dict[str, Any]] = []

        # Iterate over all <host> elements
        for host_elem in root.findall("host"):
            # Check host status
            status_elem = host_elem.find("status")
            host_state = status_elem.get("state", "unknown") if status_elem is not None else "unknown"

            # Extract address
            addr_elem = host_elem.find("address")
            host_addr = addr_elem.get("addr", "") if addr_elem is not None else ""
            addr_type = addr_elem.get("addrtype", "") if addr_elem is not None else ""

            # Extract primary hostname if present
            hostname = ""
            hostnames_elem = host_elem.find("hostnames")
            if hostnames_elem is not None:
                h_name_elem = hostnames_elem.find("hostname")
                if h_name_elem is not None:
                    hostname = h_name_elem.get("name", "")

            host_value = host_addr or hostname
            if host_value:
                assets.append({
                    "type": "host",
                    "value": host_value,
                    "details": {
                        "address": host_addr,
                        "addrtype": addr_type,
                        "hostname": hostname,
                        "state": host_state,
                    },
                })

            # Extract open ports and associated services
            ports_elem = host_elem.find("ports")
            if ports_elem is not None:
                for port_elem in ports_elem.findall("port"):
                    port_id_str = port_elem.get("portid", "")
                    protocol = port_elem.get("protocol", "tcp")

                    state_elem = port_elem.find("state")
                    port_state = state_elem.get("state", "") if state_elem is not None else ""

                    # We focus on open ports for asset cataloging
                    if port_state != "open":
                        continue

                    try:
                        port_num = int(port_id_str)
                    except ValueError:
                        port_num = 0

                    assets.append({
                        "type": "port",
                        "value": f"{port_id_str}/{protocol}",
                        "details": {
                            "port": port_num,
                            "protocol": protocol,
                            "state": port_state,
                            "host": host_value,
                        },
                    })

                    # Service detection details
                    service_elem = port_elem.find("service")
                    if service_elem is not None:
                        srv_name = service_elem.get("name", "")
                        product = service_elem.get("product", "")
                        version = service_elem.get("version", "")
                        extrainfo = service_elem.get("extrainfo", "")

                        assets.append({
                            "type": "service",
                            "value": f"{srv_name}:{port_id_str}" if srv_name else f"service:{port_id_str}",
                            "details": {
                                "name": srv_name,
                                "product": product,
                                "version": version,
                                "extrainfo": extrainfo,
                                "port": port_num,
                                "protocol": protocol,
                                "host": host_value,
                            },
                        })

        return assets
