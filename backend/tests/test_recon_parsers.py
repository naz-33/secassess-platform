from pathlib import Path
import pytest
from app.modules.recon import NmapParser, DnsParser

FIXTURES_DIR = Path(__file__).parent / "fixtures"


def test_nmap_parser_with_open_ports():
    """Verify Nmap parser correctly extracts hosts, open ports, and service metadata."""
    xml_content = (FIXTURES_DIR / "nmap_open_ports.xml").read_text(encoding="utf-8")
    parser = NmapParser()
    assets = parser.parse(xml_content)

    assert len(assets) >= 4

    # Check host asset
    hosts = [a for a in assets if a["type"] == "host"]
    assert len(hosts) == 1
    assert hosts[0]["value"] == "192.168.1.50"
    assert hosts[0]["details"]["hostname"] == "web-server.local"
    assert hosts[0]["details"]["state"] == "up"

    # Check open ports (port 22 and 80 open; port 443 was closed)
    ports = [a for a in assets if a["type"] == "port"]
    assert len(ports) == 2
    port_vals = {p["value"] for p in ports}
    assert "22/tcp" in port_vals
    assert "80/tcp" in port_vals
    assert "443/tcp" not in port_vals

    # Check services metadata
    services = [a for a in assets if a["type"] == "service"]
    assert len(services) == 2
    srv_names = {s["details"]["name"] for s in services}
    assert "ssh" in srv_names
    assert "http" in srv_names

    # Check product/version in details
    nginx_srv = next(s for s in services if s["details"]["name"] == "http")
    assert nginx_srv["details"]["product"] == "nginx"
    assert nginx_srv["details"]["version"] == "1.18.0"


def test_nmap_parser_empty_or_down():
    """Verify parser handles scan with no open ports without error."""
    xml_content = (FIXTURES_DIR / "nmap_empty.xml").read_text(encoding="utf-8")
    parser = NmapParser()
    assets = parser.parse(xml_content)

    # Only host entry might exist or empty list; ports and services must be 0
    ports = [a for a in assets if a["type"] == "port"]
    services = [a for a in assets if a["type"] == "service"]
    assert len(ports) == 0
    assert len(services) == 0


def test_nmap_parser_malformed_xml():
    """Verify malformed XML raises ValueError."""
    xml_content = (FIXTURES_DIR / "nmap_malformed.xml").read_text(encoding="utf-8")
    parser = NmapParser()
    with pytest.raises(ValueError, match="Failed to parse Nmap XML"):
        parser.parse(xml_content)


def test_nmap_parser_prefers_http_for_table_guess_on_tcp_3000():
    xml_content = (FIXTURES_DIR / "nmap_open_ports.xml").read_text(encoding="utf-8")
    xml_content = (
        xml_content.replace('portid="80"', 'portid="3000"')
        .replace(
            '<service name="http" product="nginx" version="1.18.0" extrainfo="Ubuntu" method="probed"/>',
            '<service name="hbci" method="table"/>',
        )
    )

    assets = NmapParser().parse(xml_content)
    service = next(asset for asset in assets if asset["type"] == "service" and asset["value"].endswith(":3000"))

    assert service["value"] == "http:3000"
    assert service["details"]["name"] == "http"


def test_dns_parser_dig_records():
    """Verify DNS parser extracts records into host and service asset dicts."""
    dig_content = (FIXTURES_DIR / "dig_sample.txt").read_text(encoding="utf-8")
    parser = DnsParser()
    assets = parser.parse(dig_content)

    assert len(assets) == 6

    # Verify A record
    a_rec = next(a for a in assets if a["details"].get("record_type") == "A")
    assert a_rec["type"] == "host"
    assert a_rec["value"] == "93.184.216.34"
    assert a_rec["details"]["name"] == "example.com"
    assert a_rec["details"]["ttl"] == 300

    # Verify MX service record
    mx_rec = next(a for a in assets if a["details"].get("record_type") == "MX")
    assert mx_rec["type"] == "service"
    assert "mail.example.com." in mx_rec["details"]["value"]

    # Verify TXT service record
    txt_rec = next(a for a in assets if a["details"].get("record_type") == "TXT")
    assert txt_rec["type"] == "service"
    assert "v=spf1 -all" in txt_rec["details"]["value"]


def test_dns_parser_localhost_mode():
    """Verify DNS parser returns clean empty list when localhost notice is encountered."""
    parser = DnsParser()
    notice = "No DNS records for this target type (localhost or IP address)."
    assets = parser.parse(notice)
    assert assets == []
