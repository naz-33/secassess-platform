import pytest
from app.modules.scans import validate_scan_target
from app.modules.scans.adapters import NmapAdapter, DnsAdapter


def test_target_validation_valid_inputs():
    """Verify standard legitimate targets pass validation."""
    assert validate_scan_target("localhost") == "localhost"
    assert validate_scan_target("127.0.0.1") == "127.0.0.1"
    assert validate_scan_target("::1") == "::1"
    assert validate_scan_target("192.168.1.100") == "192.168.1.100"
    assert validate_scan_target("api.example.com") == "api.example.com"
    assert validate_scan_target("http://localhost:3000") == "localhost"
    assert validate_scan_target("https://secure.example.com/api/v1") == "secure.example.com"
    assert validate_scan_target("127.0.0.1:8080") == "127.0.0.1"


@pytest.mark.parametrize(
    "malicious_target",
    [
        "localhost; rm -rf /",
        "127.0.0.1 && whoami",
        "example.com | cat /etc/passwd",
        "$(whoami).evil.com",
        "`id`.test.local",
        "127.0.0.1 > /dev/null",
        "127.0.0.1 < /tmp/input",
        "test (injection)",
        "host!name",
        "host'name",
        'host"name',
        "host\\name",
        "host\nname",
        "host\rname",
        "host\tname",
        "host name with space",
    ],
)
def test_target_validation_shell_metacharacters_rejected(malicious_target: str):
    """Verify any target containing shell metacharacters or whitespace is rejected."""
    with pytest.raises(ValueError, match="forbidden shell metacharacters or whitespace"):
        validate_scan_target(malicious_target)


@pytest.mark.parametrize(
    "flag_target",
    [
        "-A",
        "--script=vuln",
        "-sS",
        "-oX /tmp/pwn",
        "-T5",
        "--version-all",
    ],
)
def test_target_validation_flag_injection_rejected(flag_target: str):
    """Verify target starting with '-' is rejected to prevent flag injection."""
    with pytest.raises(ValueError, match="cannot start with '-'"):
        validate_scan_target(flag_target)


def test_nmap_adapter_safe_command_generation():
    """Verify Nmap adapter builds safe command argv without string concatenation."""
    adapter = NmapAdapter()
    argv = adapter.build_command("192.168.1.1", {"top_ports": 50, "timing": "-T3", "service_version": True})

    assert isinstance(argv, list)
    assert "-sV" in argv
    assert "-oX" in argv
    assert "-" in argv
    assert "-T3" in argv
    assert "--top-ports" in argv
    assert "50" in argv
    assert argv[-1] == "192.168.1.1"


@pytest.mark.parametrize(
    "disallowed_options",
    [
        {"arbitrary_flag": "-A"},
        {"timing": "-T5"},  # Aggressive T5 is disallowed
        {"top_ports": 99999},  # Exceeds max 1000
        {"ports": "80; rm -rf /"},  # Metacharacters in port range
        {"script": "vuln"},  # Scripts disallowed in safe profile
    ],
)
def test_nmap_adapter_disallowed_options_rejected(disallowed_options: dict):
    """Verify unsafe or unapproved options are rejected with ValueError."""
    adapter = NmapAdapter()
    with pytest.raises(ValueError):
        adapter.build_command("localhost", disallowed_options)


def test_dns_adapter_disallowed_record_types():
    """Verify DNS adapter rejects unauthorized record types."""
    adapter = DnsAdapter()
    with pytest.raises(ValueError, match="Disallowed DNS record type"):
        adapter.build_command("example.com", {"record_types": ["AXFR"]})

    with pytest.raises(ValueError, match="Disallowed DNS record type"):
        adapter.build_command("example.com", {"record_type": "EVIL"})


def test_dns_adapter_uses_separate_queries_and_reverse_lookup(monkeypatch):
    adapter = DnsAdapter()
    monkeypatch.setattr(adapter, "resolve_executable", lambda: "dig")

    commands = adapter.build_commands("juice-shop")
    assert [command[2] for command in commands] == ["A", "AAAA", "NS", "MX", "TXT"]
    assert all("ANY" not in command for command in commands)

    reverse = adapter.build_commands("172.18.0.10")
    assert reverse == [["dig", "-x", "172.18.0.10", "+noall", "+answer"]]


def test_dns_parser_deduplicates_host_addresses():
    from app.modules.recon import DnsParser

    raw_output = (
        "juice-shop. 60 IN A 172.18.0.10\n"
        "juice-shop. 60 IN A 172.18.0.10\n"
        "juice-shop. 60 IN AAAA fd00::10\n"
    )
    assets = DnsParser().parse(raw_output)
    assert [(asset["type"], asset["value"]) for asset in assets] == [
        ("host", "172.18.0.10"),
        ("host", "fd00::10"),
    ]
