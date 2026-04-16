from core.scanner import DEFAULT_PROFILE, NetworkScanner, SCAN_PROFILES


class FakeHostData(dict):
    def all_protocols(self):
        return [proto for proto in ("tcp", "udp", "sctp") if proto in self]


class FakeNmap:
    def __init__(self, include_host=True):
        self.include_host = include_host
        self.calls = []
        self.host_data = FakeHostData(
            {
                "tcp": {
                    22: {"name": "ssh", "product": "OpenSSH", "version": "9.0", "state": "open"},
                    9999: {"name": "custom", "product": "svc", "version": "1.0", "state": "open"},
                },
                "osmatch": [{"name": "TestOS"}],
            }
        )

    def scan(self, hosts, arguments):
        self.calls.append((hosts, arguments))

    def all_hosts(self):
        return ["127.0.0.1"] if self.include_host else []

    def __getitem__(self, target):
        return self.host_data


def _build_scanner_with_fake_nmap(fake_nmap, monkeypatch):
    scanner = object.__new__(NetworkScanner)
    scanner.nm = fake_nmap
    monkeypatch.setattr(scanner, "_save_initial_baseline", lambda _results: None)
    return scanner


def test_scan_invalid_profile_falls_back_to_default(monkeypatch):
    fake_nmap = FakeNmap()
    scanner = _build_scanner_with_fake_nmap(fake_nmap, monkeypatch)

    result = scanner.scan_localhost(profile="invalid-profile")

    assert result["profile"] == DEFAULT_PROFILE
    assert fake_nmap.calls[0][1] == SCAN_PROFILES[DEFAULT_PROFILE]["args"]


def test_scan_shapes_result_and_risk_flags(monkeypatch):
    fake_nmap = FakeNmap()
    scanner = _build_scanner_with_fake_nmap(fake_nmap, monkeypatch)

    result = scanner.scan_localhost(profile="quick")
    ports_by_num = {entry["port"]: entry for entry in result["ports"]}

    assert result["os_guess"] == "TestOS"
    assert ports_by_num[22]["is_critical"] is True
    assert ports_by_num[22]["service"] == "SSH - Secure Shell"
    assert ports_by_num[9999]["is_critical"] is False
    assert ports_by_num[9999]["version"] == "custom svc 1.0"
    assert result["profile"] == "quick"


def test_scan_returns_empty_ports_when_target_not_in_results(monkeypatch):
    fake_nmap = FakeNmap(include_host=False)
    scanner = _build_scanner_with_fake_nmap(fake_nmap, monkeypatch)

    result = scanner.scan_localhost(profile="standard")

    assert result["ports"] == []

