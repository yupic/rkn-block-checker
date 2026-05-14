from unittest.mock import patch, MagicMock

from rkn_checker.dns import (
    DOH_ENDPOINTS,
    resolve_doh,
    resolve_doh_all,
    resolve_system,
    resolve_system_all,
)


class TestResolveSystem:
    @patch(
        "rkn_checker.dns.socket.getaddrinfo",
        return_value=[
            (2, 1, 6, "", ("1.2.3.4", 0)),
            (2, 1, 6, "", ("1.2.3.5", 0)),
        ],
    )
    def test_returns_ip_on_success(self, mock_gethost):
        assert resolve_system("example.com") == "1.2.3.4"
        assert resolve_system_all("example.com") == ["1.2.3.4", "1.2.3.5"]

    @patch("rkn_checker.dns.socket.getaddrinfo", side_effect=__import__("socket").gaierror("fail"))
    def test_returns_none_on_gaierror(self, mock_gethost):
        assert resolve_system("example.com") is None
        assert resolve_system_all("example.com") == []


class TestResolveDoh:
    @patch("rkn_checker.dns.requests.get")
    def test_returns_ip_from_answer(self, mock_get):
        resp = MagicMock()
        resp.ok = True
        resp.headers = {}
        resp.json.return_value = {"Answer": [{"type": 1, "data": "9.9.9.9"}]}
        mock_get.return_value = resp
        ip, endpoint, latency_ms = resolve_doh("example.com")
        assert ip == "9.9.9.9"
        assert endpoint == DOH_ENDPOINTS[0]
        assert latency_ms is not None

    @patch("rkn_checker.dns.requests.get")
    def test_returns_all_a_records_from_answer(self, mock_get):
        resp = MagicMock()
        resp.ok = True
        resp.headers = {}
        resp.json.return_value = {
            "Answer": [
                {"type": 1, "data": "9.9.9.9"},
                {"type": 28, "data": "2001:db8::1"},
                {"type": 1, "data": "149.112.112.112"},
            ]
        }
        mock_get.return_value = resp
        ips, endpoint, latency_ms = resolve_doh_all("example.com")
        assert ips == ["9.9.9.9", "149.112.112.112"]
        assert endpoint == DOH_ENDPOINTS[0]
        assert latency_ms is not None

    @patch("rkn_checker.dns.requests.get")
    def test_returns_none_on_http_error(self, mock_get):
        resp = MagicMock()
        resp.ok = False
        mock_get.return_value = resp
        assert resolve_doh("example.com") == (None, None, None)

    @patch("rkn_checker.dns.requests.get", side_effect=__import__("requests").exceptions.RequestException("network error"))
    def test_returns_none_on_request_exception(self, mock_get):
        assert resolve_doh("example.com") == (None, None, None)

    @patch("rkn_checker.dns.requests.get")
    def test_passes_timeout_param(self, mock_get):
        resp = MagicMock()
        resp.ok = False
        mock_get.return_value = resp
        resolve_doh("example.com", timeout=2.5)
        assert mock_get.call_count == len(DOH_ENDPOINTS)
        for call in mock_get.call_args_list:
            assert call[1]["timeout"] == 2.5
