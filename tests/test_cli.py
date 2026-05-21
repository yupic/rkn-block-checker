from unittest.mock import patch

import pytest

from rkn_checker.cli import _run_streaming, main
from rkn_checker.models import CheckResult, Verdict


class TestMutuallyExclusiveFlags:
    def test_white_and_black_together_exits(self):
        with pytest.raises(SystemExit) as ei:
            main(["--white", "--black"])
        assert ei.value.code == 2


class TestValidation:
    def test_workers_zero_exits(self):
        with pytest.raises(SystemExit) as ei:
            main(["--workers", "0"])
        assert ei.value.code == 2

    def test_timeout_negative_exits(self):
        with pytest.raises(SystemExit) as ei:
            main(["--timeout", "-1"])
        assert ei.value.code == 2


class TestJsonModeTimeout:
    @patch("rkn_checker.cli.get_self_info", return_value={"ip": "1.2.3.4"})
    @patch("rkn_checker.core.check_urls_parallel", return_value=[])
    def test_json_mode_passes_timeout_to_get_self_info(self, mock_parallel, mock_self):
        main(["--json", "--timeout", "3.0"])
        mock_self.assert_called_with(timeout=3.0)

    @patch("rkn_checker.cli.get_self_info", return_value=None)
    @patch("rkn_checker.core.check_urls_parallel", return_value=[])
    def test_json_mode_enables_doh_only_with_flag(self, mock_parallel, mock_self):
        main(["--json", "--no-self-info", "--doh"])
        assert mock_parallel.call_args.kwargs["enable_doh"] is True

    @patch("rkn_checker.cli.get_self_info", return_value=None)
    @patch("rkn_checker.core.check_urls_parallel", return_value=[])
    def test_no_self_info_flag_skips_lookup(self, mock_parallel, mock_self):
        main(["--json", "--no-self-info"])
        mock_self.assert_not_called()


class TestStreamingNoSelfInfo:
    @patch("rkn_checker.cli.print_header")
    @patch("rkn_checker.cli._run_streaming", return_value=([], []))
    def test_no_self_info_passes_empty_dict_to_header(self, mock_stream, mock_header):
        main(["--no-self-info"])
        mock_header.assert_called_with({})


class TestCliOutputOrder:
    @patch("rkn_checker.cli.print_section")
    @patch("rkn_checker.cli.print_result")
    def test_table_prints_in_input_order_after_parallel_checks(
        self, mock_print_result, mock_print_section
    ):
        def check_in_completion_order(name, url, timeout, enable_doh=False):
            import time

            delays = {"a": 0.01, "b": 0.02, "c": 0.03}
            time.sleep(delays[name])
            return CheckResult(name=name, url=url, verdict=Verdict.OK)

        urls = {
            "c": "https://c.example/",
            "b": "https://b.example/",
            "a": "https://a.example/",
        }

        with patch("rkn_checker.cli.check_url", side_effect=check_in_completion_order):
            results, _ = _run_streaming(
                run_white=True,
                run_black=False,
                white_urls=urls,
                black_urls={},
                workers=3,
                timeout=1.0,
            )

        assert [r.name for r in results] == ["c", "b", "a"]
        assert [call.args[0].name for call in mock_print_result.call_args_list] == [
            "c",
            "b",
            "a",
        ]
