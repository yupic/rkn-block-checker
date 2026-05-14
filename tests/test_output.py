from rkn_checker.models import CheckResult, Verdict
from rkn_checker import output
from rkn_checker.output import print_result


def test_print_result_explains_non_200_http_status(capsys):
    result = CheckResult(
        name="chatgpt",
        url="https://chatgpt.com",
        verdict=Verdict.OK,
        status_code=403,
        notes=["DoH: https://cloudflare-dns.com/dns-query -> 104.18.32.47 (59ms)"],
    )

    print_result(result)

    assert "HTTP code 403 Forbidden" in capsys.readouterr().out


def test_print_result_does_not_explain_http_200(capsys):
    result = CheckResult(
        name="chatgpt",
        url="https://chatgpt.com",
        verdict=Verdict.OK,
        status_code=200,
    )

    print_result(result)

    assert "HTTP code 200 OK" not in capsys.readouterr().out


def test_colored_http_status_marks_4xx_red(monkeypatch):
    monkeypatch.setattr(output.C, "RED", "<red>")
    monkeypatch.setattr(output.C, "RESET", "</>")

    assert output._colored_http_status("403 ", 403) == "<red>403 </>"
    assert output._colored_http_status("500 ", 500) == "500 "
    assert output._colored_http_status("200 ", 200) == "200 "
