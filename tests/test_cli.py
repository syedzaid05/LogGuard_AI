"""CLI tests."""
from logguard import cli


def test_rules_command(capsys):
    assert cli.main(["rules"]) == 0
    out = capsys.readouterr().out
    assert "LG001" in out
    assert "CQ001" in out


def test_providers_command(capsys):
    assert cli.main(["providers"]) == 0
    out = capsys.readouterr().out
    assert "groq" in out and "gemini" in out


def test_scan_file_ok(tmp_path, capsys):
    target = tmp_path / "app.py"
    target.write_text("x = 1\n", encoding="utf-8")
    assert cli.main(["scan", str(target)]) == 0
    assert "finding(s)" in capsys.readouterr().out


def test_scan_fail_on(tmp_path, capsys):
    target = tmp_path / "bad.py"
    target.write_text("x = eval('1')\n", encoding="utf-8")
    assert cli.main(["scan", str(target), "--fail-on", "High"]) == 1
    assert cli.main(["scan", str(target), "--fail-on", "Critical"]) == 0
    capsys.readouterr()


def test_scan_writes_json(tmp_path, capsys):
    target = tmp_path / "app.py"
    target.write_text("import os\nos.system('ls')\n", encoding="utf-8")
    out_json = tmp_path / "report.json"
    assert cli.main(["scan", str(target), "--json", str(out_json)]) == 0
    assert out_json.exists()
    capsys.readouterr()


def test_scan_missing_target(capsys):
    assert cli.main(["scan", "this is not a repo or path"]) == 2
