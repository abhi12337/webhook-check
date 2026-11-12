import json
import subprocess
import sys
from pathlib import Path

import pytest

from webhook_check.cli import main
from webhook_check.findings import RULES, SEVERITIES, mask_secret

FIX = Path(__file__).parent / "fixtures"
ROOT = Path(__file__).parent.parent


def run(capsys, *argv):
    code = main(list(argv))
    out, err = capsys.readouterr()
    return code, out, err


def test_scan_vulnerable_text_report(capsys):
    code, out, _ = run(capsys, "scan", str(FIX / "node_vulnerable"), "--no-color")
    assert code == 1
    assert "CRITICAL WHK001" in out and "app/api/webhooks/stripe/route.ts:8" in out
    assert "why:" in out and "fix:" in out and "constructEventAsync" in out
    assert "Exit code: 1" in out


def test_scan_clean_exits_0(capsys):
    code, out, _ = run(capsys, "scan", str(FIX / "py_clean"), str(FIX / "node_clean"), "--no-color")
    assert code == 0
    assert "No findings" in out and "16 webhook handler(s)" not in out
    assert "14 webhook handler(s)" in out and "2 Razorpay payment-verification endpoint(s)" in out


def test_json_report_shape(capsys):
    code, out, _ = run(capsys, "scan", str(FIX / "py_vulnerable"), "--json")
    doc = json.loads(out)
    assert code == 1 and doc["exit_code"] == 1 and doc["tool"] == "webhook-check"
    assert set(doc["summary"]) == set(SEVERITIES)
    first = doc["findings"][0]
    assert first["severity"] == "critical"
    assert {"rule_id", "severity", "message", "file", "line", "evidence", "title", "why", "fix"} <= set(first)
    h = doc["handlers"][0]
    assert {"file", "line", "handler", "framework", "provider", "kind", "signature_verified"} <= set(h)


def test_fail_on_min_severity_and_disable(capsys):
    assert run(capsys, "scan", str(FIX / "py_vulnerable"), "--fail-on", "never")[0] == 0
    code, out, _ = run(capsys, "scan", str(FIX / "py_vulnerable"), "--json", "--min-severity", "critical")
    assert {f["severity"] for f in json.loads(out)["findings"]} == {"critical"}
    code, out, _ = run(capsys, "scan", str(FIX / "py_vulnerable"), "--json", "--disable", "WHK001",
                       "--disable", "whk006", "--disable", "WHK002", "--disable", "WHK004", "--disable", "WHK005")
    ids = {f["rule_id"] for f in json.loads(out)["findings"]}
    assert ids == {"WHK003", "WHK007", "WHK008"} and code == 0    # medium/low only: below --fail-on high
    assert run(capsys, "scan", str(FIX / "py_vulnerable"), "--disable", "WHK001", "--disable", "WHK006",
               "--disable", "WHK002", "--disable", "WHK004", "--disable", "WHK005", "--fail-on", "low")[0] == 1


def test_unknown_rule_and_missing_path(capsys, tmp_path):
    code, _, err = run(capsys, "scan", str(tmp_path / "nope"))
    assert code == 2 and "does not exist" in err
    code, _, err = run(capsys, "scan", str(tmp_path), "--disable", "WHK999")
    assert code == 2 and "unknown rule" in err


def test_bad_option_is_usage_error(capsys):
    with pytest.raises(SystemExit) as e:
        main(["scan", "--fail-on", "sometimes"])
    assert e.value.code == 2


def test_scan_single_file(capsys):
    code, out, _ = run(capsys, "scan", str(FIX / "node_vulnerable" / "server" / "hono.ts"), "--json")
    doc = json.loads(out)
    assert code == 1 and sorted(f["rule_id"] for f in doc["findings"]) == ["WHK001", "WHK007"]


def test_output_never_contains_secrets(capsys, make_repo, fake):
    root = make_repo({
        "server.ts": (f'const STRIPE_WEBHOOK_SECRET = "{fake["whsec"]}";\n'
                      f'const hookSecret = process.env.HOOK_SECRET || "{fake["generic"]}";\n'
                      'app.post("/webhooks/stripe", (req, res) => {\n'
                      f'  const e = stripe.webhooks.constructEvent(req.body, req.headers["stripe-signature"], "{fake["whsec"]}");\n'
                      '  res.end();\n});\n'),
        "settings.py": f'STRIPE_WEBHOOK_SECRET = "{fake["whsec"]}"\nGITHUB_WEBHOOK_SECRET = "{fake["generic"]}"\n',
    })
    for fmt in ([], ["--json"]):
        code, out, _ = run(capsys, "scan", str(root), "--no-color", *fmt)
        assert code == 1
        for secret in fake.values():
            assert secret not in out
            assert secret[:8] not in out      # never more than 4 leading characters


def test_mask_secret_shows_at_most_four_chars():
    assert mask_secret("abcdefghijklmnopqrstuvwxyz") == "abcd**** (26 chars)"
    assert mask_secret("abcdefgh") == "ab**** (8 chars)"
    assert mask_secret("abc") == "**** (3 chars)"


def test_tests_folders_skipped_unless_included(capsys, make_repo):
    vuln = (FIX / "node_vulnerable" / "server" / "hono.ts").read_text()
    root = make_repo({"tests/hono.ts": vuln, "hono.test.ts": vuln, "__mocks__/hono.ts": vuln})
    code, out, _ = run(capsys, "scan", str(root), "--json")
    assert code == 0 and json.loads(out)["findings"] == []
    code, out, _ = run(capsys, "scan", str(root), "--json", "--include-tests")
    assert code == 1 and len(json.loads(out)["findings"]) == 6


def test_exclude_glob(capsys, copy_fixture):
    root = copy_fixture("node_vulnerable")
    code, out, _ = run(capsys, "scan", str(root), "--exclude", "server/*", "--exclude", "app/*",
                       "--exclude", "pages", "--json")
    assert code == 0 and json.loads(out)["files_scanned"] == 0


def test_node_modules_and_build_output_skipped(capsys, make_repo):
    vuln = (FIX / "node_vulnerable" / "server" / "hono.ts").read_text()
    root = make_repo({"node_modules/x/hono.ts": vuln, ".next/server/hono.js": vuln, "dist/hono.js": vuln})
    code, out, _ = run(capsys, "scan", str(root), "--json")
    assert code == 0 and json.loads(out)["files_scanned"] == 0


def test_no_handlers_message(capsys, make_repo):
    root = make_repo({"index.ts": "export const x = 1;\n"})
    code, out, _ = run(capsys, "scan", str(root), "--no-color")
    assert code == 0 and "No webhook handlers found" in out


def test_rules_lists_every_rule(capsys):
    code, out, _ = run(capsys, "rules")
    assert code == 0
    for rid in RULES:
        assert rid in out


def test_every_rule_has_title_why_fix():
    for r in RULES.values():
        assert r.title and len(r.why) > 40 and len(r.fix) > 40


def test_module_entry_point():
    env = {"PYTHONPATH": str(ROOT / "src")}
    if sys.platform == "win32":
        env.update({"SYSTEMROOT": "C:\\Windows", "PATH": ""})
    res = subprocess.run([sys.executable, "-m", "webhook_check", "scan", str(FIX / "py_clean"), "--brief"],
                         capture_output=True, text=True, env=env)
    assert res.returncode == 0, res.stderr
    assert "No findings" in res.stdout


def test_no_network_imports():
    """The scanner must never be able to contact anything."""
    src = ROOT / "src" / "webhook_check"
    for p in src.glob("*.py"):
        text = p.read_text(encoding="utf-8")
        for mod in ("urllib.request", "http.client", "socket", "requests", "httpx", "subprocess"):
            assert f"import {mod}" not in text and f"from {mod} import" not in text, (p.name, mod)


@pytest.mark.parametrize("name", ["py_vulnerable", "node_vulnerable"])
def test_every_finding_has_location_evidence_and_specific_fix(capsys, name):
    _, out, _ = run(capsys, "scan", str(FIX / name), "--json")
    for f in json.loads(out)["findings"]:
        assert f["file"] and f["line"] and f["evidence"] and f["fix"]
        assert f["fix"] != RULES[f["rule_id"]].fix, f["rule_id"]      # tailored, not the generic text


def test_demo_generator(tmp_path, capsys):
    res = subprocess.run([sys.executable, str(ROOT / "examples" / "make_demo.py"), str(tmp_path / "demo")],
                         capture_output=True, text=True)
    assert res.returncode == 0, res.stderr
    code, out, _ = run(capsys, "scan", str(tmp_path / "demo"), "--json")
    doc = json.loads(out)
    assert code == 1
    assert {f["rule_id"] for f in doc["findings"]} == set(RULES)       # the demo exercises every rule


def test_readme_examples_match_real_output(tmp_path, monkeypatch, capsys):
    """README says its output is produced by the tool, not hand-edited: keep that true."""
    import re

    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    subprocess.run([sys.executable, str(ROOT / "examples" / "make_demo.py"), str(tmp_path / "demo-webhooks")],
                   check=True, capture_output=True)
    monkeypatch.chdir(tmp_path)
    for argv in (["scan", "demo-webhooks/web/server/express.ts", "--brief"],
                 ["scan", "demo-webhooks/web/app/api/webhooks/stripe/route.ts"],
                 ["scan", "demo-webhooks", "--brief"]):
        _, out, _ = run(capsys, *argv, "--no-color")
        assert out.strip() in readme, argv
    monkeypatch.chdir(ROOT)
    _, out, _ = run(capsys, "scan", "tests/fixtures/node_clean", "tests/fixtures/py_clean", "--no-color")
    assert out.strip() in readme
    assert not re.search(r"whsec_[A-Za-z0-9]{8}", readme)
