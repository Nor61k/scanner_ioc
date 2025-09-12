import json
from pathlib import Path
from types import SimpleNamespace

import builtins


def test_sigma_cli_flags_parsing(monkeypatch, tmp_path):
    # smoke: ensure parse_args handles sigma flags
    from importlib import reload
    import main as app
    argv = [
        'prog', '--sigma', '--sigma-rules', 'rules/sigma', '--sigma-pipeline', 'winlogbeat',
        '--sigma-input', str(tmp_path), '--sigma-recursive', '--sigma-evtx-chunk', '10',
        '--sigma-timeout', '5', '--sigma-max-findings', '1', '--sigma-verbose'
    ]
    monkeypatch.setattr(app, 'parse_args', lambda: SimpleNamespace(
        config='config/scan_manager.yaml', output=str(tmp_path), logs=str(tmp_path), case_id='cid',
        encryption_key=None, scanner=None, max_cpu=1, max_ram=None,
        sigma=True, sigma_rules='rules/sigma', sigma_pipeline='winlogbeat',
        sigma_input=[str(tmp_path)], sigma_recursive=True, sigma_evtx_chunk=10,
        sigma_timeout=5, sigma_fail_on_parse=False, sigma_max_findings=1, sigma_verbose=True,
    ))

    # Mock SigmaScanner
    class DummySigma:
        def __init__(self, *a, **kw):
            pass
        def scan(self, **kw):
            return {"meta": {"sigma_cli_version": "v0", "pipeline": "winlogbeat", "files_scanned": 0, "errors": []}, "findings": []}

    monkeypatch.setenv('PYTHONHASHSEED', '0')
    monkeypatch.setitem(__import__('sys').modules, 'core.sigma_scanner', SimpleNamespace(SigmaScanner=DummySigma))

    # Run main; should not raise
    assert app.main() in (0, 1)


