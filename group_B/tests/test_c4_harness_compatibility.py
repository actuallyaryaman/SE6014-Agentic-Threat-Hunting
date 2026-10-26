"""Exercise real historical/current C4 interfaces without services or model calls."""
import importlib
import json
from pathlib import Path
import shutil

import pytest

REPO = Path(__file__).resolve().parents[2]
LEGACY = 'ae8b316730fdabcbe90929b6869c1a8f8bf0eef4'
CURRENT = '5e76ccf6262fc756a0b5c5fce3d11eb09fac97c4'


@pytest.fixture
def demo(tmp_path, monkeypatch):
    monkeypatch.syspath_prepend(str(REPO / 'group_B/scripts'))
    module = importlib.import_module('group_B.scripts.check_onboarding_hunt_demo')
    original_output = module.subprocess.check_output
    def script_output(args, **kwargs):
        if args[:2] == ['git', 'show']:
            name = 'legacy' if args[2].startswith(LEGACY + ':') else 'current'
            return (REPO / 'group_B/tests/fixtures/c4_api' / (name + '.py')).read_bytes()
        return original_output(args, **kwargs)
    monkeypatch.setattr(module.subprocess, 'check_output', script_output)
    monkeypatch.setattr(module, 'command', lambda *args: args[-1])
    test = module.HuntDemo.__new__(module.HuntDemo)
    test.root = tmp_path / 'work'
    test.root.mkdir()
    test.report = {'cases': []}
    test.require_c4_match = False
    output = tmp_path / 'output'
    for name in ('attack', 'attack-repeat'):
        destination = output / name
        destination.mkdir(parents=True)
        shutil.copy2(REPO / 'group_B/tests/c2_c3_evidence' / name / 'result.json', destination / 'result.json')
    return test, output


@pytest.mark.parametrize('ref,checks', [(LEGACY, 7), (CURRENT, 16)])
def test_supports_real_old_and_new_c4_interfaces(demo, ref, checks):
    test, output = demo
    test.compare_c4(ref, output)
    assert test.report['c4']['checks'] == checks
    assert test.report['c4']['status'] == 'compared'
    assert 'Matched checks' in (output / 'c4-comparison.md').read_text()
    assert not json.loads((output / 'c4-comparison.json').read_text())['errors']


def test_validation_failure_is_retained_and_fails_the_harness(demo):
    test, output = demo
    (output / 'attack/result.json').write_text('{}')
    with pytest.raises(ValueError, match='C4 input validation failed'):
        test.compare_c4(CURRENT, output)
    assert test.report['c4']['status'] == 'invalid_input'
    assert json.loads((output / 'c4-comparison.json').read_text())['errors']
    assert 'INVALID INPUT' in (output / 'c4-comparison.md').read_text()


def test_differences_are_reported_and_strict_mode_can_fail(demo):
    test, output = demo
    path = output / 'attack-repeat/result.json'
    data = json.loads(path.read_text())
    data['hypothesis'] = 'A different hypothesis'
    path.write_text(json.dumps(data))
    test.compare_c4(CURRENT, output)
    assert not test.report['c4']['all_match']
    assert 'hypothesis' in test.report['c4']['differing_fields']
    test.require_c4_match = True
    with pytest.raises(AssertionError, match='C4 repeatability differences'):
        test.compare_c4(CURRENT, output)
