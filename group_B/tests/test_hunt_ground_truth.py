"""Seeded scenario acceptance cannot be satisfied by two agents agreeing wrongly."""
import copy
import importlib
from pathlib import Path

import pytest


@pytest.fixture
def demo(monkeypatch):
    root = Path(__file__).resolve().parents[2]
    monkeypatch.syspath_prepend(str(root / 'group_B/scripts'))
    cls = importlib.import_module('group_B.scripts.check_onboarding_hunt_demo').HuntDemo
    demo = cls.__new__(cls)
    demo.expected = {'attack-event-1', 'attack-event-2'}
    return demo


def result(label, claims=None):
    return {'verdict': {'label': label}, 'claims': claims or [], 'self_check': {'failed': []}}


@pytest.mark.parametrize('run', ['attack', 'attack-repeat'])
def test_seeded_attack_requires_support_and_exact_evidence(demo, run):
    valid = result('SUPPORTED', [{'event_ids': sorted(demo.expected)}])
    demo.check_ground_truth(run, valid, demo.expected)
    with pytest.raises(AssertionError, match='wrong seeded-scenario verdict'):
        demo.check_ground_truth(run, result('INCONCLUSIVE'), set())
    with pytest.raises(AssertionError, match='citations differ'):
        demo.check_ground_truth(run, valid, {'attack-event-1'})
    with pytest.raises(AssertionError, match='citations differ'):
        demo.check_ground_truth(run, valid, demo.expected | {'benign-event'})


@pytest.mark.parametrize('run,label', [('benign', 'NOT_SUPPORTED'), ('missing-host', 'INCONCLUSIVE'),
                                      ('empty-window', 'INSUFFICIENT_DATA')])
def test_negative_scenario_requires_expected_label_and_no_claims(demo, run, label):
    demo.check_ground_truth(run, result(label), set())
    with pytest.raises(AssertionError, match='unexpected claims'):
        demo.check_ground_truth(run, result(label, [{'event_ids': ['unexpected']}]), {'unexpected'})
    with pytest.raises(AssertionError, match='wrong seeded-scenario verdict'):
        demo.check_ground_truth(run, result('SUPPORTED'), set())
