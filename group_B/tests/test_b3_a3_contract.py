"""Stream acceptance, replay identity and conservative UDP verification."""
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from group_B.agentic_ingestion import ExecutionConfig
from group_B.agentic_ingestion.adapters import UdpStreamAdapter, TransportError
from group_B.agentic_ingestion import adapters


@pytest.fixture
def receiver(monkeypatch):
    root = Path(__file__).resolve().parents[2] / 'group_A/A3_Stream_Ingestion'
    monkeypatch.syspath_prepend(str(root))
    spec = importlib.util.spec_from_file_location('a3_contract_receiver', root / 'receiver.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def envelope():
    return {'message': '2026-10-25T00:00:00Z example', 'event_id': 'a' * 64,
            'event': {'id': 'a' * 64}, 'labels': {'source_id': 'b3-' + 'b' * 24,
            'run_id': 'test-run', 'ingest_pipeline': 'linux-auth', 'envelope': 'b3.raw.v1'}}


def test_raw_requires_explicit_enable_and_approved_pipeline(receiver, monkeypatch):
    with pytest.raises(ValueError, match='disabled'):
        receiver.validate_incoming(envelope())
    monkeypatch.setenv('A3_ALLOW_B3_RAW', 'true')
    with pytest.raises(ValueError, match='approved'):
        receiver.validate_incoming(envelope())
    monkeypatch.setenv('A3_B3_PIPELINES', 'linux-auth')
    event = receiver.validate_incoming(envelope())
    assert event['event']['id'] == event['event_id'] == 'a' * 64
    event['event_id'] = 'different'
    with pytest.raises(ValueError, match='Invalid'):
        receiver.validate_incoming(event)


def test_normalized_flow_still_validates(receiver):
    event = {'@timestamp': '2026-10-25T00:00:00Z', 'message': 'login',
             'event': {'dataset': 'linux.auth', 'original': 'login', 'id': 'old-id',
                       'action': 'ssh_login', 'category': ['authentication'], 'outcome': 'success'},
             'host': {'name': 'demo'}}
    assert receiver.validate_incoming(event) == event


def test_stream_endpoint_rejects_remote_and_url_extras():
    for url in ('udp://192.0.2.1:9999', 'http://127.0.0.1:9999', 'udp://127.0.0.1:9999/path',
                'udp://user@127.0.0.1:9999', 'udp://127.0.0.1'):
        with pytest.raises(ValueError):
            ExecutionConfig(a3_udp_url=url)


def test_udp_receipt_is_not_an_ack_and_oversize_sends_nothing(monkeypatch):
    sent = []
    class Socket:
        def __enter__(self): return self
        def __exit__(self, *args): pass
        def settimeout(self, value): pass
        def sendto(self, packet, address): sent.append(json.loads(packet))
    monkeypatch.setattr(adapters.socket, 'socket', lambda *args: Socket())
    plan = SimpleNamespace(dry_run=False, status='planned', ingest_mode='stream')
    record = envelope()
    record['labels'].pop('envelope')
    adapter = UdpStreamAdapter('udp://127.0.0.1:9999')
    receipt = adapter.handoff(plan, [record])
    assert receipt.submitted == 1 and receipt.acknowledged == 0
    assert sent[0]['labels']['envelope'] == 'b3.raw.v1'
    assert 'envelope' not in record['labels']
    sent.clear()
    oversized = dict(record, message='x' * 4096)
    with pytest.raises(TransportError, match='4096'):
        adapter.handoff(plan, [record, oversized])
    assert not sent


def test_forwarding_preserves_raw_identity_and_pipeline(receiver, monkeypatch):
    posted = []
    class Response:
        status = 200
        def __enter__(self): return self
        def __exit__(self, *args): pass
    def post(request, **kwargs):
        posted.append(json.loads(request.data))
        return Response()
    monkeypatch.setattr(receiver.urllib.request, 'urlopen', post)
    record = envelope()
    assert receiver.forward_event(record) == 200
    assert receiver.forward_event(record) == 200
    for event in posted:
        assert event['labels']['source_id'] == 'b3-' + 'b' * 24
        assert event['labels']['ingest_pipeline'] == 'linux-auth'
        assert event['labels']['ingest_mode'] == 'stream'
        assert event['event']['id'] == event['event_id'] == 'a' * 64
        assert '@timestamp' not in event
