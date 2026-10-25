"""Tests for the demonstration website: attacks, incident record and web endpoints."""

import json
import threading
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

import pytest

from dashboard.server import ATTACKS, DemoStream, make_handler


@pytest.fixture
def stream():
    s = DemoStream("datasets/bidmc_53n.csv", 60, rate=1.0, handover_gap=0.05)
    for _ in range(4):
        s.process(s.genuine())
    return s


def outcomes(stream, injected):
    return [(e["replay"], e["decision"], e["label"]) for e in stream.events if e["injected"] == injected]


def test_replay_attack_dropped_without_decryption(stream):
    stream.attack("replay")
    (event,) = [e for e in stream.events if e["injected"] == "replay"]
    assert (event["replay"], event["decision"], event["decrypted"]) == ("dropped", "DISCARD", False)
    assert event["stages"][-1][0] == "Decrypt" and event["stages"][-1][1] == "skip"


def test_handover_records_incident(stream):
    stream.attack("handover")
    assert outcomes(stream, "handover") == [("dropped", "DISCARD", None)]
    assert outcomes(stream, "handover-next")[0][0] == "accepted"
    incident = stream.snapshot()["incident"]
    assert incident["open"] is False and incident["end"] > incident["start"]
    assert {e["injected"] for e in incident["events"]} == {"handover", "handover-next"}


@pytest.mark.parametrize("name", ["tamper", "case_swap", "jump"])
def test_forged_packets_fail_decryption(stream, name):
    stream.attack(name)
    (event,) = [e for e in stream.events if e["injected"] == name]
    assert event["rules"] == ["R-DECRYPT-FAILED"]


@pytest.mark.parametrize("name, rule", [("stale", "R-TS-STALE"), ("future", "R-TS-FUTURE"), ("malformed", "R-MALFORMED-HEADER")])
def test_bad_timestamps_and_headers_dropped(stream, name, rule):
    stream.attack(name)
    (event,) = [e for e in stream.events if e["injected"] == name]
    assert event["rules"] == [rule]


@pytest.mark.parametrize("name, label", [("hr300", "Flagged"), ("probe_off", "Flagged"), ("shock", "Flagged")])
def test_clinical_events_flagged_not_discarded(stream, name, label):
    stream.attack(name)
    (event,) = [e for e in stream.events if e["injected"] == name]
    assert (event["decision"], event["label"]) == ("FLAG", label)
    assert event["vitals"] is not None and event["points"]


def test_flood_blocks_excess_packets(stream):
    stream.attack("flood")
    blocked = [e for e in stream.events if e["injected"] == "flood" and e["rules"] == ["R-RATE-LIMIT"]]
    assert len(blocked) >= 30
    assert all(e["replay"] is None for e in blocked)


def test_every_listed_attack_is_implemented(stream):
    before = len(stream.events)
    for name in ATTACKS:
        stream.attack(name)
    assert len(stream.events) > before + len(ATTACKS)


@pytest.fixture
def server(stream):
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(stream))
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{httpd.server_address[1]}", stream
    httpd.shutdown()
    httpd.server_close()


def get(url):
    with urllib.request.urlopen(url, timeout=5) as r:
        return r.status, r.read()


def test_page_and_state_served(server):
    base, _ = server
    status, body = get(base + "/")
    assert status == 200 and b"Anomaly &amp; Replay Detection" in body
    status, body = get(base + "/api/state")
    state = json.loads(body)
    assert status == 200 and state["case"] == "CASE001" and len(state["events"]) == 4


def test_attack_endpoint_queues_known_attacks_only(server):
    base, stream = server
    req = urllib.request.Request(base + "/api/attack/replay", method="POST")
    with urllib.request.urlopen(req, timeout=5) as r:
        assert r.status == 202
    assert stream.commands.get_nowait() == "replay"
    bad = urllib.request.Request(base + "/api/attack/delete-everything", method="POST")
    with pytest.raises(urllib.error.HTTPError) as err:
        urllib.request.urlopen(bad, timeout=5)
    assert err.value.code == 400


def test_static_files_cannot_escape_their_folder(server):
    base, _ = server
    with pytest.raises(urllib.error.HTTPError) as err:
        get(base + "/static/../server.py")
    assert err.value.code == 404
