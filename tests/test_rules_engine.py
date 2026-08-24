from app.detection.engine import matches_filter


def test_matches_filter_exact():
    ev = {"category": "authentication", "action": "login_failure"}
    assert matches_filter(ev, {"category": "authentication"})
    assert not matches_filter(ev, {"category": "network"})


def test_matches_filter_list():
    ev = {"severity": "high"}
    assert matches_filter(ev, {"severity": ["high", "critical"]})
    assert not matches_filter(ev, {"severity": ["low"]})


def test_matches_filter_message_contains():
    ev = {"message": "Failed password for root from 1.2.3.4"}
    assert matches_filter(ev, {"message_contains": "failed password"})
    assert not matches_filter(ev, {"message_contains": "mimikatz"})


def test_matches_filter_message_contains_any():
    ev = {"message": "detected mimikatz.exe on host"}
    assert matches_filter(ev, {"message_contains_any": ["cobaltstrike", "mimikatz"]})


def test_matches_filter_empty_matches_all():
    assert matches_filter({"anything": "goes"}, {})
