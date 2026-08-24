import importlib.util
import os
import sys
import time

import pytest

_MODULE_PATH = os.path.join(os.path.dirname(__file__), "..", "agents", "file_integrity_agent.py")
_spec = importlib.util.spec_from_file_location("file_integrity_agent", _MODULE_PATH)
fim = importlib.util.module_from_spec(_spec)
sys.modules["file_integrity_agent"] = fim
_spec.loader.exec_module(fim)


@pytest.fixture
def watch_dir(tmp_path):
    (tmp_path / "keep.txt").write_text("hello")
    (tmp_path / "ignored.tmp").write_text("should be skipped")
    return tmp_path


def test_scan_respects_ignore_extensions(watch_dir):
    inventory = fim.scan([str(watch_dir)], [".tmp"], max_files=1000)
    names = {os.path.basename(p) for p in inventory}
    assert "keep.txt" in names
    assert "ignored.tmp" not in names


def test_diff_detects_created_modified_deleted(watch_dir):
    baseline = fim.scan([str(watch_dir)], [".tmp"], max_files=1000)

    # created
    (watch_dir / "new_file.txt").write_text("new")
    # modified (ensure mtime actually changes)
    time.sleep(0.05)
    (watch_dir / "keep.txt").write_text("hello world, now longer")
    # deleted: none yet

    after_change = fim.scan([str(watch_dir)], [".tmp"], max_files=1000)
    created, modified, deleted = fim.diff(baseline, after_change)

    created_names = {os.path.basename(p) for p in created}
    modified_names = {os.path.basename(p) for p in modified}
    assert "new_file.txt" in created_names
    assert "keep.txt" in modified_names
    assert deleted == []


def test_diff_detects_deletion(watch_dir):
    baseline = fim.scan([str(watch_dir)], [".tmp"], max_files=1000)
    os.remove(watch_dir / "keep.txt")
    after_change = fim.scan([str(watch_dir)], [".tmp"], max_files=1000)

    created, modified, deleted = fim.diff(baseline, after_change)
    deleted_names = {os.path.basename(p) for p in deleted}
    assert "keep.txt" in deleted_names
    assert created == []


def test_build_events_shapes_match_event_schema(watch_dir):
    inventory = {str(watch_dir / "a.txt"): {"size": 10, "mtime": 123.0}}
    events = fim.build_events(
        created=[str(watch_dir / "a.txt")], modified=[], deleted=["/tmp/gone.txt"],
        inventory=inventory, hostname="test-host",
    )
    kinds = {e["action"] for e in events}
    assert kinds == {"file_created", "file_deleted"}
    for e in events:
        assert e["category"] == "file"
        assert e["host"] == "test-host"
