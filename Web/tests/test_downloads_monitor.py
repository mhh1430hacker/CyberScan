from monitoring.downloads_monitor import DownloadMonitor


def test_monitor_queues_only_stable_readable_files(tmp_path):
    completed = tmp_path / "complete.bin"
    partial = tmp_path / "in-flight.crdownload"
    completed.write_bytes(b"complete")
    partial.write_bytes(b"partial")
    monitor = DownloadMonitor(str(tmp_path), stable_polls=2)

    monitor._scan_once()
    assert monitor.get_next() is None
    monitor._scan_once()

    assert monitor.get_next() == str(completed)
    assert monitor.get_next() is None


def test_monitor_waits_again_when_a_file_changes_between_polls(tmp_path):
    sample = tmp_path / "changing.bin"
    sample.write_bytes(b"first")
    monitor = DownloadMonitor(str(tmp_path), stable_polls=2)

    monitor._scan_once()
    sample.write_bytes(b"second-longer")
    monitor._scan_once()
    assert monitor.get_next() is None
    monitor._scan_once()

    assert monitor.get_next() == str(sample)


def test_monitor_baselines_existing_files_and_requeues_changed_files(tmp_path):
    sample = tmp_path / "existing.bin"
    sample.write_bytes(b"old")
    monitor = DownloadMonitor(str(tmp_path), stable_polls=1)
    monitor._prime_existing_files()

    monitor._scan_once()
    assert monitor.get_next() is None

    sample.write_bytes(b"changed")
    monitor._scan_once()
    assert monitor.get_next() == str(sample)


def test_monitor_callback_consumes_event_without_growing_the_pull_queue(tmp_path):
    sample = tmp_path / "new.bin"
    sample.write_bytes(b"download")
    events = []
    monitor = DownloadMonitor(str(tmp_path), callback=events.append, stable_polls=1)

    monitor._scan_once()

    assert events == [str(sample)]
    assert monitor.get_next() is None
