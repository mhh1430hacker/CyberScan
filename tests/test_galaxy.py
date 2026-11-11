"""Every file's galaxy: made from its measured slices, unique to its fingerprint."""
from __future__ import annotations

import hashlib
import os

import numpy as np
import pytest

from conftest import scan, settle, wait_for

pytest.importorskip("PySide6")


def _structure(data: bytes, regions=()):
    from ui.structure import build_structure

    position = {"entropy_boundaries": [{"offset_start": a, "offset_end": b, "severity": s} for a, b, s in regions]}
    return build_structure(data, None, {}, position)


def test_the_same_file_always_gives_the_same_galaxy_and_another_file_another(qapplication):
    from ui.galaxy import build_galaxy

    data = b"Agenda for Thursday. " * 6000 + os.urandom(40000)
    structure = _structure(data)
    sha = hashlib.sha256(data).hexdigest()
    first, second = build_galaxy(structure, sha), build_galaxy(structure, sha)
    assert np.array_equal(first.positions, second.positions) and first.arms == second.arms
    other = build_galaxy(structure, hashlib.sha256(data + b"!").hexdigest())
    assert not np.array_equal(first.positions, other.positions)


def test_every_star_is_a_measured_slice_from_core_to_rim(qapplication):
    from ui.galaxy import build_galaxy

    data = bytes(50000) + os.urandom(50000)
    structure = _structure(data)
    galaxy = build_galaxy(structure, hashlib.sha256(data).hexdigest())
    assert galaxy.positions.shape[0] == structure.count
    assert np.array_equal(galaxy.offsets, structure.offsets)
    half = structure.count // 2
    # The start of the file is near the core; the end at the rim.
    assert np.median(galaxy.radius[:half // 4]) < np.median(galaxy.radius[-half // 4:])
    # Quiet bytes burn cool and faint, random bytes gold.
    assert galaxy.colors[:half, 2].mean() > galaxy.colors[:half, 0].mean()
    assert galaxy.colors[-half:, 0].mean() > galaxy.colors[-half:, 2].mean()
    assert float(galaxy.radius.max()) <= 1.0


def test_flagged_regions_become_supernovas(qapplication):
    from ui.galaxy import GalaxyPainter, build_galaxy

    data = os.urandom(20000) + bytes(80000)
    structure = _structure(data, [(60000, 70000, "high")])
    galaxy = build_galaxy(structure, hashlib.sha256(data).hexdigest())
    novas = GalaxyPainter(galaxy).supernovas()
    assert len(novas) == 1
    start, end = galaxy.offsets[novas[0]]
    assert 60000 - 1024 <= start and end <= 70000 + 1024


def test_the_wallpaper_is_painted_at_full_size(qapplication):
    from ui.galaxy import build_galaxy, render_wallpaper

    data = os.urandom(30000) + b"text " * 4000
    galaxy = build_galaxy(_structure(data), hashlib.sha256(data).hexdigest())
    image = render_wallpaper(galaxy, 640, 360, "The galaxy of a file", "SHA-256 …")
    assert (image.width(), image.height()) == (640, 360)
    center = image.pixelColor(320, 180)
    assert center.red() + center.green() + center.blue() > 60  # the core shines


def test_the_result_opens_the_observatory_and_esc_closes_it(window, qapplication, tmp_path):
    from PySide6.QtCore import Qt
    from PySide6.QtGui import QKeyEvent

    sample = tmp_path / "notes.txt"
    sample.write_text("Agenda for Thursday.\n" * 400, encoding="utf-8")
    scan(qapplication, window, str(sample))
    assert wait_for(qapplication, lambda: window.result_panel.inside_card.isVisible(), 20)
    window.result_panel.galaxy_button.click()
    observatory = window.observatory
    assert observatory is not None and observatory.isVisible()
    assert wait_for(qapplication, lambda: observatory.ready, 60)
    assert observatory.view._timer.isActive()  # it turns while it is on screen
    settle(qapplication, 0.3)
    observatory.keyPressEvent(QKeyEvent(QKeyEvent.Type.KeyPress, Qt.Key.Key_Escape, Qt.KeyboardModifier.NoModifier))
    assert window.observatory is None


def test_reduced_motion_shows_the_galaxy_still(qapplication, monkeypatch):
    monkeypatch.setenv("CYBERSCAN_REDUCE_MOTION", "1")
    from ui.galaxy import GalaxyView, build_galaxy

    data = os.urandom(20000)
    view = GalaxyView()
    view.resize(400, 300)
    view.set_galaxy(build_galaxy(_structure(data), hashlib.sha256(data).hexdigest()))
    view.show()
    assert not view._timer.isActive() and view.bang() == 1.0
    view.close()
