"""Split conformal prediction: a model that may say "I am not sure".

Random-forest class scores are not probabilities, and on a small or shifted
dataset the top score can be confidently wrong. Conformal prediction turns any
scores into prediction *sets* with a finite-sample guarantee: if calibration
and future files are exchangeable, the true class is inside the set at least
``1 - alpha`` of the time, whatever the model is.

Nonconformity of a labelled example is ``1 - score[true class]``. On a held-out
calibration set, ``qhat`` is the ``ceil((n + 1)(1 - alpha)) / n`` empirical
quantile of those values. A new file's set holds every class whose
``1 - score`` is at most ``qhat``. The model *commits* only when the set holds
exactly one class; an empty or multi-class set means it abstains, and the scan
falls back to static evidence.

With too few calibration examples for the requested ``alpha``
(``n < 1/alpha - 1``) no finite ``qhat`` exists: every set holds every class
and the model always abstains. That is the honest answer for a tiny dataset.
"""
from __future__ import annotations

import math
from collections.abc import Sequence
from dataclasses import dataclass

import numpy as np

DEFAULT_ALPHA = 0.1


@dataclass(frozen=True)
class ConformalCalibration:
    alpha: float
    qhat: float
    calibration_size: int

    @property
    def sufficient(self) -> bool:
        """False when the calibration set was too small to bound the error rate."""
        return self.qhat < 1.0

    def as_provenance(self) -> dict[str, float | int]:
        return {
            "conformal_alpha": self.alpha,
            "conformal_qhat": self.qhat,
            "conformal_calibration_size": self.calibration_size,
        }

    @classmethod
    def from_provenance(cls, provenance) -> "ConformalCalibration | None":
        try:
            alpha = float(provenance["conformal_alpha"])
            qhat = float(provenance["conformal_qhat"])
            size = int(provenance["conformal_calibration_size"])
        except (KeyError, TypeError, ValueError):
            return None
        if not (0.0 < alpha < 1.0 and 0.0 <= qhat <= 1.0 and size >= 0):
            return None
        return cls(alpha, qhat, size)


def calibrate(scores: np.ndarray, true_index: Sequence[int], alpha: float = DEFAULT_ALPHA) -> ConformalCalibration:
    """Fit ``qhat`` from class scores (rows sum to 1) of a held-out calibration set."""
    if not 0.0 < alpha < 1.0:
        raise ValueError("alpha must be between 0 and 1.")
    scores = np.asarray(scores, dtype=np.float64)
    true_index = np.asarray(true_index, dtype=np.int64)
    if scores.ndim != 2 or scores.shape[0] != true_index.shape[0]:
        raise ValueError("scores must be (n, classes) with one true class per row.")
    n = scores.shape[0]
    rank = math.ceil((n + 1) * (1.0 - alpha))
    if n == 0 or rank > n:
        return ConformalCalibration(alpha, 1.0, n)
    nonconformity = np.sort(1.0 - scores[np.arange(n), true_index])
    return ConformalCalibration(alpha, float(nonconformity[rank - 1]), n)


def prediction_set(scores_row: Sequence[float], calibration: ConformalCalibration, classes: Sequence[str]) -> list[str]:
    """Every class the calibration cannot rule out for this file, in ``classes`` order."""
    if not calibration.sufficient:
        return list(classes)
    # A tiny tolerance keeps a score that ties qhat exactly inside the set.
    return [name for name, score in zip(classes, scores_row) if 1.0 - float(score) <= calibration.qhat + 1e-12]


def evaluate(scores: np.ndarray, true_index: Sequence[int], calibration: ConformalCalibration) -> dict[str, float]:
    """Coverage, mean set size and abstention rate on a set the calibration never saw."""
    scores = np.asarray(scores, dtype=np.float64)
    true_index = np.asarray(true_index, dtype=np.int64)
    if scores.shape[0] == 0:
        return {"coverage": math.nan, "mean_set_size": math.nan, "abstention_rate": math.nan, "committed_accuracy": math.nan}
    if calibration.sufficient:
        members = (1.0 - scores) <= calibration.qhat + 1e-12
    else:
        members = np.ones_like(scores, dtype=bool)
    sizes = members.sum(axis=1)
    committed = sizes == 1
    covered = members[np.arange(scores.shape[0]), true_index]
    return {
        "coverage": round(float(covered.mean()), 4),
        "mean_set_size": round(float(sizes.mean()), 4),
        "abstention_rate": round(float((~committed).mean()), 4),
        # Accuracy on the files where the model committed to one class.
        "committed_accuracy": round(float(covered[committed].mean()), 4) if committed.any() else math.nan,
    }
