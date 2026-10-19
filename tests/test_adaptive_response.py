import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import pytest

from src.adaptive_response import choose_response


@pytest.mark.parametrize(
    "score, expected",
    [
        (0, ("NORMAL", "CONTINUE_MONITORING")),
        (29, ("NORMAL", "CONTINUE_MONITORING")),
        (30, ("ENHANCED", "ENHANCED_REVIEW")),
        (59, ("ENHANCED", "ENHANCED_REVIEW")),
        (60, ("INTENSIVE", "PRIORITY_ALERT")),
        (100, ("INTENSIVE", "PRIORITY_ALERT")),
    ],
)
def test_choose_response(score, expected):
    assert choose_response(score) == expected

