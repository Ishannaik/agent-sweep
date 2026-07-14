"""The found-count flash fade (_flash_style)."""
from agentsweep.ui.progress import _flash_style


def test_flash_fades_white_to_red():
    assert _flash_style(0.0) == "bold rgb(255,255,255)"   # just hit — full white
    assert _flash_style(1.0) == "bold rgb(215,40,40)"     # settled — red3
    # clamps out of range and is monotonic in redness (g drops as t rises)
    assert _flash_style(-1.0) == _flash_style(0.0)
    assert _flash_style(2.0) == _flash_style(1.0)
    g = lambda s: int(s.split(",")[1])
    assert g(_flash_style(0.25)) > g(_flash_style(0.75))
