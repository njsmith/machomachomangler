from ..util import round_to_next

def test_round_to_next():
    assert round_to_next(10, 12) == 12
    assert round_to_next(20, 12) == 24
    assert round_to_next(24, 12) == 24
