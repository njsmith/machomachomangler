def round_to_next(size, alignment):
    "Return smallest n such that n % alignment == 0, n >= size"
    if size % alignment == 0:
        return size
    else:
        return alignment * (size // alignment + 1)

def test_round_to_next():
    assert round_to_next(10, 12) == 12
    assert round_to_next(20, 12) == 24
    assert round_to_next(24, 12) == 24
