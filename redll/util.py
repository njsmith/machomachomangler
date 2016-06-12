def round_to_next(size, alignment):
    "Return smallest n such that n % alignment == 0, n >= size"
    if size % alignment == 0:
        return size
    else:
        return alignment * (size // alignment + 1)
