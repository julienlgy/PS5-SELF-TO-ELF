"""Validation and range helpers shared by the SELF and ELF parsers."""


def require(condition, message):
    if not condition:
        raise ValueError(message)


def fits(offset, size, limit):
    return offset <= limit and size <= limit - offset


def overlaps(first, second):
    offset, size = first
    other, length = second
    return size != 0 and length != 0 and offset < other + length and other < offset + size


def covered(offset, size, copies):
    end = offset + size
    while offset < end:
        next_offset = max(
            (start + length for start, length, _ in copies
             if start <= offset < start + length),
            default=offset,
        )
        if next_offset == offset:
            return False
        offset = next_offset
    return True
