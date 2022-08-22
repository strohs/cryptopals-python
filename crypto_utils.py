import string
import collections
from itertools import islice
from math import log10
# Utilities to compute the QuadGram score of a block of english plaintext

# sum of all the quad counts in the file english_quadgrams.txt
TOTAL_QUAD_COUNT: int = 4224127912


def _build_quadgram_dict() -> dict[tuple, float]:
    """
    returns a dictionary that maps the bytes of a quadgram to the probability of it occuring in
    english text. The keys are a tuple of four ints, representing the ascii values of each quadgram
    character. The values are the probability score of the quad
    """
    d = dict()
    with open("./files/english_quadgrams.txt") as file:
        for readline in file.readlines():
            quad, count = readline.rstrip("\n").split(" ")
            quad = tuple(bytes(quad.lower(), encoding="ascii"))
            count = int(count, 10)
            prob = log10(count / TOTAL_QUAD_COUNT)
            d[quad] = prob
    return d


QUADGRAM_PROBS = _build_quadgram_dict()


# these are the bytes we accept as English characters, anything outside this range will be rejected
# with a score of None
VALID_ASCII_BYTES = [10, 13] + list(range(32, 128))


def quadgram_score(block: bytes) -> float | None:
    """
    determine if the given block (of ASCII) are english text using a quad-gram comparison method.
    higher scores indicate a better likely-hood of being english text
    A score >= 0 is not english at all
    :return: a float < 0.0 if the block might be english, or None if the block is not English text
    at all. This can happen if the block has no letters in it at all
    """
    if not any(map(lambda b: b in VALID_ASCII_BYTES, block)):
        return None
    # we want at least one space character in the block, ideally we would check for some percentage of spaces
    if 32 not in block:
        return None

    # now filter out all letters and convert them to lowercase
    letters = [b for b in block.lower() if chr(b) in string.ascii_lowercase]
    letters = bytes(letters)

    # we want the majority of characters in the block to be letters, try 50% as a starting point
    if len(letters) < (len(block) * 0.5):
        return None

    # partition the letters into quadgrams and compute the score
    prob = 0.0
    for quad in _sliding_window(letters, 4):
        if quad in QUADGRAM_PROBS:
            prob += QUADGRAM_PROBS[quad]
        else:
            prob += log10(0.01 / TOTAL_QUAD_COUNT)

    return prob


def _sliding_window(iterable, n):
    # sliding_window('ABCDEFG', 4) -> ABCD BCDE CDEF DEFG
    it = iter(iterable)
    window = collections.deque(islice(it, n), maxlen=n)
    if len(window) == n:
        yield tuple(window)
    for x in it:
        window.append(x)
        yield tuple(window)
