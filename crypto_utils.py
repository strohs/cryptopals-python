import string
import collections
from itertools import islice, zip_longest, cycle
from math import log10

"""
Crypto Utils
This module contains common functions for cryptographic related tasks


"""

# for our cryptopals solutions, whitespace is either a LineFeed or a space
WHITESPACE = [10, 32]

# these are the ASCII bytes we accept as "legal" characters in the cryptopal challenges.
# Anything outside this range will be rejected with a score of None
VALID_ASCII_BYTES = WHITESPACE + list(range(33, 128))

# maps a lowercase ascii letter to its frequency within english text
FREQUENCIES = {
    97: 0.08167,
    98: 0.01492,
    99: 0.02782,
    100: 0.04253,
    101: 0.12702,
    102: 0.02228,
    103: 0.02015,
    104: 0.06094,
    105: 0.06966,
    106: 0.00153,
    107: 0.00772,
    108: 0.04025,
    109: 0.02406,
    110: 0.06749,
    111: 0.07507,
    112: 0.01929,
    113: 0.00095,
    114: 0.05987,
    115: 0.06327,
    116: 0.09056,
    117: 0.02758,
    118: 0.00978,
    119: 0.02360,
    120: 0.00150,
    121: 0.01974,
    122: 0.00074
}

# sum of all the quad counts in the file english_quadgrams.txt
TOTAL_QUAD_COUNT: int = 4224127912


def _build_quadgram_dict() -> dict[tuple, float]:
    """
    loads and returns a dictionary that maps the four letters of an english quadgram to the probability of
    it occurring in text. The letters are stored as a four-tuple of int. Each int is the ASCII value of that letter.
    The values are the probability score of that quadgram
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


# build the dictionary when this module is loaded
QUADGRAM_PROBS = _build_quadgram_dict()


def quadgram_score(block: bytes) -> float | None:
    """
    determine if the given block (of ASCII) bytes are english text using a quad-gram comparison method.
    higher scores indicate a better likely-hood of being english text.
    :return: a float < 0.0 if the block might be english. returns None if the block is not English text, for
    example, if the block has no letters in it at all.
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
    """
    builds a sliding window of length 'n' over the iterable and returns them as an iterable of tuples.
    sliding_window('ABCDEFG', 4) -> ABCD BCDE CDEF DEFG
    """
    it = iter(iterable)
    window = collections.deque(islice(it, n), maxlen=n)
    if len(window) == n:
        yield tuple(window)
    for x in it:
        window.append(x)
        yield tuple(window)


def repeating_xor(block: bytes, key: bytes) -> bytes:
    """
    XORs the bytes in block with key, cycling the bytes in key as needed to fully XOR every byte of block
    :return: the XORed bytes
    """
    return bytes(map(lambda pair: pair[0] ^ pair[1], islice(zip_longest(block, cycle(key)), len(block))))


def fixed_xor(buf1: bytes, buf2: bytes) -> bytearray:
    """
    XOR corresponding bytes in buf1 and buf2 and returns the result as a new bytearray
    """
    xored = [buf1[i] ^ buf2[i] for i in range(len(buf1))]
    return bytearray(xored)


def chunks(lst, n):
    """Yield successive n-sized chunks from lst."""
    for i in range(0, len(lst), n):
        yield lst[i:i + n]


def valid_english_byte(b: int) -> bool:
    """
    returns true if the given byte, b, is an ASCII digit, letter, punctuation, space or linefeed; else false
    """
    return b in VALID_ASCII_BYTES


def chi2_score(block: bytes) -> float | None:
    """
    tests if the given block is english text by computing its chi squared score. The lower the score, the more
    likely the block is english text.
    :param block: the ascii bytes to test
    :return: the chi squared score for the text. If the block is not english at all, meaning that no letters
    were found in the block, None is returned
    """
    # every byte in block must be a "valid" character
    if not all(map(lambda b: valid_english_byte(b), block)):
        return None
    # there should be at least one space character in block
    if not any(map(lambda b: b == 32, block)):
        return None
    # build a frequency map of all lower case letters in block, with a count of how many
    # times that letter occurs in block
    letter_counts = collections.Counter(filter(lambda b: b in range(97, 123), block.lower()))
    total_letters = letter_counts.total()

    # there's gotta be letters in the block in order to be english
    if total_letters == 0:
        return None

    # compute
    score = 0.0
    for letter in letter_counts.keys():
        count = letter_counts[letter]
        expected = total_letters * FREQUENCIES[letter]
        score += pow(count - expected, 2) / expected

    return score


def hamming(bs1: bytes, bs2: bytes) -> int:
    """
    returns the total number of bits that differ between corresponding bytes of `bs1` and `bs2`
    raises a RuntimeError if bs1 and bs2 are not the same length
    """
    if len(bs1) != len(bs2):
        raise RuntimeError("bytes must be equal length in order to compute hamming distance")
    count = 0
    for b1, b2 in zip_longest(bs1, bs2):
        xor = b1 ^ b2
        while xor > 0:
            xor &= xor - 1
            count += 1
    return count


def break_single_byte_xor(block: bytes) -> (float | None, int | None):
    """
    given a block of XOR encrypted bytes, try to find the single ASCII character that best
    decrypts the block into english text. The "best" character is the one with the lowest chi squared score.
    :return (score, int) | None  where score is the of the best character, and int is the ASCII value of that
    character. `None` is returned if the block could not be decrypted because the scoring algorithm did not
    recognize it as english
    """
    scores = []
    for c in range(256):
        single_bytes = bytes([c] * len(block))
        xored = fixed_xor(block, single_bytes)
        score = chi2_score(xored)
        if score:
            # print("scored {}({}) {:7.4} ||{}||".format(c, str(c), score, xored.decode(encoding="ascii")))
            scores.append((c, score, xored))
    scores.sort(key=lambda s: s[1])

    # print top 3 scores
    # for s in scores[0:3]:
    #     print("    score {}({}) {:7.4} ||{}||".format(s[0], str(s[0]), s[1], s[2].decode(encoding="ascii")))

    if len(scores) > 0:
        return scores[0][1], scores[0][0]
    else:
        return None
