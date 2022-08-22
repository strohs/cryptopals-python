import base64
from itertools import islice
from crypto_utils import fixed_xor, break_single_byte_xor, repeating_xor, hamming, chunks

"""
Cryptopals Challenges Set 1
https://cryptopals.com/
"""


def convert_hex_to_base64(s: str) -> str:
    """
    Set 1, Challenge 1: Convert a hex encoded string to Base64
    s - the hexadecimal string to encode as base64
    returns the base64 encoded string
    """
    b = bytearray.fromhex(s)
    b64 = base64.b64encode(b)
    return b64.decode()


def fixed_xor_bytes(buf1: bytes, buf2: bytes) -> bytearray:
    """
    Set1, Challenge 2: XOR the bytes in buf1 and buf2
    :return: a bytearray containing the xored bytes
    """
    return fixed_xor(buf1, buf2)


def single_byte_xor_cipher(s: str) -> str:
    """
    Set 1, Challenge 3: find the single byte that was used to encrypt the input string 's'
    :param s: a hex encoded string to be decrypted
    :return: the plaintext string
    """
    bs = bytes.fromhex(s)
    (score, key) = break_single_byte_xor(bs)
    plaintext = fixed_xor(bs, bytearray([key] * len(bs)))
    return plaintext.decode(encoding="ascii")


def detect_single_byte_xor() -> str | None:
    """
    Set 1, Challenge 4: find the line in file 4.txt that has been encrypted using single character XOR
    :return: the decrypted plaintext
    """
    scores = []
    with open("./files/4.txt", "r") as file:
        for readline in file.readlines():
            line = readline.rstrip("\n")
            bs = bytes.fromhex(line)
            result = break_single_byte_xor(bs)
            if result:
                score, key = result
                scores.append((score, key, bs))
    if len(scores) > 0:
        scores.sort(key=lambda s: s[0])
        best_score, best_key, best_line = scores[0]
        plaintext = fixed_xor(best_line, bytearray([best_key] * len(best_line)))
        print(f"best score {best_score:8.3} {best_key}, {plaintext}")
        return plaintext.decode(encoding="ascii")
    else:
        return None


def implement_repeating_key_xor() -> str:
    """Set 1, Challenge 5
    implement a repeating key XOR encryptor using the key "ICE"
    :return a hexadecimal string of the encrypted bytes
    """
    plain = b"""Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"""
    key = b"ICE"
    encrypted = repeating_xor(plain, key)
    return encrypted.hex()


def break_repeating_key_xor():
    """Set1, Challenge 6
    Break repeating key XOR
    The goal is to find the key that was used to encrypt the entire text in the file "6.txt". The plaintext
    of the file was encrypted using repeating key XOR and then base64 encoded.
    """
    file = open("./files/6_decoded.txt", "rb")
    xored = file.read()
    file.close()

    # step 1, guess the encryption keysize. Try sizes between 2 and 40
    #  Compare FIRST and SECOND keysize worth of bytes, find hamming distance between them and
    #  normalize result by dividing by keysize
    # The keysize with the smallest normalized edit distance is "probably" the key
    probable_keys = []
    for keysize in range(2, 41):
        chunk = list(islice(chunks(xored, keysize), 4))
        d1 = hamming(chunk[0], chunk[1]) / keysize
        d2 = hamming(chunk[1], chunk[2]) / keysize
        d3 = hamming(chunk[2], chunk[3]) / keysize
        normalized = (d1 + d2 + d3) / 3.0
        #print(d1, d2, d3, normalized)
        probable_keys.append((keysize, normalized))
    probable_keys.sort(key=lambda k: k[1])

    # step 2, For each keysize, we need to partition the XORed bytes into N blocks, where N is the
    # current KEYSIZE. Each of those blocks must contain corresponding bytes. For Example:
    # Suppose the current KEYSIZE is 3 and our xored bytes = [0, 1, 2, 3, 4, 5, 6, 7, 8],
    # we need to build "byte_blocks" that look like: [[0,3,6], [1,4,7], [2,5,8]]. We can then
    # try to guess the single byte cipher for each of those byte blocks, and use the best
    # scoring byte for each block the construct the final repeating key.
    final_keys: list[bytes] = []
    # try the top 3 keys, we just want the key lengths
    keysizes = islice([k[0] for k in probable_keys], 3)
    for keysize in keysizes:
        byte_blocks = []

        # build the byte_blocks
        for k in range(0, keysize):
            block = list(islice(xored[k:], 0, None, keysize))
            byte_blocks.append(block)

        # now try to guess the single byte key for each byte_block
        key = []
        for i, block in enumerate(byte_blocks):
            result = break_single_byte_xor(block)
            if result:
                kscore, k = result
                print("adding byte {}({}) with score {:8.3}, for keysize {} block {}".format(k, chr(k), kscore, keysize, i))
                key.append(k)
        if len(key) > 0:
            final_keys.append(bytes(key))

    # print the results of decrypting with each key
    for key in final_keys:
        key_str = key.decode(encoding="ascii")
        print(f"decryption result for key={key_str}")
        print("-----------------------------------------------------------------------------------------------")
        decrypted = repeating_xor(xored, key).decode(encoding="ascii")
        print(decrypted)
        print("-----------------------------------------------------------------------------------------------")


if __name__ == "__main__":
    # single_byte_xor_cipher("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
    break_repeating_key_xor()

