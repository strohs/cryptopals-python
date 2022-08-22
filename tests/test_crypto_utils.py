from unittest import TestCase
from crypto_utils import quadgram_score, chi2_score, repeating_xor, hamming


class Test(TestCase):

    def test_chi_squared(self):
        bs1 = b"ATTACK THE EAST WALL OF THE CASTLE AT DAWN"
        bs2 = b"FYYFHP YMJ JFXY BFQQ TK YMJ HFXYQJ FY IFBS"
        score1 = chi2_score(bs1)
        score2 = chi2_score(bs2)
        self.assertEqual(score1, 20.322194193280357)
        self.assertEqual(score2, 769.0659743350321)

    def test_repeating_key_xor(self):
        plain = b"Abracadabra"
        key = b"ICE"
        encrypted_bytes = [8, 33, 55, 40, 32, 36, 45, 34, 39, 59, 34]
        encrypted = repeating_xor(plain, key)
        self.assertEqual(list(encrypted), encrypted_bytes)

    def test_hamming(self):
        buf1 = b"this is a test"
        buf2 = b"wokka wokka!!!"
        self.assertEqual(hamming(buf1, buf2), 37)

    def test_quadgram_score(self):
        b1 = b"ATTACK THE EAST WALL OF THE CASTLE AT DAWN"
        score1 = quadgram_score(b1)
        self.assertEqual(score1, -127.77224079273714)

        b2 = b"FYYFHP YMJ JFXY BFQQ TK YMJ HFXYQJ FY IFBS"
        score2 = quadgram_score(b2)
        self.assertEqual(score2, -302.3543701340869)
