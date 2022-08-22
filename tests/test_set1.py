from unittest import TestCase
from set1 import convert_hex_to_base64, fixed_xor_bytes, implement_repeating_key_xor, single_byte_xor_cipher


class Test(TestCase):
    def test_convert_hex_to_base64(self):
        enc = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
        b64_str = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
        self.assertEqual(convert_hex_to_base64(enc), b64_str)

    def test_fixed_xor(self):
        s1 = bytes.fromhex("1c0111001f010100061a024b53535009181c")
        s2 = bytes.fromhex("686974207468652062756c6c277320657965")
        xored = fixed_xor_bytes(s1, s2)
        self.assertEqual(xored.hex(), "746865206b696420646f6e277420706c6179")

    def test_single_byte_xor(self):
        s1 = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
        decrypted = single_byte_xor_cipher(s1)
        self.assertEqual(decrypted, "Cooking MC's like a pound of bacon")

    def test_implement_repeating_key_xor(self):
        encrypted = implement_repeating_key_xor()
        self.assertEqual(encrypted, "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f")
