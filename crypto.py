# crypto.py
# Simple Caesar cipher implementation, handles upper/lower letters.
from typing import Tuple

def caesar_encrypt(plaintext: str, key: int) -> str:
    result_chars = []
    for ch in plaintext:
        if 'a' <= ch <= 'z':
            base = ord('a')
            result_chars.append(chr((ord(ch) - base + key) % 26 + base))
        elif 'A' <= ch <= 'Z':
            base = ord('A')
            result_chars.append(chr((ord(ch) - base + key) % 26 + base))
        else:
            result_chars.append(ch)
    return ''.join(result_chars)

def caesar_decrypt(ciphertext: str, key: int) -> str:
    return caesar_encrypt(ciphertext, (-key) % 26)

def vigenere_encrypt(plaintext: str, key: str) -> str:
    result = []
    key = key.upper()
    key_index = 0

    for ch in plaintext:
        if ch.isalpha():
            shift = ord(key[key_index % len(key)]) - ord('A')
            base = ord('A') if ch.isupper() else ord('a')
            result.append(chr((ord(ch) - base + shift) % 26 + base))
            key_index += 1
        else:
            result.append(ch)
    return ''.join(result)


def vigenere_decrypt(ciphertext: str, key: str) -> str:
    result = []
    key = key.upper()
    key_index = 0

    for ch in ciphertext:
        if ch.isalpha():
            shift = ord(key[key_index % len(key)]) - ord('A')
            base = ord('A') if ch.isupper() else ord('a')
            result.append(chr((ord(ch) - base - shift) % 26 + base))
            key_index += 1
        else:
            result.append(ch)
    return ''.join(result)


# A generic interface for later adding more ciphers
def encrypt(text: str, key, method: str = "caesar") -> str:
    if method == "caesar":
        return caesar_encrypt(text, int(key) % 26)
    elif method == "vigenere":
        return vigenere_encrypt(text, str(key))
    else:
        raise ValueError("Unknown method")


def decrypt(text: str, key, method: str = "caesar") -> str:
    if method == "caesar":
        return caesar_decrypt(text, int(key) % 26)
    elif method == "vigenere":
        return vigenere_decrypt(text, str(key))
    else:
        raise ValueError("Unknown method")


# quick test
if __name__ == "__main__":
    print("[Caesar]", encrypt("Hello", 3), "→", decrypt(encrypt("Hello", 3), 3))
    print("[Vigenere]", encrypt("ATTACKATDAWN", "LEMON"), "→", decrypt(encrypt("ATTACKATDAWN", "LEMON"), "LEMON"))