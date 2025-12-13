# crypto.py
# Simple Caesar cipher implementation, handles upper/lower letters.
import random
import math
import json
from typing import Tuple
import json
import bcrypt

# Password hashing helpers (bcrypt)
# ------------------------------
def hash_password(password: str) -> str:
    """Return bcrypt hash (utf-8 str) for a plaintext password."""
    hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    return hashed.decode('utf-8')

def verify_password(password: str, hashed: str) -> bool:
    """Verify plaintext password against bcrypt hash (both strings)."""
    try:
        return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))
    except Exception:
        return False
    
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


# Substitution cipher (monoalphabetic substitution)
def substitution_encrypt(plaintext: str, key: str) -> str:
    # key: 26-letter mapping representing ciphertext letters for A..Z
    clean_key = ''.join([c for c in key if c.isalpha()])
    if len(clean_key) != 26:
        raise ValueError("Substitution key must contain 26 letters")
    clean_key = clean_key.upper()
    mapping_upper = {chr(ord('A') + i): clean_key[i] for i in range(26)}
    mapping_lower = {k.lower(): v.lower() for k, v in mapping_upper.items()}

    result = []
    for ch in plaintext:
        if ch.isupper():
            result.append(mapping_upper.get(ch, ch))
        elif ch.islower():
            result.append(mapping_lower.get(ch, ch))
        else:
            result.append(ch)
    return ''.join(result)


def substitution_decrypt(ciphertext: str, key: str) -> str:
    clean_key = ''.join([c for c in key if c.isalpha()])
    if len(clean_key) != 26:
        raise ValueError("Substitution key must contain 26 letters")
    clean_key = clean_key.upper()
    mapping_upper = {clean_key[i]: chr(ord('A') + i) for i in range(26)}
    mapping_lower = {k.lower(): v.lower() for k, v in mapping_upper.items()}

    result = []
    for ch in ciphertext:
        if ch.isupper():
            result.append(mapping_upper.get(ch, ch))
        elif ch.islower():
            result.append(mapping_lower.get(ch, ch))
        else:
            result.append(ch)
    return ''.join(result)


# Simple columnar transposition cipher
# key: number of columns (int > 0). Encryption writes plaintext into rows
# left-to-right with that many columns and reads out column-by-column.
def transposition_encrypt(plaintext: str, key: int) -> str:
    cols = int(key)
    if cols <= 0:
        raise ValueError("Transposition key must be a positive integer")
    # keep all characters (including spaces and punctuation)
    # fill into rows
    rows = (len(plaintext) + cols - 1) // cols
    padded_len = rows * cols
    pad_char = 'X'
    padded = plaintext.ljust(padded_len, pad_char)

    result = []
    for c in range(cols):
        for r in range(rows):
            idx = r * cols + c
            result.append(padded[idx])
    return ''.join(result)


def transposition_decrypt(ciphertext: str, key: int) -> str:
    cols = int(key)
    if cols <= 0:
        raise ValueError("Transposition key must be a positive integer")
    length = len(ciphertext)
    rows = (length + cols - 1) // cols
    # build empty grid
    grid = [[''] * cols for _ in range(rows)]
    idx = 0
    for c in range(cols):
        for r in range(rows):
            if idx < length:
                grid[r][c] = ciphertext[idx]
                idx += 1

    # read row-wise
    result = []
    for r in range(rows):
        for c in range(cols):
            result.append(grid[r][c])

    # strip potential padding X characters added during encryption
    return ''.join(result).rstrip('X')


# A generic interface for later adding more ciphers
def encrypt(text: str, key, method: str = "caesar") -> str:
    if method == "caesar":
        return caesar_encrypt(text, int(key) % 26)
    elif method == "vigenere":
        return vigenere_encrypt(text, str(key))
    elif method == "substitution":
        return substitution_encrypt(text, str(key))
    elif method == "transposition":
        return transposition_encrypt(text, int(key))
    else:
        raise ValueError("Unknown method")


def decrypt(text: str, key, method: str = "caesar") -> str:
    if method == "caesar":
        return caesar_decrypt(text, int(key) % 26)
    elif method == "vigenere":
        return vigenere_decrypt(text, str(key))
    elif method == "substitution":
        return substitution_decrypt(text, str(key))
    elif method == "transposition":
        return transposition_decrypt(text, int(key))
    else:
        raise ValueError("Unknown method")

# Small lists of common short words for quick scoring.
_COMMON_WORDS = {
    "english": ["the","and","to","of","is","in","it","you","that","he","was","for","on","are","with","as","I","his","they","be"],
    "french": ["le","la","et","de","des","les","un","une","à","est","pour","qui","dans","en","ce","il","elle","nous","vous"],
    # Arabic common small words (in Arabic script). Note: Caesar over Arabic requires Arabic alphabet shifts.
    "arabic": ["و", "في", "على", "من", "إلى", "ال", "هو", "هي", "هذا", "ذلك"]
}

def _score_text_by_language(text: str, language: str) -> float:
    language = language.lower()
    words = _COMMON_WORDS.get(language, [])
    lowered = text.lower()
    score = 0.0
    # count occurrences of each common word
    for w in words:
        if w in lowered:
            score += lowered.count(w) * (2.0 if language != "arabic" else 1.5)
    # bonus for many printable letters
    letters = sum(1 for c in text if c.isalpha())
    score += letters * 0.01
    return score

def caesar_break(ciphertext: str, language: str = "english") -> dict:
    
    language = language.lower()
    candidates = []
    if language == "arabic":
        # Arabic alphabet (28 letters)
        arab_alphabet = "ابتثجحخدذرزسشصضطظعغفقكلمنهوي"
        A = arab_alphabet
        n = len(A)
        # build mapping index
        for k in range(n):
            out = []
            for ch in ciphertext:
                if ch in A:
                    idx = A.index(ch)
                    out.append(A[(idx - k) % n])
                else:
                    out.append(ch)
            plain = ''.join(out)
            score = _score_text_by_language(plain, language)
            candidates.append((k, plain, score))
    else:
        # Latin alphabet 0..25
        for k in range(26):
            plain = caesar_decrypt(ciphertext, k)
            score = _score_text_by_language(plain, language)
            candidates.append((k, plain, score))

    candidates.sort(key=lambda x: x[2], reverse=True)
    best = candidates[0]
    return {"key": best[0], "plaintext": best[1], "candidates": candidates}


# ------------------------------
# Task 2: RSA implementation (manual)
# ------------------------------

def _is_probable_prime(n: int, k: int = 6) -> bool:
    """Miller-Rabin primality test (probabilistic)."""
    if n < 2:
        return False
    small_primes = [2,3,5,7,11,13,17,19,23,29]
    for p in small_primes:
        if n % p == 0:
            return n == p
    # write n-1 as d * 2^s
    d = n - 1
    s = 0
    while d % 2 == 0:
        d //= 2
        s += 1
    import random
    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        composite = True
        for __ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                composite = False
                break
        if composite:
            return False
    return True

def _generate_prime_candidate(bits: int) -> int:
    # generate odd integer with given bits
    p = random.getrandbits(bits)
    p |= (1 << bits - 1) | 1
    return p

def generate_prime(bits: int = 512) -> int:
    """Generate a prime number of 'bits' bits."""
    while True:
        p = _generate_prime_candidate(bits)
        if _is_probable_prime(p):
            return p

def egcd(a: int, b: int):
    if b == 0:
        return (a, 1, 0)
    else:
        g, x1, y1 = egcd(b, a % b)
        return (g, y1, x1 - (a // b) * y1)

def modinv(a: int, m: int) -> int:
    g, x, y = egcd(a, m)
    if g != 1:
        raise Exception('modular inverse does not exist')
    return x % m

def generate_rsa_keypair(bits: int = 512):
    """
    Generate RSA keypair: returns (n, e, d)
    e is usually 65537 but must be coprime with phi(n)
    """
    # generate two distinct primes p and q
    p = generate_prime(bits // 2)
    q = generate_prime(bits // 2)
    while q == p:
        q = generate_prime(bits // 2)
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 65537
    if math.gcd(e, phi) != 1:
        # fallback: choose random odd e
        e = 3
        while math.gcd(e, phi) != 1:
            e += 2
    d = modinv(e, phi)
    return (n, e, d)

# Helpers to convert bytes <-> ints and chunking
def _bytes_to_int(b: bytes) -> int:
    return int.from_bytes(b, byteorder='big')

def _int_to_bytes(i: int, length: int) -> bytes:
    return i.to_bytes(length, byteorder='big')

def rsa_encrypt_int(m_int: int, pub_n: int, pub_e: int) -> int:
    return pow(m_int, pub_e, pub_n)

def rsa_decrypt_int(c_int: int, priv_n: int, priv_d: int) -> int:
    return pow(c_int, priv_d, priv_n)

def rsa_encrypt_bytes(data: bytes, pub_n: int, pub_e: int) -> list:
    """
    Encrypt bytes using RSA by chunking into blocks smaller than n.
    Returns list of integers (cipher blocks).
    """
    k = (pub_n.bit_length() - 1) // 8  # max bytes per block
    if k <= 0:
        raise ValueError("Public modulus too small.")
    blocks = [data[i:i+k] for i in range(0, len(data), k)]
    cipher_blocks = []
    for b in blocks:
        m = _bytes_to_int(b)
        if m >= pub_n:
            raise ValueError("Message chunk integer >= modulus")
        c = rsa_encrypt_int(m, pub_n, pub_e)
        cipher_blocks.append(c)
    return cipher_blocks

def rsa_decrypt_bytes(cipher_blocks: list, priv_n: int, priv_d: int) -> bytes:
    out = bytearray()
    for c in cipher_blocks:
        m = rsa_decrypt_int(c, priv_n, priv_d)
        # compute minimal byte length for this block
        blen = (m.bit_length() + 7) // 8
        if blen == 0:
            out.extend(b'\x00')
        else:
            out.extend(_int_to_bytes(m, blen))
    return bytes(out)

# Helper to serialize/deserialize RSA cipher blocks to JSON-friendly strings
def rsa_encrypt_string(plaintext: str, pub_n: int, pub_e: int) -> str:
    b = plaintext.encode('utf-8')
    c_blocks = rsa_encrypt_bytes(b, pub_n, pub_e)
    # convert to decimal strings and join with commas
    return json.dumps([str(x) for x in c_blocks])

def rsa_decrypt_string(ciphertext_json: str, priv_n: int, priv_d: int) -> str:
    arr = json.loads(ciphertext_json)
    cipher_blocks = [int(x) for x in arr]
    b = rsa_decrypt_bytes(cipher_blocks, priv_n, priv_d)
    return b.decode('utf-8', errors='ignore')


# quick test
if __name__ == "__main__":
    print("[Caesar]", encrypt("Hello", 3), "→", decrypt(encrypt("Hello", 3), 3))
    print("[Vigenere]", encrypt("ATTACKATDAWN", "LEMON"), "→", decrypt(encrypt("ATTACKATDAWN", "LEMON"), "LEMON"))
    # Caesar breaker (English)
    cipher = caesar_encrypt("This is a secret message about the project.", 7)
    res = caesar_break(cipher, "english")
    print("Caesar-break best:", res["key"], res["plaintext"])

    # RSA small demo (using small bits for fast test)
    n,e,d = generate_rsa_keypair(bits=256)
    print("RSA keys (n bits):", n.bit_length())
    sample = "Hello RSA"
    cstr = rsa_encrypt_string(sample, n, e)
    recovered = rsa_decrypt_string(cstr, n, d)
    print("RSA:", sample, "->", cstr, "->", recovered)