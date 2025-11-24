# client.py
import socket
import threading
import json
from crypto import (
    encrypt, decrypt,
    caesar_break,
    generate_rsa_keypair,
    rsa_encrypt_string, rsa_decrypt_string
)


HOST = '127.0.0.1'
PORT = 65432

last_received_ciphertext = None

def receiver(sock, key, method):
    global last_received_ciphertext
    while True:
        try:
            data = sock.recv(8192)
            if not data:
                print("[*] Server closed connection")
                break
            text = data.decode('utf-8', errors='ignore')
            last_received_ciphertext = text
            # Decrypt locally if it's not JSON control data
            # We'll assume chat messages are ciphertext strings (not JSON)
            try:
                # if it's JSON and control, you could parse it here
                obj = json.loads(text)
                # If it's a control message, show it raw
                print("\n[MSG - control JSON]:", obj, "\n> ", end='', flush=True)
            except Exception:
                plaintext = decrypt(text, key, method)
                print(f"\n[RECV] (ciphertext: {text})\n[PLAINTEXT] {plaintext}\n> ", end='', flush=True)
        except Exception as e:
            print("Receive error:", e)
            break

def main():
    global last_received_ciphertext
    nickname = input("Choose your nickname: ").strip() or "anon"
    # choose cipher and key
    print("Choose cipher method:")
    print("1 - Caesar Cipher")
    print("2 - Vigenere Cipher")
    print("3 - Substitution Cipher")
    print("4 - Transposition Cipher")
    choice = input("Enter 1/2/3/4: ").strip()
    if choice == "2":
        method = "vigenere"
        key = input("Enter Vigenere key (word): ").strip().upper()
    else:
        # allow more methods
        if choice == "3":
            method = "substitution"
            while True:
                key = input("Enter substitution key (26 letters, mapping for A..Z): ").strip()
                clean = ''.join([c for c in key if c.isalpha()])
                if len(clean) == 26:
                    key = clean.upper()
                    break
                print("Key must contain 26 letters (A-Z). Try again.")
        elif choice == "4":
            method = "transposition"
            while True:
                try:
                    key = int(input("Enter transposition key (number of columns > 0): ").strip())
                    if key > 0:
                        break
                    print("Enter an integer > 0.")
                except:
                    print("Enter an integer.")
        else:
            method = "caesar"
            while True:
                try:
                    key = int(input("Enter Caesar key (0-25): ").strip())
                    break
                except:
                    print("Enter an integer.")
    

    print("Generating RSA keypair (this may take a few seconds)...")
    n, e, d = generate_rsa_keypair(bits=512)  # adjust bits if needed
    print(f"RSA public key (n bits): {n.bit_length()}, public exponent e={e}")
    # Register on server with public key
    registration = {"type": "register", "nick": nickname, "pub": [str(n), str(e)]}

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((HOST, PORT))
    s.sendall(json.dumps(registration).encode('utf-8'))

    t = threading.Thread(target=receiver, args=(s, key, method), daemon=True)
    t.start()

    print("\nConnected! Commands:\n - /quit to exit\n - /break <lang>  -> try to auto-break last ciphertext as Caesar (languages: english,french,arabic)\n - /rsa_demo <text> -> encrypt text with your own public key then decrypt it (demo)\nType message to send (it will be encrypted before sending).")

    try:
        while True:
            msg = input("> ").strip()
            if msg == "":
                continue
            if msg.lower() == "/quit":
                break
            if msg.startswith("/break"):
                parts = msg.split()
                lang = parts[1] if len(parts) > 1 else "english"
                if last_received_ciphertext is None:
                    print("No ciphertext received yet to break.")
                else:
                    print("Trying to break last_received_ciphertext with Caesar brute-force...")
                    res = caesar_break(last_received_ciphertext, lang)
                    print("Best key:", res["key"])
                    print("Plaintext guess:\n", res["plaintext"])
                continue
            if msg.startswith("/rsa_demo"):
                # show RSA encrypt/decrypt demo using local keys
                toenc = msg[len("/rsa_demo"):].strip() or "Hello RSA demo"
                cstr = rsa_encrypt_string(toenc, n, e)
                print("Encrypted (json):", cstr)
                rec = rsa_decrypt_string(cstr, n, d)
                print("Decrypted:", rec)
                continue

            # Otherwise treat as chat message: encrypt and send
            ciphertext = encrypt(msg, key, method)
            s.sendall(ciphertext.encode('utf-8'))
            print(f"(sent ciphertext: {ciphertext})")

    except KeyboardInterrupt:
        print("\nExiting.")
    finally:
        s.close()

if __name__ == "__main__":
    main()