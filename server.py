# server.py
# Server supports:
# - signup (store bcrypt-hashed passwords in users.json)
# - login (verify bcrypt hash)
# - registration (receive public key after login)
# - forward ciphertext bytes to other clients (server logs only ciphertext)

import socket
import threading
import json
import os
from crypto import hash_password, verify_password

HOST = '127.0.0.1'
PORT = 65432
USERS_FILE = "users.json"

clients = {}  # conn -> metadata: {"nick":..., "pub": [n,e], "username": ...}
lock = threading.Lock()

def load_users():
    if not os.path.exists(USERS_FILE):
        with open(USERS_FILE, 'w', encoding='utf-8') as f:
            json.dump({}, f)
        return {}
    with open(USERS_FILE, 'r', encoding='utf-8') as f:
        try:
            return json.load(f)
        except Exception:
            return {}

def save_users(users):
    with open(USERS_FILE, 'w', encoding='utf-8') as f:
        json.dump(users, f, indent=2)

def handle_client(conn, addr, users_db):
    print(f"[+] Connected {addr}")
    try:
        # Step 1: expect auth JSON (signup or login)
        raw = conn.recv(8192)
        if not raw:
            conn.close()
            return

        try:
            obj = json.loads(raw.decode('utf-8', errors='ignore'))
        except Exception:
            conn.sendall(json.dumps({"status":"error","msg":"Invalid auth format"}).encode('utf-8'))
            conn.close()
            return

        # Handle signup
        if obj.get("type") == "signup":
            username = obj.get("username")
            password = obj.get("password")
            if not username or not password:
                conn.sendall(json.dumps({"status":"error","msg":"Missing username/password"}).encode('utf-8'))
                conn.close()
                return
            if username in users_db:
                conn.sendall(json.dumps({"status":"error","msg":"User already exists"}).encode('utf-8'))
                conn.close()
                return
            hashed = hash_password(password)
            users_db[username] = hashed
            save_users(users_db)
            conn.sendall(json.dumps({"status":"ok","msg":"Signup successful"}).encode('utf-8'))
            # After signup, expect the client to send registration JSON (nick + pub) next
            raw = conn.recv(8192)
            if not raw:
                conn.close()
                return
            try:
                obj2 = json.loads(raw.decode('utf-8', errors='ignore'))
            except Exception:
                conn.close()
                return
            # treat obj2 as registration (nick + pub)
            nick = obj2.get("nick", username)
            pub = obj2.get("pub")
            with lock:
                clients[conn] = {"nick": nick, "pub": pub, "username": username}
            print(f"[REGISTER after signup] {username} as {nick}, pub={pub}")
        # Handle login
        elif obj.get("type") == "login":
            username = obj.get("username")
            password = obj.get("password")
            if username not in users_db:
                conn.sendall(json.dumps({"status":"error","msg":"User not found"}).encode('utf-8'))
                conn.close()
                return
            stored = users_db[username]
            if not verify_password(password, stored):
                conn.sendall(json.dumps({"status":"error","msg":"Wrong password"}).encode('utf-8'))
                conn.close()
                return
            # success
            conn.sendall(json.dumps({"status":"ok","msg":"Login successful"}).encode('utf-8'))
            # After login, expect registration JSON
            raw = conn.recv(8192)
            if not raw:
                conn.close()
                return
            try:
                obj2 = json.loads(raw.decode('utf-8', errors='ignore'))
            except Exception:
                conn.close()
                return
            nick = obj2.get("nick", username)
            pub = obj2.get("pub")
            with lock:
                clients[conn] = {"nick": nick, "pub": pub, "username": username}
            print(f"[REGISTER after login] {username} as {nick}, pub={pub}")
        else:
            conn.sendall(json.dumps({"status":"error","msg":"Unknown auth type"}).encode('utf-8'))
            conn.close()
            return

        # Main loop: forward ciphertext to other clients, log ciphertext only
        while True:
            data = conn.recv(8192)
            if not data:
                break
            text_display = data.decode('utf-8', errors='ignore')
            with lock:
                meta = clients.get(conn, {})
                nick = meta.get("nick", "?")
            print(f"[Encrypted log] from {nick}: {text_display}")
            # forward raw bytes to others
            with lock:
                for other_conn in list(clients.keys()):
                    if other_conn is not conn:
                        try:
                            other_conn.sendall(data)
                        except Exception:
                            try:
                                other_conn.close()
                            except:
                                pass
                            if other_conn in clients:
                                del clients[other_conn]

    except Exception as e:
        print("Client error:", e)
    finally:
        print(f"[-] Disconnected {addr}")
        with lock:
            if conn in clients:
                del clients[conn]
        try:
            conn.close()
        except:
            pass

def main():
    users_db = load_users()
    print(f"[server] Loaded users: {list(users_db.keys())}")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen()
        print(f"Server listening on {HOST}:{PORT}")
        while True:
            conn, addr = s.accept()
            t = threading.Thread(target=handle_client, args=(conn, addr, users_db), daemon=True)
            t.start()

if __name__ == "__main__":
    main()
