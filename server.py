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
            users_db[username] = {
                "password_hash": hashed,
                "face_encoding":None,
                "consent":False
            }
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
            stored = users_db[username]["password_hash"]
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
            incoming_json_str = data.decode('utf-8', errors='ignore')
            
            # Get sender info BEFORE processing
            with lock:
                sender_meta = clients.get(conn, {})
                sender_nick = sender_meta.get("nick", "?")
                sender_username = sender_meta.get("username", "?")
            
            try:
                # Attempt to parse the incoming data as our chat JSON
                msg_obj = json.loads(incoming_json_str)
                
                # Check if it's a chat message with a receiver specified
                if msg_obj.get("type") == "chat" and msg_obj.get("receiver"):
                    receiver_username = msg_obj["receiver"]
                    
                    print(f"[Encrypted log] from {sender_nick} to {receiver_username}: {msg_obj.get('ciphertext', 'NO_CIPHERTEXT')[:50]}...")
                    
                    # Find the connection for the receiver
                    receiver_conn = None
                    with lock:
                        for other_conn, meta in clients.items():
                            if meta.get("username") == receiver_username:
                                receiver_conn = other_conn
                                break
                    
                    # Route the message
                    if receiver_conn:
                        try:
                            # Send the *original raw JSON* containing sender/receiver/ciphertext
                            receiver_conn.sendall(data) 
                            print(f"[ROUTED] from {sender_nick} to {receiver_username}")
                        except Exception as e:
                            print(f"[ERROR] Could not send to {receiver_username}: {e}. Closing connection.")
                            # Clean up
                            with lock:
                                if receiver_conn in clients:
                                    del clients[receiver_conn]
                            try:
                                receiver_conn.close()
                            except:
                                pass
                    else:
                        print(f"[WARN] Receiver {receiver_username} not found or not connected.")
                        # (Optional: send a 'user not found' response back to the sender)
                else:
                    # Log raw data if it doesn't match the new chat format
                    print(f"[Encrypted log] from {sender_nick} (UNKNOWN FORMAT): {incoming_json_str}")

            except json.JSONDecodeError:
                # Fallback for non-JSON/legacy/raw data
                print(f"[Encrypted log] from {sender_nick} (RAW DATA): {incoming_json_str}")
                # For now, discard raw data if not a JSON chat message, 
                # as the new protocol requires a receiver.
                pass
            except Exception as e:
                print(f"[Server Error processing message from {sender_nick}]: {e}")

    except Exception as e:
        print(f"[Client Handler Error]: {e}")
    finally:
        with lock:
            if conn in clients:
                username = clients[conn].get("username", "unknown")
                print(f"[-] Disconnected {username}")
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