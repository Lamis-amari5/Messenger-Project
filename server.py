# server.py
import socket
import threading
import json

HOST = '127.0.0.1'   # localhost for testing
PORT = 65432

clients = {}  # socket -> nickname
lock = threading.Lock()

def broadcast(sender_sock, data: bytes):
    # forward ciphertext to all other clients (or implement targeted forwarding)
    for sock in list(clients.keys()):
        if sock is not sender_sock:
            try:
                sock.sendall(data)
            except:
                sock.close()
                del clients[sock]

def handle_client(conn, addr):
    print(f"[+] Connected {addr}")
    try:
        # Expect the client to first send a registration JSON bytes or nickname line
        raw = conn.recv(4096)
        if not raw:
            conn.close()
            return

        # Try parse as JSON registration; otherwise treat as nickname plain text
        try:
            obj = json.loads(raw.decode('utf-8', errors='ignore'))
            if isinstance(obj, dict) and obj.get("type") == "register":
                nick = obj.get("nick", str(addr))
                pub = obj.get("pub", None)  # should be [n, e] or similar
                clients[conn] = {"nick": nick, "pub": pub}
                print(f"[REGISTER] {nick} pub={pub}")
            else:
                # fallback
                nick = obj.get("nick", str(addr)) if isinstance(obj, dict) else str(addr)
                clients[conn] = {"nick": nick, "pub": None}
                print(f"[REGISTER-other] {nick}")
        except Exception:
            # treat raw as nickname
            nick = raw.decode('utf-8', errors='ignore').strip() or str(addr)
            clients[conn] = {"nick": nick, "pub": None}
            print(f"[REGISTER (plain)] {nick}")

        # Now handle incoming messages
        while True:
            data = conn.recv(8192)
            if not data:
                break

            # If data starts with JSON and is a public-key-request or other control, you can extend.
            # For now: server logs only encrypted payloads and forwards bytes to others.
            text_display = data.decode('utf-8', errors='ignore')
            print(f"[Encrypted log] from {clients.get(conn, {}).get('nick','?')}: {text_display}")
            broadcast(conn, data)

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
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen()
        print(f"Server listening on {HOST}:{PORT}")
        while True:
            conn, addr = s.accept()
            t = threading.Thread(target=handle_client, args=(conn, addr), daemon=True)
            t.start()

if __name__ == "__main__":
    main()