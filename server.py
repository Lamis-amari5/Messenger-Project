# server.py
import socket
import threading

HOST = '127.0.0.1'   # localhost for testing
PORT = 65432

clients = {}  # socket -> nickname

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
        # first message: nickname (plaintext or encrypted? for simplicity, treat nickname as first message in plain)
        nickname = conn.recv(1024).decode('utf-8', errors='ignore').strip()
        if not nickname:
            nickname = str(addr)
        clients[conn] = nickname
        print(f"Client name: {nickname}")
        while True:
            data = conn.recv(4096)
            if not data:
                break
            # data is expected to be ciphertext bytes
            # Log ciphertext only:
            print(f"[Encrypted log] from {nickname}: {data.decode('utf-8', errors='ignore')}")
            # Forward ciphertext to other clients
            broadcast(conn, data)
    except Exception as e:
        print("Client error:", e)
    finally:
        print(f"[-] Disconnected {addr}")
        if conn in clients:
            del clients[conn]
        conn.close()

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