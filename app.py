# app.py
import streamlit as st
import socket
import threading
import json
import time
import queue
import cv2
import numpy as np

from crypto import (
    hash_password,
    verify_password,
    extract_face_encoding_from_image,
    verify_face_encoding,
    encrypt,
    decrypt,
    rsa_encrypt_string,
    rsa_decrypt_string,
    PUB_N, PUB_E, PRIV_N, PRIV_D
)

USERS_FILE = "users.json"
SERVER_HOST = "127.0.0.1"
SERVER_PORT = 65432

# ------------------------------
# Session state init (VERY IMPORTANT)
# ------------------------------
def init_state():
    defaults = {
        "authenticated": False,
        "current_user": None,
        "face_verified": False,
        "sock": None,
        "connected": False,
        "messages": [],
        "message_queue": queue.Queue(),
        "my_method": "caesar",
        "my_key": 3,
        "decrypt_method": "caesar",
        "decrypt_key": 3,
        "password_plain": None
    }
    for k, v in defaults.items():
        if k not in st.session_state:
            st.session_state[k] = v

init_state()

# ------------------------------
# Load & Save users (local)
# ------------------------------
def load_users():
    try:
        with open(USERS_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except:
        return {}

def save_users(users):
    with open(USERS_FILE, "w", encoding="utf-8") as f:
        json.dump(users, f, indent=2)

users = load_users()

# ------------------------------
# SOCKET RECEIVE THREAD
# ------------------------------
def receive_messages(sock, msg_queue):
    """Thread-safe message receiver that puts incoming messages into a queue"""
    while True:
        try:
            data = sock.recv(8192)
            if not data:
                break

            s = data.decode("utf-8", errors="ignore")
            try:
                obj = json.loads(s)
                if obj.get("type") == "chat":
                    msg_queue.put({
                        "sender": obj.get("sender"),
                        "receiver": obj.get("receiver"),
                        "method": obj.get("method"),
                        "ciphertext": obj.get("ciphertext"),
                        "time": time.time(),
                        "is_own": False  # Mark as received message
                    })
            except json.JSONDecodeError:
                pass
        except:
            break

# ------------------------------
# CHAT INTERFACE
# ------------------------------
def chat_interface():
    st.set_page_config(page_title="Secure Messenger", layout="wide")
    
    user = st.session_state.current_user
    
    # ---------- CONNECT TO SERVER ----------
    if not st.session_state.connected:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((SERVER_HOST, SERVER_PORT))
            st.session_state.sock = sock

            # LOGIN AUTH
            auth = {
                "type": "login",
                "username": user,
                "password": st.session_state.password_plain
            }
            sock.sendall(json.dumps(auth).encode())

            # Wait for response
            response = sock.recv(4096)
            resp_obj = json.loads(response.decode('utf-8', errors='ignore'))
            
            if resp_obj.get("status") != "ok":
                st.error(f"Login failed: {resp_obj.get('msg', 'Unknown error')}")
                st.session_state.authenticated = False
                st.stop()

            # REGISTRATION (send public key)
            reg = {"nick": user, "pub": [PUB_N, PUB_E]}
            sock.sendall(json.dumps(reg).encode())

            # Start receiver thread
            threading.Thread(
                target=receive_messages,
                args=(sock, st.session_state.message_queue),
                daemon=True
            ).start()

            st.session_state.connected = True
            st.rerun()
            
        except Exception as e:
            st.error(f"Connection error: {e}")
            st.stop()

    # ---------- RECEIVE NEW MESSAGES ----------
    new_messages = []
    while not st.session_state.message_queue.empty():
        new_messages.append(st.session_state.message_queue.get())
    
    if new_messages:
        st.session_state.messages.extend(new_messages)
        st.rerun()

    # ---------- LAYOUT ----------
    col1, col2 = st.columns([1, 3])
    
    with col1:
        st.title("🔐 Secure Chat")
        st.write(f"**User:** {user}")
        st.write(f"**Status:** 🟢 Connected")
        
        st.divider()
        
        # Encryption settings
        st.subheader("🔒 Your Encryption")
        st.session_state.my_method = st.selectbox(
            "Method",
            ["caesar", "vigenere", "substitution", "transposition", "rsa"],
            key="method_select"
        )

        # Set encryption key based on method
        if st.session_state.my_method == "caesar":
            st.session_state.my_key = st.number_input("Shift Key", 0, 25, 3, key="caesar_key")
        elif st.session_state.my_method == "vigenere":
            st.session_state.my_key = st.text_input("Keyword", value="KEY", key="vigenere_key")
        elif st.session_state.my_method == "substitution":
            st.session_state.my_key = st.text_input(
                "26-letter key", 
                value="ZYXWVUTSRQPONMLKJIHGFEDCBA", 
                key="sub_key"
            )
        elif st.session_state.my_method == "transposition":
            st.session_state.my_key = st.number_input("Columns", 2, 10, 3, key="trans_key")
        
        st.divider()
        
        if st.button("🚪 Logout", use_container_width=True):
            if st.session_state.sock:
                try:
                    st.session_state.sock.close()
                except:
                    pass
            st.session_state.clear()
            st.rerun()
    
    with col2:
        st.title("💬 Conversation")
        
        # ---------- CHAT MESSAGES DISPLAY ----------
        chat_container = st.container(height=450)
        
        with chat_container:
            if not st.session_state.messages:
                st.info("No messages yet. Start chatting!")
            else:
                for msg in st.session_state.messages:
                    is_own = msg.get("is_own", False)
                    sender = msg.get("sender", user)
                    ciphertext = msg.get("ciphertext", "")
                    method = msg.get("method", "caesar")
                    
                    # Decrypt the message
                    try:
                        if method == "rsa":
                            plaintext = rsa_decrypt_string(ciphertext, PRIV_N, PRIV_D)
                        else:
                            # Use the key from the message or default
                            plaintext = decrypt(
                                ciphertext,
                                st.session_state.my_key,  # Use your own key to decrypt
                                method
                            )
                    except Exception as e:
                        plaintext = f"⚠️ Decryption failed: {str(e)[:50]}"
                    
                    # Display message
                    if is_own:
                        # Own message - right side
                        with st.chat_message("user"):
                            st.markdown(f"**You** • {method.upper()}")
                            st.write(plaintext)
                            with st.expander("🔐 Show ciphertext"):
                                st.code(ciphertext, language=None)
                    else:
                        # Received message - left side
                        with st.chat_message("assistant"):
                            st.markdown(f"**{sender}** • {method.upper()}")
                            st.write(plaintext)
                            with st.expander("🔐 Show ciphertext"):
                                st.code(ciphertext, language=None)
        
        st.divider()
        
        # ---------- SEND MESSAGE FORM ----------
        st.subheader("✉️ Send Message")
        
        with st.form("send_form", clear_on_submit=True):
            col_a, col_b = st.columns([2, 1])
            
            with col_a:
                message_text = st.text_area(
                    "Message", 
                    placeholder="Type your message here...",
                    height=100,
                    label_visibility="collapsed"
                )
            
            with col_b:
                receiver = st.text_input(
                    "To", 
                    placeholder="username",
                    label_visibility="collapsed"
                )
                send_button = st.form_submit_button("🚀 Send", use_container_width=True)
        
        if send_button and message_text and receiver:
            try:
                # Encrypt the message
                if st.session_state.my_method == "rsa":
                    encrypted = rsa_encrypt_string(message_text, PUB_N, PUB_E)
                else:
                    encrypted = encrypt(
                        message_text, 
                        st.session_state.my_key, 
                        st.session_state.my_method
                    )

                # Create payload
                payload = {
                    "type": "chat",
                    "sender": user,
                    "receiver": receiver,
                    "method": st.session_state.my_method,
                    "ciphertext": encrypted
                }

                # Send to server
                st.session_state.sock.sendall(json.dumps(payload).encode())

                # Add to own messages (mark as own)
                st.session_state.messages.append({
                    "sender": user,
                    "receiver": receiver,
                    "method": st.session_state.my_method,
                    "ciphertext": encrypted,
                    "time": time.time(),
                    "is_own": True
                })
                
                st.success(f"✅ Message sent to {receiver}")
                time.sleep(0.5)
                st.rerun()
                
            except Exception as e:
                st.error(f"Send failed: {e}")

# ------------------------------
# AUTHENTICATION
# ------------------------------
def auth_interface():
    st.set_page_config(page_title="Login - Secure Messenger", layout="centered")
    st.title("🔐 Messenger with Face Recovery")

    choice = st.sidebar.selectbox(
        "Menu",
        ["Login", "Signup", "Forgot Password"]
    )

    # ---------- SIGNUP ----------
    if choice == "Signup":
        st.subheader("Create New Account")
        
        u = st.text_input("Username")
        p = st.text_input("Password", type="password")
        p2 = st.text_input("Confirm Password", type="password")
        
        st.info("📸 Take a photo for face recovery")
        img = st.camera_input("Face Photo")

        if st.button("📝 Signup", use_container_width=True):
            if not u or not p:
                st.error("Username and password required")
            elif p != p2:
                st.error("Passwords don't match")
            elif u in users:
                st.error("User already exists")
            elif not img:
                st.error("Face photo required")
            else:
                try:
                    img_np = cv2.cvtColor(
                        cv2.imdecode(
                            np.frombuffer(img.read(), np.uint8),
                            cv2.IMREAD_COLOR
                        ),
                        cv2.COLOR_BGR2RGB
                    )
                    enc = extract_face_encoding_from_image(img_np)
                    
                    if enc is None:
                        st.error("No face detected. Please try again.")
                    else:
                        users[u] = {
                            "password_hash": hash_password(p),
                            "face_encoding": enc.tolist()
                        }
                        save_users(users)
                        st.success("✅ Account created! You can now login.")
                except Exception as e:
                    st.error(f"Signup error: {e}")

    # ---------- LOGIN ----------
    elif choice == "Login":
        st.subheader("Login to Your Account")
        
        u = st.text_input("Username")
        p = st.text_input("Password", type="password")

        if st.button("🔓 Login", use_container_width=True):
            if u in users and verify_password(p, users[u]["password_hash"]):
                st.session_state.authenticated = True
                st.session_state.current_user = u
                st.session_state.password_plain = p
                st.success("Login successful!")
                time.sleep(0.5)
                st.rerun()
            else:
                st.error("❌ Invalid credentials")

    # ---------- FORGOT PASSWORD ----------
    elif choice == "Forgot Password":
        st.subheader("Reset Password with Face Verification")
        
        u = st.text_input("Username")
        
        if u and u not in users:
            st.error("User not found")
            st.stop()
        
        st.info("📸 Take a photo to verify your identity")
        img = st.camera_input("Face Photo")

        if st.button("🔍 Verify Face") and img and u in users:
            try:
                img_np = cv2.cvtColor(
                    cv2.imdecode(
                        np.frombuffer(img.read(), np.uint8),
                        cv2.IMREAD_COLOR
                    ),
                    cv2.COLOR_BGR2RGB
                )
                live = extract_face_encoding_from_image(img_np)
                
                if live is None:
                    st.error("No face detected")
                else:
                    stored = users[u]["face_encoding"]
                    if verify_face_encoding(stored, live):
                        st.session_state.face_verified = True
                        st.success("✅ Face verified!")
                        st.rerun()
                    else:
                        st.error("❌ Face verification failed")
            except Exception as e:
                st.error(f"Verification error: {e}")

        if st.session_state.face_verified:
            st.divider()
            newp = st.text_input("New Password", type="password")
            newp2 = st.text_input("Confirm New Password", type="password")
            
            if st.button("🔄 Reset Password"):
                if newp != newp2:
                    st.error("Passwords don't match")
                elif not newp:
                    st.error("Password required")
                else:
                    users[u]["password_hash"] = hash_password(newp)
                    save_users(users)
                    st.success("✅ Password updated! You can now login.")
                    st.session_state.face_verified = False
                    time.sleep(1)
                    st.rerun()

# ------------------------------
# ROUTING
# ------------------------------
if st.session_state.authenticated:
    chat_interface()
else:
    auth_interface()