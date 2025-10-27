Secure Messaging App

A simple client-server messaging application built in Python, developed progressively throughout the semester.
The goal is to practice encryption, hashing, and authentication concepts through a functional messaging system.

🎯 Project Objective

This project aims to:

Implement a secure chat between multiple clients using socket programming.

Ensure confidentiality by encrypting messages on the sender side and decrypting only on the receiver side.

Introduce and apply classical encryption methods (Caesar, Vigenère), and later explore hashing and authentication.

🧠 Current Features (as of Week 2)

Client–server architecture using sockets
Caesar cipher encryption and decryption
Vigenère cipher encryption and decryption
Encrypted messages are sent through the server
Server never sees plaintext, only ciphertext
Each client decrypts locally to view the original message

Project Structure
messenger_project/
├── client.py # Client interface (console)
├── server.py # Server that forwards encrypted messages
├── crypto.py # Contains Caesar and Vigenere ciphers
└── README.md

🚀 How to Run

Start the server

python server.py

Open two terminals and run clients:

python client.py

Choose your nickname.

Select the cipher method (1 for Caesar, 2 for Vigenere).

Enter the encryption key.

Type messages and see encryption/decryption in action!

Server output example:

[Encrypted log] from Alice: LXFOPVEFRNHR

Client output example:

[RECV] (ciphertext: LXFOPVEFRNHR)
[PLAINTEXT] ATTACKATDAWN

🔒 How Encryption Works
Cipher Key Type Description Example
Caesar Integer Shifts each letter by a fixed number. "HELLO" with key 3 → "KHOOR"
Vigenère Word Each letter of the key determines a shift. "HELLO" with key "KEY" → "RIJVS"

Messages are:

Encrypted before sending.

Transmitted as ciphertext.

Decrypted only by clients who know the key.

Next Steps

Planned for future sessions:

Add user authentication (username + hashed password).

Store chat history.

Add a clean Lovable UI (graphical interface).

Implement more encryption/hashing algorithms .

Bioinformatics student — USTHB
This project is part of the “BIO” module.
