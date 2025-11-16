Secure Chat System (Information Security Assignment)

This is a Python-based secure chat application built for an Information Security course. It implements a custom, application-layer cryptographic protocol to achieve Confidentiality, Integrity, Authenticity, and Non-Repudiation (CIANR) between a client and a server.

This project does not use TLS/SSL or any other pre-built secure channel abstraction. All security guarantees are implemented from scratch at the application layer using raw sockets and the cryptography library, as per the assignment requirements.

Core Features Implemented

PKI & Certificate Validation: A custom Root CA (gen_ca.py) issues signed X.509 certificates to the client and server (gen_cert.py). The server and client perform mutual authentication by verifying each other's certificates against this CA.

Secure Registration & Login: User credentials are stored securely in a MySQL database. Passwords are never stored, only a cryptographically-strong salt (16 bytes) and a salted hash (pwd_hash using SHA-256).

Encrypted Credential Transport: Before login or registration, the client and server perform a temporary Diffie-Hellman (DH) exchange to create an ephemeral AES key. The user's password is encrypted with this key before being sent, ensuring it is never in plaintext on the wire.

Confidentiality (AES-128): After successful authentication, a second DH exchange establishes a unique session key. All subsequent chat messages are encrypted using AES-128-CBC with PKCS#7 padding.

Integrity & Authenticity (RSA + SHA-256): Every chat message is individually signed. The hash SHA256(seqno || timestamp || ciphertext) is signed with the sender's private RSA key. The receiver verifies this signature with the sender's public key (from their certificate), protecting against tampering.

Replay Protection: A strictly increasing sequence number (seqno) is included in every message. The server and client track the last-seen seqno and reject any message that is out-of-order or a duplicate.

Non-Repudiation: A complete Transcript of all messages (sent and received) is maintained by both parties. Upon quitting, a SessionReceipt is generated, which contains a SHA-256 hash of the entire transcript, digitally signed by the user. This receipt can be verified offline with verify_transcript.py to prove the session's authenticity.

How to Run

This guide assumes you have Python 3.8+, Git, and a MySQL server already installed.

Phase 1: Setup (One-Time Only)

Clone the Repository:

git clone git@github.com:Shaharyar2442/securechat-skeleton-i220999.git
cd securechat-skeleton


Create and Activate Virtual Environment:

# Create the venv
python -m venv venv

# Activate on Windows
.\venv\Scripts\activate


Install Dependencies:

(venv) pip install -r requirements.txt


Setup MySQL Database:

Log in to your MySQL command-line client as root.

Create the database and a dedicated user:

CREATE DATABASE secure_chat;
CREATE USER 'secure_chat_user'@'localhost' IDENTIFIED BY 'your_password_here';
GRANT ALL PRIVILEGES ON secure_chat.* TO 'secure_chat_user'@'localhost';
FLUSH PRIVILEGES;
EXIT;


Edit config.py: Open the config.py file and update the DB_PASSWORD variable with the password you just created.

Initialize the Database Table:

This command runs the db.py script to create the users table inside your secure_chat database.

(venv) python -m app.storage.db


Success output: Users table checked/created successfully.

Generate Certificates:

These commands create the certs/ directory and all required keys and certificates.

# 1. Create the Root CA
(venv) python scripts/gen_ca.py

# 2. Create the Server certificate (signed by the CA)
(venv) python scripts/gen_cert.py server server

# 3. Create the Client certificate (signed by the CA)
(venv) python scripts/gen_cert.py client client


Your certs folder is now complete.

Phase 2: Running the Application

You will need two terminals.

Terminal 1: Start the Server

# Make sure your venv is active
(venv) python -m app.server


Leave this running. It will say: Server listening on localhost:12345...

Terminal 2: Start the Client

# Open a new terminal and activate the venv
.\venv\Scripts\activate
(venv) python -m app.client


You can now follow the prompts to:

Register a new user.

Login as that user.

Chat (all messages are encrypted and signed).

Quit by typing !!quit.

Phase 3: Verifying the Session (Non-Repudiation Test)

After you quit a chat session with !!quit, the client generates two files:

server_transcript.log (A log of all messages from the server's perspective)

server_session_receipt.json (The signed hash of that log)

You can verify the integrity of this session by running:

(venv) python verify_transcript.py server_session_receipt.json


Successful Output:

Verifying session using receipt: server_session_receipt.json
 - Loading transcript: server_transcript.log
 - Loading our certificate: certs/client.crt
--- Verifying Session Receipt ---
  - Computed Hash: [some_hash_value]
  - Receipt Hash:  [the_exact_same_hash_value]
  - Hash MATCH: Transcript integrity confirmed.
  - Verifying signature over receipt hash...
  - Receipt signature is VALID.
--- Tamper Test ---
  ...
  - SUCCESS: Tampered hash does not match receipt hash.
Verification complete.


This output is the final proof that the SessionReceipt cryptographically guarantees the integrity of the Transcript.