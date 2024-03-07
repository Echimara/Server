# auth: Chimara Okeke
# Date: 12/2/2023

# required libraries
from http.server import BaseHTTPRequestHandler, HTTPServer
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from urllib.parse import urlparse, parse_qs
import base64

# for encryption
import os
from base64 import b64encode, b64decode
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes

# for database
import json
import jwt
import datetime
import sqlite3
import uuid
import socket
import argon2  # Make sure to install argon2-cffi package

import time
import threading
from threading import Lock



# Generate a random key for AES encryption
def generate_key():
    return get_random_bytes(16)


# Generate key and encode it as base64
key = generate_key()
base64_key = b64encode(key).decode("utf-8")

# Set the key as an environment variable
os.environ["NOT_MY_KEY"] = base64_key

# Connecting to sqlite
# connection object
connection_obj = sqlite3.connect("totally_not_my_privateKeys.db")

# Retrieve the encryption key from the environment variable
encryption_key = os.environ.get("NOT_MY_KEY")

# Ensure that the encryption key is available
if not encryption_key:
    raise ValueError(
        "Encryption key (NOT_MY_KEY) not found in the environment variables."
    )

# Convert the encryption key to bytes
encryption_key = encryption_key.encode("utf-8")


# Generate a random key for AES encryption
def generate_key():
    return get_random_bytes(16)


# Function to encrypt the private keys using AES encryption
def encrypt_private_key(private_key, key):
    cipher = AES.new(key, AES.MODE_ECB)
    ciphered_data = cipher.encrypt(pad(private_key.encode(), AES.block_size))
    return b64encode(ciphered_data).decode("utf-8")


# function saves priv keys
def save_private_key_to_db(key_pem, expiration):
    # cursor object
    cursor_obj = connection_obj.cursor()

    # Creating table if it doesn't exist
    cursor_obj.execute(
        """
    CREATE TABLE IF NOT EXISTS keys(
        kid INTEGER PRIMARY KEY AUTOINCREMENT,
        key BLOB NOT NULL,
        exp INTEGER NOT NULL
    );
    """
    )

    # Create table users if it doesn't exist
    cursor_obj.execute(
        """
        CREATE TABLE IF NOT EXISTS users(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            email TEXT UNIQUE,
            date_registered TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_login TIMESTAMP      
        );
        """
    )

    # Create table auth_logs if it doesn't exist
    cursor_obj.execute(
        """
    CREATE TABLE IF NOT EXISTS auth_logs(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    request_ip TEXT NOT NULL,
    request_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    user_id INTEGER,  
    FOREIGN KEY(user_id) REFERENCES users(id)
);
    """
    )

    # Insert the new key
    cursor_obj.execute(
        "INSERT INTO keys (key, exp) VALUES (?, ?)", (key_pem, expiration)
    )

    # Commit the changes
    connection_obj.commit()

    print("Key is saved")

    # Close the cursor (not the connection)
    cursor_obj.close()


# provided project 1 template
hostName = "localhost"
serverPort = 8080

private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)
expired_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)

pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption(),
)
expired_pem = expired_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption(),
)

# Before saving the private keys to the database, call the encryption function
# Get the key from environment variable and decode it from base64
key = b64decode(os.getenv("NOT_MY_KEY"))

# Encrypt the private key
encrypted_private_key = encrypt_private_key("your_private_key", key)

# Calls function to save private keys to the database
save_private_key_to_db(
    encrypted_private_key, int(datetime.datetime.timestamp(datetime.datetime.now()))
)
save_private_key_to_db(
    expired_pem,
    int(
        datetime.datetime.timestamp(
            datetime.datetime.now() + datetime.timedelta(hours=1)
        )
    ),
)

numbers = private_key.private_numbers()


def int_to_base64(value):
    """Convert an integer to a Base64URL-encoded string"""
    value_hex = format(value, "x")
    # Ensure even length
    if len(value_hex) % 2 == 1:
        value_hex = "0" + value_hex
    value_bytes = bytes.fromhex(value_hex)
    encoded = base64.urlsafe_b64encode(value_bytes).rstrip(b"=")
    return encoded.decode("utf-8")


class MyServer(BaseHTTPRequestHandler):
    def do_PUT(self):
        self.send_response(405)
        self.end_headers()
        return

    def do_PATCH(self):
        self.send_response(405)
        self.end_headers()
        return

    def do_DELETE(self):
        self.send_response(405)
        self.end_headers()
        return

    def do_HEAD(self):
        self.send_response(405)
        self.end_headers()
        return

    def log_auth_request(self, user_id):
        # Open a cursor to interact with the database
        cursor_obj = connection_obj.cursor()

        # Log the details into the auth_logs table
        cursor_obj.execute(
            """
                INSERT INTO auth_logs (ip_address, timestamp, user_id)
                VALUES (?, ?, ?)
                """,
            (self.client_address[0], datetime.datetime.utcnow(), user_id),
        )

        # Commit the changes to the database
        connection_obj.commit()

        # Close the cursor
        cursor_obj.close()

    def do_POST(self):
        parsed_path = urlparse(self.path)
        params = parse_qs(parsed_path.query)
        if parsed_path.path == "/auth":
            
            headers = {"kid": "goodKID"}
            token_payload = {
                "user": "username",
                "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1),
            }
            if "expired" in params:
                headers["kid"] = "expiredKID"
                token_payload["exp"] = datetime.datetime.utcnow() - datetime.timedelta(
                    hours=1
                )
            encoded_jwt = jwt.encode(
                token_payload, pem, algorithm="RS256", headers=headers
            )

            # Log the details into the auth_logs table
            self.log_auth_request(user_id="username")

            self.send_response(200)
            self.end_headers()
            self.wfile.write(bytes(encoded_jwt, "utf-8"))
            return

        self.send_response(405)
        self.end_headers()
        return

    def log_auth_request(self, user_id):
        # Open a cursor to interact with the database
        print(f"Request logged to auth_logs table for user ID: {user_id}")


def do_POST(self):
    parsed_path = urlparse(self.path)

    if parsed_path.path == "/register":
        # Read the request body
        content_length = int(self.headers["Content-Length"])
        body = self.rfile.read(content_length)
        data = json.loads(body)

        # Extract username and email from the JSON data
        username = data.get("username")
        email = data.get("email")

        # Generate a UUIDv4 password
        generated_password = str(uuid.uuid4())

        # Hash the password using Argon2
        hasher = argon2.PasswordHasher()
        hashed_password = hasher.hash(generated_password)

        # Open a cursor to interact with the database
        cursor_obj = connection_obj.cursor()

        # Create a new record in the users table
        cursor_obj.execute(
            """
            INSERT INTO users (username, email, password_hash)
            VALUES (?, ?, ?)
            """,
            (username, email, hashed_password),
        )

        # Commit the changes to the database
        connection_obj.commit()

        # Close the cursor
        cursor_obj.close()

        # Return the password in JSON format
        response_data = {"password": generated_password}
        self.send_response(201)  # Use 201 for CREATED
        self.end_headers()
        self.wfile.write(bytes(json.dumps(response_data), "utf-8"))
        return

    self.send_response(404)  # Not Found for other endpoints
    self.end_headers()
    self.wfile.write(bytes("Endpoint not found", "utf-8"))
    return


if __name__ == "__main__":
    webServer = HTTPServer((hostName, serverPort), MyServer)
    print("Server started http://%s:%s" % (hostName, serverPort))
    try:
        webServer.serve_forever()
    except KeyboardInterrupt:
        pass

    webServer.server_close()
