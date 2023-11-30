# Name: Chimara Okeke
# Date: 10/29/2023
# Class: CSCE3550.001
# Project 2: Extending the JWKS server

# required libraries
from http.server import BaseHTTPRequestHandler, HTTPServer
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from urllib.parse import urlparse, parse_qs
import base64
import json
import jwt
import datetime

import sqlite3

# Connecting to sqlite
# connection object
connection_obj = sqlite3.connect('totally_not_my_privateKeys.db')

# function saves priv keys
def save_private_key_to_db(key_pem, expiration):
    # cursor object
    cursor_obj = connection_obj.cursor()

    # Creating table if it doesn't exist
    cursor_obj.execute("""
    CREATE TABLE IF NOT EXISTS keys(
        kid INTEGER PRIMARY KEY AUTOINCREMENT,
        key BLOB NOT NULL,
        exp INTEGER NOT NULL
    );
    """)

    # Insert the new key
    cursor_obj.execute("INSERT INTO keys (key, exp) VALUES (?, ?)", (key_pem, expiration))
    
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
    encryption_algorithm=serialization.NoEncryption()
)
expired_pem = expired_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption()
)

# Calls function to save private keys to the database
save_private_key_to_db(pem, int(datetime.datetime.timestamp(datetime.datetime.now())))
save_private_key_to_db(expired_pem, int(datetime.datetime.timestamp(datetime.datetime.now() + datetime.timedelta(hours=1))))

# function to close the database connection
def close_database_connection():
    try:
        connection_obj.close()
        print("Database connection closed.")
    except Exception as e:
        print(f"Error closing database connection: {e}")
numbers = private_key.private_numbers()

def int_to_base64(value):
    """Convert an integer to a Base64URL-encoded string"""
    value_hex = format(value, 'x')
    # Ensure even length
    if len(value_hex) % 2 == 1:
        value_hex = '0' + value_hex
    value_bytes = bytes.fromhex(value_hex)
    encoded = base64.urlsafe_b64encode(value_bytes).rstrip(b'=')
    return encoded.decode('utf-8')


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

    def do_POST(self):
        parsed_path = urlparse(self.path)
        params = parse_qs(parsed_path.query)
        if parsed_path.path == "/auth":
            headers = {
                "kid": "goodKID"
            }
            token_payload = {
                "user": "username",
                "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1)
            }
            if 'expired' in params:
                headers["kid"] = "expiredKID"
                token_payload["exp"] = datetime.datetime.utcnow() - datetime.timedelta(hours=1)
            encoded_jwt = jwt.encode(token_payload, pem, algorithm="RS256", headers=headers)
            self.send_response(200)
            self.end_headers()
            self.wfile.write(bytes(encoded_jwt, "utf-8"))
            return

        self.send_response(405)
        self.end_headers()
    except Exception as e:
            print(f"Error processing POST request: {e}")
            self.send_response(500)
            self.end_headers()
            return

    def do_GET(self):
        if self.path == "/.well-known/jwks.json":
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            keys = {
                "keys": [
                    {
                        "alg": "RS256",
                        "kty": "RSA",
                        "use": "sig",
                        "kid": "goodKID",
                        "n": int_to_base64(numbers.public_numbers.n),
                        "e": int_to_base64(numbers.public_numbers.e),
                    }
                ]
            }
            self.wfile.write(bytes(json.dumps(keys), "utf-8"))
            return

        self.send_response(405)
        self.end_headers()
        return


if __name__ == "__main__":
    webServer = HTTPServer(("localhost", 8080), MyServer)
    try:
        webServer.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        webServer.server_close()
        close_database_connection()


