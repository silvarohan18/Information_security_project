import socket
import time
import random
from datetime import datetime
import json
from Crypto.Cipher import AES
import binascii, os

def encrypt_AES_GCM(msg, secretKey):
    aesCipher = AES.new(secretKey, AES.MODE_GCM)
    ciphertext, authTag = aesCipher.encrypt_and_digest(msg)
    return (ciphertext, aesCipher.nonce, authTag)

# Create a socket object
c = socket.socket()

# Define the server host and port to connect to
server_host = '127.0.0.1'  # Replace with the server's IP address
server_port = 5000
secretKey = b'MySecretKey12345'

# Connect to the server
c.connect((server_host, server_port))
print(f"Connected to {server_host}:{server_port}")

# Step 1: Send a handshake request to the server
client_handshake_msg = "SecureConnectionRequest"
c.send(client_handshake_msg.encode('utf-8'))

# Step 2: Receive the server's handshake response
server_response = c.recv(1024).decode('utf-8')

if server_response == "SecureConnectionAccepted":
    print("Handshake with the server successful. Establishing secure connection.")

    # Continue with data transmission
    try:
        while True:
            electrical_params = {
                "timestamp": datetime.now().strftime("%m/%d/%Y-%H:%M:%S.%f")[:-4],
                "voltage": round(random.uniform(225, 240), 6),
                "current": round(random.uniform(5, 10), 6),
                "frequency": round(random.uniform(48, 52), 6),
                "rocof": round(random.uniform(-2.40, 2.40), 6),
            }
            d = json.dumps(electrical_params)
            msg = str(d).encode('utf-8')

            # Measure the time for encryption
            start_time = time.perf_counter()
            encryptedMsg = encrypt_AES_GCM(msg, secretKey)
            encryption_time = (time.perf_counter() - start_time) * 1000  # Convert to milliseconds

            print("Encryption time (ms):", encryption_time)
            print("EncryptedMsg", encryptedMsg)

            # Serialize the encrypted message before sending
            serialized_encryptedMsg = json.dumps({
                'ciphertext': binascii.hexlify(encryptedMsg[0]).decode('utf-8'),
                'aesIV': binascii.hexlify(encryptedMsg[1]).decode('utf-8'),
                'authTag': binascii.hexlify(encryptedMsg[2]).decode('utf-8')
            }).encode('utf-8')

            c.sendall(serialized_encryptedMsg)

            time.sleep(1)

    except KeyboardInterrupt:
        print("Client stopped")

else:
    print("Handshake with the server failed. Connection rejected.")

# Close the connection with the server
c.close()
