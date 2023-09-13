import json
import socket
import threading
from pymongo import MongoClient
from Crypto.Cipher import AES
import binascii, os
import time

# Connect to MongoDB
client = MongoClient('mongodb://localhost:27017/')
db = client['test']
collection = db['params']


# Decrypt function with time measurement
def decrypt_AES_GCM(encryptedMsg, secretKey):
    (ciphertext, nonce, authTag) = encryptedMsg

    aesCipher = AES.new(secretKey, AES.MODE_GCM, nonce)

    # Measure the time for decryption
    start_time = time.perf_counter()  # Start measuring time
    plaintext = aesCipher.decrypt_and_verify(ciphertext, authTag)
    decryption_time = (time.perf_counter() - start_time) * 1000  # Convert to milliseconds
    print('Decryption time (ms):', decryption_time)

    return plaintext


def handle_client(client_socket, secretKey):
    print('Handling connection from', client_socket.getpeername())

    # Step 1: Receive the client's handshake message
    client_handshake_msg = client_socket.recv(1024).decode('utf-8')

    # Step 2: Process the client's handshake message and decide whether to accept or reject the connection
    if "SecureConnectionRequest" in client_handshake_msg:
        # Step 3: Send a handshake acceptance message to the client
        server_response = "SecureConnectionAccepted"
        client_socket.send(server_response.encode('utf-8'))

        # Continue with data transmission
        while True:
            data = client_socket.recv(1024)
            if not data:
                break

            try:
                encryptedMsg = json.loads(data.decode('utf-8'))
                print("Received data:", encryptedMsg)
                ciphertext = bytes.fromhex(encryptedMsg['ciphertext'])
                nonce = bytes.fromhex(encryptedMsg['aesIV'])
                authTag = bytes.fromhex(encryptedMsg['authTag'])

                # Decrypt the message
                decrypted_data = decrypt_AES_GCM((ciphertext, nonce, authTag), secretKey)

                # Parse the decrypted data as JSON
                d = json.loads(decrypted_data.decode('utf-8'))
                print(d)

                # Store the data in MongoDB or perform other processing
                result = collection.insert_one(d)
                if result.acknowledged:
                    print("Data stored successfully", 201)
                else:
                    print("Error storing data", 500)
            except Exception as e:
                print("Exception:", e)

    else:
        # Step 4: Send a handshake rejection message to the client
        server_response = "SecureConnectionRejected"
        client_socket.send(server_response.encode('utf-8'))

    client_socket.close()
    print("Connection closed for", client_socket.getpeername())


if __name__ == '__main__':
    secretKey = b'MySecretKey12345'  # 256-bit random encryption key
    print("Encryption key:", binascii.hexlify(secretKey))

    # Create a socket object
    s = socket.socket()

    # Bind the socket to a specific IP and port
    server_host = ''  # Listen on all available interfaces
    server_port = 5000
    s.bind((server_host, server_port))

    # Put the socket into listening mode
    s.listen(5)
    print("Server is listening")

    # Accept client connections and create a new thread to handle each client
    while True:
        print('Client')
        client_socket, addr = s.accept()
        print('Got connection from', addr)

        client_thread = threading.Thread(target=handle_client, args=(client_socket, secretKey))
        client_thread.start()
