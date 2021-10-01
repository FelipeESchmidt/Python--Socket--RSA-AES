from socket import *

import rsa

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

serverName = "localhost"
serverPort = 13000

# Create socket and connect to server
clientSocket = socket(AF_INET, SOCK_STREAM)
clientSocket.connect((serverName, serverPort))

# Write line to server
clientSocket.sendall('newConnection'.encode('utf-8'))

# Read line from server
publicKeyServer = clientSocket.recv(1024)

# Transform response into UTF-8
publicKeyServer = publicKeyServer.decode('utf-8')

print(publicKeyServer)

# Recreating RSA key to use it as a key
publicKeyServer = rsa.PublicKey.load_pkcs1(publicKeyServer, 'PEM')

key = get_random_bytes(16)
cipher = AES.new(key, AES.MODE_EAX)
nonce = cipher.nonce

# Send my AES key to server
clientSocket.sendall(rsa.encrypt(key, publicKeyServer))

# Send my AES nonce to server
clientSocket.sendall(rsa.encrypt(nonce, publicKeyServer))

# Get message to send
message = input('Client ready for input\n');

# Encrypt message with AES
ciphertext, tag = cipher.encrypt_and_digest(message.encode('utf-8'))

# Send my AES message tag to server
clientSocket.sendall(rsa.encrypt(tag, publicKeyServer))

# Send my AES message to server
clientSocket.sendall(rsa.encrypt(ciphertext, publicKeyServer))

# Read line from server
key = clientSocket.recv(1024)

# Read line from server
message = clientSocket.recv(1024)

# Decrypt client Message with Client RSA key
plaintext = cipher.decrypt(message)

try:
    cipher.verify(tag)
    print("The message is authentic:", plaintext)
except ValueError:
    print("Key incorrect or message corrupted")

# Close the socket
clientSocket.close()