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
print('Sending newConnection to server looking for server public RSA KEY')
clientSocket.send('newConnection'.encode('utf-8'))

# Read line from server
publicKeyServer = clientSocket.recv(1024)

# Transform response into UTF-8
publicKeyServer = publicKeyServer.decode('utf-8')
print('Received Public RSA server KEY message TAG\n')

# Recreating RSA key to use it as a key
publicKeyServer = rsa.PublicKey.load_pkcs1(publicKeyServer, 'PEM')

key = get_random_bytes(16*2)
nonce = get_random_bytes(16)
cipher = AES.new(key, AES.MODE_SIV, nonce=nonce)

# Send my AES key to server
print('Sending AES key encrypted with public RSA')
print(rsa.encrypt(key, publicKeyServer),"\n")
clientSocket.send(rsa.encrypt(key, publicKeyServer))

# Send my AES nonce to server
print('Sending AES nonce encrypted with public RSA')
print(rsa.encrypt(nonce, publicKeyServer),"\n")
clientSocket.send(rsa.encrypt(nonce, publicKeyServer))

# Get message to send
message = input('Client ready for input\n');

# Encrypt message with AES
ciphertext, tag = cipher.encrypt_and_digest(message.encode('utf-8'))

# Send my AES message tag to server
print('\nSending AES message TAG')
print(tag,"\n")
clientSocket.send(tag)

# Send my AES message to server
print('Sending message encrypted with AES')
print(ciphertext,"\n")
clientSocket.send(ciphertext)

# Read line from server
tag = clientSocket.recv(1024)
print('Received AES server response TAG')

# Read line from server
message = clientSocket.recv(1024)
print('Received AES server response')

# Decrypt client Message with Client RSA key
cipher = AES.new(key, AES.MODE_SIV, nonce=nonce)
plaintext = cipher.decrypt_and_verify(message, tag)
plaintext = plaintext.decode('utf-8')

try:
    cipher.verify(tag)
    print("The message is authentic:", plaintext)
except ValueError:
    print("Key incorrect or message corrupted")

# Close the socket
clientSocket.close()