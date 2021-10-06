from socket import *
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

import rsa

serverName = "localhost"
serverPort = 13000

# Create socket and connect to server
clientSocket = socket(AF_INET, SOCK_STREAM)
clientSocket.connect((serverName, serverPort))

# Send new Connection to server looking for the server public RSA KEY
print('Sending newConnection to server looking for server public RSA KEY')
clientSocket.send('newConnection'.encode('utf-8'))

# Read line from server
publicRSAKeyServer = clientSocket.recv(1024)

# Transform response into UTF-8
publicRSAKeyServer = publicRSAKeyServer.decode('utf-8')
print('Received Public RSA server KEY message TAG\n')

# Recreating RSA server key to use it as a RSA key
publicRSAKeyServer = rsa.PublicKey.load_pkcs1(publicRSAKeyServer, 'PEM')

# Creating Client AES key
AESkey = get_random_bytes(16*2)
AESnonce = get_random_bytes(16)
AEScipher = AES.new(AESkey, AES.MODE_SIV, nonce=AESnonce)

# Send client AES key crypted with server RSA public key to server
print('Sending AES key encrypted with public RSA')
print(rsa.encrypt(AESkey, publicRSAKeyServer),"\n")
clientSocket.send(rsa.encrypt(AESkey, publicRSAKeyServer))

# Send client AES nonce crypted with server RSA public key to server
print('Sending AES nonce encrypted with public RSA')
print(rsa.encrypt(AESnonce, publicRSAKeyServer),"\n")
clientSocket.send(rsa.encrypt(AESnonce, publicRSAKeyServer))

# Get message to send
message = input('Client ready for input\n')

# Encrypt message with client AES key after encode with utf-8
cipherMessage, messageTag = AEScipher.encrypt_and_digest(message.encode('utf-8'))

# Send client AES message tag to server
print('\nSending AES message TAG')
print(messageTag,"\n")
clientSocket.send(messageTag)

# Send client AES message to server
print('Sending message encrypted with AES')
print(cipherMessage,"\n")
clientSocket.send(cipherMessage)

# Read line from server
responseTag = clientSocket.recv(1024)
print('Received AES server response TAG')

# Read line from server
responseMessage = clientSocket.recv(1024)
print('Received AES server response')

# Decrypt server Response with Client RSA key
AEScipher = AES.new(AESkey, AES.MODE_SIV, nonce=AESnonce)
response = AEScipher.decrypt_and_verify(responseMessage, responseTag)
response = response.decode('utf-8')

# Verify message authenticity
try:
    AEScipher.verify(responseTag)
    print("The response is authentic:", response)
except ValueError:
    print("Key incorrect or message corrupted")

# Close the connection socket
clientSocket.close()