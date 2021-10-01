from socket import *

import rsa
from Crypto.Cipher import AES

(public, private) = rsa.newkeys(1024)

print(public)

serverPort = 13000
# Create socket using the given port
serverSocket = socket(AF_INET, SOCK_STREAM)
serverSocket.bind(('', serverPort))
serverSocket.listen(1)
print ('Listening on port', serverPort, '...')

# While loop to handle arbitrary sequence of clients making requests
while 1:

    # Waits for some client to connect and creates new socket for  connection
    connectionSocket, addr = serverSocket.accept()
    print ('Client Made Connection', addr )

    # Read input line from socket
    clientSentence = connectionSocket.recv(1024)

    if clientSentence.decode('utf-8') == 'newConnection':
        print('Sending public key')
        connectionSocket.sendall(public.save_pkcs1('PEM'))
    else:
        connectionSocket.close()

    # Read input line from socket
    clientKey = connectionSocket.recv(1024)
    clientKey = rsa.decrypt(clientKey,private)
    clientNonce = connectionSocket.recv(1024)
    clientNonce = rsa.decrypt(clientNonce,private)

    clientCipher = AES.new(clientKey, AES.MODE_EAX, nonce=clientNonce)

    clientTag = connectionSocket.recv(1024)
    clientTag = rsa.decrypt(clientTag,private)
    clientMessage = connectionSocket.recv(1024)
    clientMessage = rsa.decrypt(clientMessage,private)

    
    plaintext = clientCipher.decrypt(clientMessage)

    try:
        clientCipher.verify(clientTag)
        print("The message is authentic:", plaintext)
    except ValueError:
        print("Key incorrect or message corrupted")

    # Close the connection socket
    connectionSocket.close()
