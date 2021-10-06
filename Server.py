from socket import *
from Crypto.Cipher import AES

import rsa

# Creating server RSA keys (private and public)
(publicRSAKey, privateRSAKey) = rsa.newkeys(1024)

# Create socket using the given port
serverPort = 13000
serverSocket = socket(AF_INET, SOCK_STREAM)
serverSocket.bind(('', serverPort))
serverSocket.listen(1)

print ('Listening on port', serverPort, '...')

# While loop to handle arbitrary sequence of clients making requests
while 1:

    # Waits for some client to connect and creates new socket for  connection
    connectionSocket, addr = serverSocket.accept()
    print("\n*******************************")
    print ('Client Made Connection', addr )

    # Read input line from socket
    clientSentence = connectionSocket.recv(1024)

    # If is a newConnection send the server public RSA key
    if clientSentence.decode('utf-8') == 'newConnection':
        print('Sending RSA public KEY')
        print(publicRSAKey.save_pkcs1('PEM').decode('utf-8'),"\n")
        connectionSocket.send(publicRSAKey.save_pkcs1('PEM'))
    else:
        connectionSocket.close()

    # Wait client AES Key and decrypting it with server RSA private key
    clientAESKey = connectionSocket.recv(1024)
    clientAESKey = rsa.decrypt(clientAESKey, privateRSAKey)
    print('Received AES client KEY encrypted with RSA')

    # Wait client AES Nonce and decrypting it with server RSA private key
    clientAESNonce = connectionSocket.recv(1024)
    clientAESNonce = rsa.decrypt(clientAESNonce, privateRSAKey)
    print('Received AES client NONCE encrypted with RSA')

    # Mount AES client key
    clientAESCipher = AES.new(clientAESKey, AES.MODE_SIV, nonce=clientAESNonce)

    # Wait client Message Tag
    clientMessageTag = connectionSocket.recv(1024)
    print('Received AES client message TAG')

    # Wait client Message
    clientMessage = connectionSocket.recv(1024)
    print('Received AES client message',"\n")

    # Decrypt client Message with Client AES key
    message = clientAESCipher.decrypt_and_verify(clientMessage, clientMessageTag)
    message = message.decode('utf-8')

    # Verify message authenticity
    try:
        clientAESCipher.verify(clientMessageTag)
        print("The message is authentic:", message)

        # Capitalize the sentence
        response = message.upper()

        print("\nAlterating client message to UpperCase:", response, "\n")

        # Encrypt response with client AES key
        clientAESCipher = AES.new(clientAESKey, AES.MODE_SIV, nonce=clientAESNonce)
        cipherResponse, responseTag = clientAESCipher.encrypt_and_digest(response.encode('utf-8'))

        # Send the response tag crypted with client AES key to client
        print('Sending AES response TAG from new message to client')
        print(responseTag,"\n")
        connectionSocket.send(responseTag)

        # Send the response crypted with client AES key to client
        print('Sending AES response to client')
        print(cipherResponse,"\n")
        connectionSocket.send(cipherResponse)
    except ValueError:
        print("Key incorrect or message corrupted")

    print("*******************************")
    # Close the connection socket
    connectionSocket.close()