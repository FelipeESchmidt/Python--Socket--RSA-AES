from socket import *

import rsa
from Crypto.Cipher import AES

(public, private) = rsa.newkeys(1024)

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
    print("\n*******************************")
    print ('Client Made Connection', addr )

    # Read input line from socket
    clientSentence = connectionSocket.recv(1024)

    if clientSentence.decode('utf-8') == 'newConnection':
        print('Sending RSA public KEY')
        print(public.save_pkcs1('PEM').decode('utf-8'),"\n")
        connectionSocket.send(public.save_pkcs1('PEM'))
    else:
        connectionSocket.close()

    # Wait client Key and decrypting it
    clientKey = connectionSocket.recv(1024)
    clientKey = rsa.decrypt(clientKey,private)
    print('Received AES client KEY')

    # Wait client Nonce and decrypting it
    clientNonce = connectionSocket.recv(1024)
    clientNonce = rsa.decrypt(clientNonce,private)
    print('Received AES client NONCE')

    # Mount AES client key
    clientCipher = AES.new(clientKey, AES.MODE_SIV, nonce=clientNonce)

    # Wait client Tag and decrypting it
    clientTag = connectionSocket.recv(1024)
    clientTag = rsa.decrypt(clientTag,private)
    print('Received AES client message TAG')

    # Wait client Message and decrypting it
    clientMessage = connectionSocket.recv(1024)
    clientMessage = rsa.decrypt(clientMessage,private)
    print('Received AES client message',"\n")

    # Decrypt client Message with Client RSA key
    plaintext = clientCipher.decrypt_and_verify(clientMessage, clientTag)
    plaintext = plaintext.decode('utf-8')

    # Verify authentic
    try:
        clientCipher.verify(clientTag)
        print("The message is authentic:", plaintext)

        # Capitalize the sentence
        plaintextUpper = plaintext.upper()

        print("\nAlterating client message to UpperCase:",plaintextUpper,"\n")

        # Encrypt plaintextUpper with AES

        cipher = AES.new(clientKey, AES.MODE_SIV, nonce=clientNonce)

        ciphertext, tag = cipher.encrypt_and_digest(plaintextUpper.encode('utf-8'))

        # Send the AES plaintextUpper tag to client
        print('Sending AES message TAG from new message to client')
        print(tag,"\n")
        connectionSocket.send(tag)

        # Send the AES plaintextUpper to client
        print('Sending AES new message to client')
        print(ciphertext,"\n")
        connectionSocket.send(ciphertext)
    except ValueError:
        print("Key incorrect or message corrupted")

    print("*******************************")
    # Close the connection socket
    connectionSocket.close()