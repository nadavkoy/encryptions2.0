import socket
from AES import *
from KeyGenerator import *
import pickle
import os

KEY = os.urandom(16)


class Client(object):
    """ creating client """
    def __init__(self):
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client_socket.connect(('127.0.0.1', 4500))
        self.aes = AESCrypt()
        self.rsa = Cryptonew()
        self.public = ''

    def unpack(self, data):
        return pickle.loads(data.decode('base64'))

    def pack(self, data):
        return pickle.dumps(data).encode('base64')


def send_key(client):
    """ sends encryption key with the public key """
    client.public = client.client_socket.recv(1024)  # receiving public
    client.public = client.unpack(client.public)  # unpacking
    encrypted_key = client.rsa.encrypt(KEY, client.public)  # encrypting key with public
    client.client_socket.send(encrypted_key)  # sending key
    response = client.client_socket.recv(1024)  # receiving server's confirmation
    print response


def send_encrypted_request(client, request):
    """ sends encrypted message and receives the response"""
    encrypted_message = client.aes.encryptAES(KEY, request)
    client.client_socket.send(encrypted_message)
    response = client.client_socket.recv(1024)
    response = client.aes.decryptAES(KEY, response)
    return response


def main():
    client = Client()
    send_key(client)
    while True:
        name = raw_input()
        server_response = send_encrypted_request(client, name)
        print server_response


if __name__ == '__main__':
    main()