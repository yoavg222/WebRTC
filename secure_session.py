from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os


class SecureSession_AES:
    def __init__(self,key):
        self.aes_key = AESGCM(key)


    def encrypt(self,plaintext):
        nonce = os.urandom(12)
        ciphertext = self.aes_key.encrypt(nonce,plaintext,None)
        return nonce + ciphertext


    def decrypt(self,data):
        nonce = data[:12]
        ciphertext = data[12:]
        return self.aes_key.decrypt(nonce,ciphertext,None)