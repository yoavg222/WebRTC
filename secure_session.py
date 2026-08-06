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




class SecureSessionSRTP:
    def __init__(self,key1,key2):

        self.key_decrypt = AESGCM(key1)
        self.key_encrypt = AESGCM(key2)

    def encrypt(self, plaintext):
        nonce = os.urandom(12)
        ciphertext = self.key_encrypt.encrypt(nonce, plaintext, None)
        return nonce + ciphertext


    def decrypt(self, data):
        nonce = data[:12]
        ciphertext = data[12:]
        return self.key_decrypt.decrypt(nonce, ciphertext, None)

