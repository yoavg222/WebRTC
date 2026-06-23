from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import  default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding


PRIVATE_KEY_PATH = "private_key.pem"
PUBLIC_KEY_PATH = "public_key.pem"
PASSWORD = b"mypassword"

class RSA:
    def __init__(self):
        if not self.load_keys():
            self.private_key = rsa.generate_private_key(
                public_exponent= 65537,
                key_size=2048
            )
            self.public_key = self.private_key.public_key()
            self.serialize_private_key()




    def serialize_private_key(self):
        pem_private = self.private_key.private_bytes(
            encoding= serialization.Encoding.PEM,
            format = serialization.PrivateFormat.PKCS8,
            encryption_algorithm= serialization.BestAvailableEncryption(PASSWORD)
        )
        with open(PRIVATE_KEY_PATH,"wb") as file:
            file.write(pem_private)


    def serialize_public_key(self):
        pem_public = self.public_key.public_bytes(
            encoding= serialization.Encoding.PEM,
            format = serialization.PublicFormat.SubjectPublicKeyInfo
        )
        with open(PUBLIC_KEY_PATH,"wb") as file:
            file.write(pem_public)



    def load_keys(self):
        try:
            with open(PRIVATE_KEY_PATH, "rb") as key_file:
                self.private_key = serialization.load_pem_private_key(
                    key_file.read(),
                    password=PASSWORD,
                    backend=default_backend()
                )
            with open(PUBLIC_KEY_PATH, "rb") as key_file:
                self.public_key = serialization.load_pem_public_key(
                    key_file.read(),
                    backend=default_backend()
                )
            return True

        except:
            return False



    def public_key_to_send(self):
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo)


    def decrypt_message_rsa(self,encrypted_message):
        try:
            aes_key = self.private_key.decrypt(
                encrypted_message,padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            return aes_key

        except ValueError:
            return None