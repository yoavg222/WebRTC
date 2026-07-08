import warnings
warnings.filterwarnings("ignore", category=UserWarning, module="aiootp")


from aiootp import X25519
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import x25519

from constant import group_x25519,TLS_AES_128_GCM_SHA256



class ECDH:

    def __init__(self):
        self.my_key = X25519().generate()
        self.shared_key = None
        self.client_handshake_key = None
        self.client_handshake_iv = None
        self.client_record_number_key = None
        self.server_handshake_key = None
        self.server_handshake_iv = None
        self.server_record_number_key = None


    def shared_key_calculate(self,peer_key,group):

        if group == group_x25519:
            peer_pub_key_obj = x25519.X25519PublicKey.from_public_bytes(peer_key)
            self.shared_key = self.my_key.exchange(peer_pub_key_obj)
        else:
            pass



    def derived_key_func(self,cipher_suits):
        if cipher_suits == TLS_AES_128_GCM_SHA256:
            length = 16
            algorithm_sha = hashes.SHA256()
        else:
            algorithm_sha = hashes.SHA384()
            length = 32

        self.client_handshake_key = HKDF(
            algorithm=algorithm_sha, length=length, salt=None, info=b"client handshake key"
        ).derive(self.shared_key)

        self.client_handshake_iv = HKDF(
            algorithm=algorithm_sha, length=12, salt=None, info=b"client handshake iv"
        ).derive(self.shared_key)

        self.client_record_number_key = HKDF(
            algorithm=algorithm_sha, length=16, salt=None, info=b"client record number key"
        ).derive(self.shared_key)


        self.server_handshake_key = HKDF(
            algorithm=algorithm_sha, length=length, salt=None, info=b"server handshake key"
        ).derive(self.shared_key)

        self.server_handshake_iv = HKDF(
            algorithm=algorithm_sha, length=12, salt=None, info=b"server handshake iv"
        ).derive(self.shared_key)

        self.server_record_number_key = HKDF(
            algorithm=algorithm_sha, length=16, salt=None, info=b"server record number key"
        ).derive(self.shared_key)

        return self.client_handshake_key,self.client_handshake_iv,self.client_record_number_key,self.server_handshake_key,self.server_handshake_iv,self.server_record_number_key




    def public_key(self):

        public_key_obj = self.my_key.public_key

        return public_key_obj.public_bytes(
            encoding = serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
