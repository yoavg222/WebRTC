import warnings
warnings.filterwarnings("ignore", category=UserWarning, module="aiootp")


from aiootp import X25519
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import x25519




class ECDH:

    def __init__(self):
        self.my_key = X25519().generate()
        self.shared_key = None

    def shared_key_calculate(self,peer_key):

        peer_public_key = peer_key.public_bytes

        peer_pub_key_obj = x25519.X25519PublicKey.from_public_bytes(peer_public_key)
        self.shared_key = self.my_key.exchange(peer_pub_key_obj)

    def derived_key(self):

        return HKDF(
            algorithm=hashes.SHA256(),
            length = 32,
            salt = None,
            info = b"handshake data"

        ).derive(self.shared_key)

    def public_key(self):

        public_key_obj = self.my_key.public_key

        return public_key_obj.public_bytes(
            encoding = serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )