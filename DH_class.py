from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from  cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

from RSA_class import RSA
from constant import PARAMETERS_PATH


class DH:


    def __init__(self):
        self.dh_parameters_pem = b"0"
        self.shared_key_server = b"0"
        self.shared_key_client = b"0"
        self.key_server = b"0"
        self.key_client = b"0"
        self.rsa_session = RSA()


    def derived_key(self,boolean_var):
        if boolean_var:
            return HKDF(
                algorithm=hashes.SHA256(),length=32,salt = None,info = b"handshake data",
            ).derive(self.shared_key_server)
        else:
            return HKDF(
                algorithm=hashes.SHA256(), length=32, salt=None, info=b"handshake data",
            ).derive(self.shared_key_client)





    def dh_key_exchange_server(self,recv_send_server):
        recv_send_server.send_with_size(self.dh_parameters_pem)

        parameters_object = serialization.load_pem_parameters(self.dh_parameters_pem)
        a_private = parameters_object.generate_private_key()

        b_public = recv_send_server.recv_by_size()
        b_public_object = serialization.load_pem_public_key(b_public)

        a_public = a_private.public_key()
        a_public_pem = a_public.public_bytes(
            encoding= serialization.Encoding.PEM,format = serialization.PublicFormat.SubjectPublicKeyInfo)

        public_key_digital_signature, rsa_public_key = self.digital_signature(a_public_pem)

        pem_public = rsa_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        recv_send_server.send_with_size(pem_public)

        to_send = public_key_digital_signature + a_public_pem
        recv_send_server.send_with_size(to_send)

        self.shared_key_server = a_private.exchange(b_public_object)
        print("shared_key_server: ",self.shared_key_server)

        self.key_server = self.derived_key(True)
        return self.key_server



    def dhp_key_exchange_client(self,recv_send_client):
        parameters_from_server = recv_send_client.recv_by_size()
        parameters_from_server_obj = serialization.load_pem_parameters(parameters_from_server)

        b_private = parameters_from_server_obj.generate_private_key()
        b_public = b_private.public_key()

        b_public_pem = b_public.public_bytes(
            encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
        recv_send_client.send_with_size(b_public_pem)

        a_rsa_public = recv_send_client.recv_by_size()
        signature_msg_public_key = recv_send_client.recv_by_size()
        signature_msg = signature_msg_public_key[:256]
        a_public = signature_msg_public_key[256:]

        authentication = self.check_digital_signature(a_rsa_public,a_public,signature_msg)

        if not authentication:
            return False,None
        a_public_object =serialization.load_pem_public_key(a_public)


        self.shared_key_client = b_private.exchange(a_public_object)
        print("shared_key_client: ",self.shared_key_client)

        self.key_client = self.derived_key(False)
        return self.key_client



    def upload_to_disk_dh(self):

        self.dh_parameters_pem = dh.generate_parameters(generator=2,key_size=2048)
        self.dh_parameters_pem = self.dh_parameters_pem.parameter_bytes(
            encoding=serialization.Encoding.PEM,format=serialization.ParameterFormat.PKCS3
        )

        with open(PARAMETERS_PATH,"wb") as f:
            f.write(self.dh_parameters_pem)

        return True




    def load_from_disk_dh(self):
        try:
            with open(PARAMETERS_PATH,"rb") as f:
                self.dh_parameters_pem = serialization.load_pem_parameters(
                    f.read()
                )
                self.dh_parameters_pem = self.dh_parameters_pem.parameter_bytes(
                    encoding=serialization.Encoding.PEM, format=serialization.ParameterFormat.PKCS3
                )
                return True
        except:
            return None


    def encrypt_with_rsa_digital_signature(self,rsa_private_key, signature):
        final_signature = rsa_private_key.sign(
            signature, padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        return final_signature


    def digital_signature(self,public_key_dh):
        rsa_private_key = self.rsa_session.private_key
        rsa_public_key = self.rsa_session.public_key
        signature = self.encrypt_with_rsa_digital_signature(rsa_private_key, public_key_dh)

        return signature, rsa_public_key


    def check_digital_signature(self,server_rsa_public_key,server_dh_public_key,signature_msg):
        public_key_rsa = serialization.load_pem_public_key(server_rsa_public_key)
        try:
            public_key_rsa.verify(
                signature_msg,
                server_dh_public_key,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()

            )
            return True

        except Exception as err:
            print(err)
            return False




    def digital_signature_public_key(self,public_key_dh):
        rsa_private_key = self.rsa_session.private_key
        rsa_public_key = self.rsa_session.public_key
        signature = self.encrypt_with_rsa_digital_signature(rsa_private_key, public_key_dh)

        return signature,rsa_public_key



