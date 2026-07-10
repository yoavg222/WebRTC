import datetime

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import  default_backend
from constant import PATH_STORE_PRIVATE_KEY,PATH_TO_STORE_CERTIFICATE,PATH_STORE_PUBLIC_KEY


class BuildCertificate:

    def __init__(self):
        if not self.load_from_disk_key():
            self.private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048
            )

            with open(PATH_STORE_PRIVATE_KEY,"wb") as f:
                f.write(self.private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format = serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.BestAvailableEncryption(b"passphrase")
                ))

            self.public_key = self.private_key.public_key()
            with open(PATH_STORE_PUBLIC_KEY,"wb") as f:
                f.write(self.public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format = serialization.PublicFormat.SubjectPublicKeyInfo,
                ))

        else:
            pass

        if not self.load_from_disk_certificate():
            self.subject = self.issuer = x509.Name([
                x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "California"),
                x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "My Company"),
                x509.NameAttribute(NameOID.COMMON_NAME, "mysite.com"),
            ])

            self.certificate = x509.CertificateBuilder().subject_name(
                self.subject
            ).issuer_name(
                self.issuer
            ).public_key(
                self.public_key
            ).serial_number(
                x509.random_serial_number()
            ).not_valid_before(
                datetime.datetime.now(datetime.timezone.utc)
            ).not_valid_after(
                datetime.datetime.now(
                    datetime.timezone.utc) + datetime.timedelta(days=365)
                ).add_extension(
                x509.SubjectAlternativeName([x509.DNSName("localhost")]),critical=False
            ).sign(self.private_key,hashes.SHA256())

            with open (PATH_TO_STORE_CERTIFICATE,"wb") as f:
                f.write(self.certificate.public_bytes(serialization.Encoding.PEM))

        else:
            pass






    def load_from_disk_key(self):
        try:

            with open(PATH_STORE_PRIVATE_KEY, "rb") as key_file:
                self.private_key = serialization.load_pem_private_key(
                    key_file.read(),
                    password=b"passphrase",
                    backend=default_backend()
                )

            with open(PATH_STORE_PUBLIC_KEY,"rb") as key_file:
                self.public_key = serialization.load_pem_public_key(
                    key_file.read(),
                    backend=default_backend()
                )
            return True

        except:
            return False




    def load_from_disk_certificate(self):

        try:
            with open(PATH_TO_STORE_CERTIFICATE,"rb") as file:
                certificate_data = file.read()

            self.certificate = x509.load_pem_x509_certificate(certificate_data)
            return True

        except:
            return False



    def fingerprint(self):
        return self.certificate.fingerprint(hashes.SHA256()),"sha-256"



    def to_der(self):
        return self.certificate.public_bytes(serialization.Encoding.DER)



    def get_private_key(self):
        return self.private_key