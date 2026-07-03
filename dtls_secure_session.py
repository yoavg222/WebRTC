from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes



class DTLS13_SecureSession:
    def __init__(self,traffic_key, traffic_iv, sn_key):
        self.aes_gcm = AESGCM(traffic_key)
        self.traffic_iv = traffic_iv
        self.sn_cipher = Cipher(algorithms.AES(sn_key),modes.ECB())
        # self.sn_cipher = sn_key

    def generate_nonce(self,seq_bytes):
        padded_seq = b"\x00" * (12 - len(seq_bytes)) + seq_bytes
        return bytes(a^b for a,b in zip(self.traffic_iv,padded_seq))


    def mask_on_header(self,mask,header_info,seq_num_bytes):

        mask_to_xor = mask[0]
        header_info = int.from_bytes(header_info,byteorder="big")

        mask_to_xor = int.from_bytes(mask[1:3],byteorder="big")
        seq_num_int = int.from_bytes(seq_num_bytes,byteorder="big")
        seq_num = seq_num_int ^ mask_to_xor

        return header_info,seq_num


    def encrypt_and_mask(self,seq_num,is_server,plain_text):
        handshake_key = b""
        record_number_key = b""

        header_info = b"\x2e"

        if is_server:
            handshake_key = self.aes_gcm
            record_number_key =  self.sn_cipher

        else:
            handshake_key = self.aes_gcm
            record_number_key =  self.sn_cipher

        seq_num_bytes = seq_num.to_bytes(2,byteorder="big")
        nonce = self.generate_nonce(seq_num_bytes)

        header = header_info + seq_num_bytes

        cipher_text = handshake_key.encrypt(nonce,plain_text,header)
        sample = cipher_text[5:21]

        encryptor = record_number_key.encryptor()
        mask_part_1 = encryptor.update(sample)
        mask_part_2 = encryptor.finalize()

        mask = mask_part_1 + mask_part_2

        header_info,seq_num_bytes = self.mask_on_header(mask,header_info,seq_num_bytes)

        full_packet = header_info.to_bytes(1) + seq_num_bytes.to_bytes(2,byteorder="big") + cipher_text
        print(full_packet)

        return full_packet



    def decrypt_and_mask(self,packet):
        pass


