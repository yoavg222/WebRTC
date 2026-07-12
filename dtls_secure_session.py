from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from constant import DEMO_HEADER


class DTLS13_SecureSession:
    def __init__(self,traffic_key, traffic_iv, sn_key):
        self.aes_gcm = AESGCM(traffic_key)
        self.traffic_iv = traffic_iv
        self.sn_cipher = Cipher(algorithms.AES(sn_key),modes.ECB())
        self.header_info_const = b"\x2e"
        self.traffic_key = traffic_key


    def generate_nonce(self,seq_bytes):
        padded_seq = b"\x00" * (12 - len(seq_bytes)) + seq_bytes
        return bytes(a^b for a,b in zip(self.traffic_iv,padded_seq))


    def mask_on_header(self,mask,seq_num_bytes):

        mask_to_xor = int.from_bytes(mask[1:3],byteorder="big")
        print("mask_to_xor in mask_on_header: ",mask_to_xor)

        seq_num_int = int.from_bytes(seq_num_bytes,byteorder="big")
        print("seq_num_int: ",seq_num_int)

        seq_num = seq_num_int ^ mask_to_xor

        return seq_num



    def decrypt_mask_on_seq_num(self,seq_num,mask):
        seq_num = seq_num ^ mask
        print("decrypt_mask_on_seq_num seq_num: ",seq_num)
        return seq_num



    def encrypt_and_mask(self,seq_num,plain_text):
        header_info = b"\x2e"

        seq_num_bytes = seq_num.to_bytes(2,byteorder="big")
        nonce = self.generate_nonce(seq_num_bytes)


        cipher_text_demo = self.aes_gcm.encrypt(nonce,plain_text,DEMO_HEADER)

        record_length = len(cipher_text_demo)
        record_length_bytes = record_length.to_bytes(2,byteorder="big")

        header = header_info + seq_num_bytes + record_length_bytes



        cipher_text = self.aes_gcm.encrypt(nonce,plain_text,header)

        print("cipher text in encrypt_and_mask: ",cipher_text.hex())
        print("header in encrypt_and_mask: ",header.hex())
        print("nonce in encrypt_and_mask: ",nonce.hex())
        print("encrypt key: ",self.traffic_key)


        sample = cipher_text[5:21]
        print("sample in encrypt :",sample.hex())

        encryptor = self.sn_cipher.encryptor()
        mask_part_1 = encryptor.update(sample)
        mask_part_2 = encryptor.finalize()

        mask = mask_part_1 + mask_part_2
        print("mask in encrypt: ",mask)



        seq_num_bytes = self.mask_on_header(mask,seq_num_bytes)
        return cipher_text,header_info,seq_num_bytes





    def decrypt_and_mask(self, packet):
        seq_len = 0

        header_info = packet[0]
        sample = packet[10:26]
        print("sample in decrypt_and_mask: ",sample.hex())


        encryptor = self.sn_cipher.encryptor()
        mask_part_1 = encryptor.update(sample)
        mask_part_2 = encryptor.finalize()

        cipher_text = packet[5:]

        mask = mask_part_1 + mask_part_2
        print("mask in decrypt: ",mask.hex())

        if header_info.to_bytes(1, byteorder="big") == self.header_info_const:
            print("good decrypt_mask_on_header")
            seq_len = 2

        else:
            print("not good decrypt_mask_on_header")

        seq_number = int.from_bytes(packet[1:1 + seq_len], byteorder="big")
        mask_to_seq_num = int.from_bytes(mask[1:3], byteorder="big")

        seq_number = self.decrypt_mask_on_seq_num(seq_number, mask_to_seq_num)
        seq_number_bytes = seq_number.to_bytes(2, byteorder="big")

        length = len(packet) - 5
        length_bytes = length.to_bytes(2, byteorder="big")

        header = header_info.to_bytes(1) + seq_number_bytes + length_bytes

        nonce = self.generate_nonce(seq_number_bytes)
        print("nonce in decrypt_and_mask: ", nonce.hex())
        print("header in decrypt_and_mask: ", header.hex())
        print("cipher_text in decrypt_and_mask: ", cipher_text.hex())
        print("key in decrypt_and_mask: ", self.traffic_key)

        try:
            plain_text = self.aes_gcm.decrypt(nonce, cipher_text, header)
            print("plain_text in decrypt_and_mask: ", plain_text.hex())

        except Exception as err:
            print("error in decrypt_and_mask")
            print(err)
            return None,None


        return plain_text, seq_number

