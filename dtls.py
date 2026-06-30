import struct
import random
from ECDH_class import ECDH


signature_algorithms = [
    0x000d,
    0x0020,
    0x001e,
    0x0603,
    0x0503,
    0x0403,
    0x0203,
    0x0806,
    0x080b,
    0x0805,
    0x080a,
    0x0804,
    0x0809,
    0x0601,
    0x0501,
    0x0401,
    0x0301,
    0x0201
]

cipher_suits_dic = {
    "TLS_AES_128_GCM_SHA256" : 0x1301,
    "TLS_AES_256_GCM_SHA384" : 0x1302,
    "TLS_CHACHA20_POLY1305_SHA256": 0x1303
}

supported_versions_server = b"\x00\x2b\x00\x02\xfe\xfc"
handshake_type = b"\x16"
version = b"\xfe\xfd"
client_hello_type = b"\x01"
supported_versions = b"\x00\x2b"
dtls_13 = b"\xfe\xfc"
key_share = b"\x00\x33"
key_exchange_ecdh = b"\x00\x1d"
no_crime = b"\x01\x00"
cipher_suite_data = b"\x00\x06"
legacy_session_id = b"\x00"
legacy_cookie = b"\x00"
server_hello_type = b"\x02"
epoch = b"\x00\x00"

handshake_msg = 0



client_hello_packets = {}

def extension_key_share_func(public_key):
    return key_share + b"\x00\x26" + b"\x00\x24" + b"\x00\x1d" + b"\x00\x20" + public_key


def handshake_message_sequence_number_func(handshake_message_sequence_number):
    return handshake_message_sequence_number.to_bytes(6,byteorder="big")


def dtls_record_header(sequence_number,length):
    return handshake_type + version + epoch + sequence_number + length



def is_in(cipher_suits):

    for key in cipher_suits_dic.keys():
        if struct.pack("!H",cipher_suits_dic[key]) == cipher_suits:
            print("found cipher_suits")
            return True
    return False




def server_pick_cipher_suits(cipher_suits_client):

    for cipher_suits in cipher_suits_client:
        cipher_suits = cipher_suits.to_bytes(2,byteorder="big")
        if is_in(cipher_suits):
             return cipher_suits

    return None




def message_splitting():
    pass




def server_hello_parsing():
    pass





def client_hello_parsing(client_hello_packet):

    is_full_packet = True

    dtls_record_type = client_hello_packet[0]
    if dtls_record_type != 22:
        print("this packet is not Handshake packet")
        return False

    dtls_protocol_version = struct.unpack(">H",client_hello_packet[1:3])[0]
    dtls_protocol_version = dtls_protocol_version.to_bytes(2,byteorder="big")

    if dtls_protocol_version != version:
        print("this packet is not in the good version")
        return False

    handshake_record_type = client_hello_packet[15]
    handshake_record_type= handshake_record_type.to_bytes(1,byteorder="big")

    if handshake_record_type != client_hello_type:
        print("this packet is not in the good handshake_record_type")
        return False

    handshake_record_length = client_hello_packet[16:19]
    handshake_record_length = struct.unpack(">3s",handshake_record_length)[0]
    handshake_record_length = int.from_bytes(handshake_record_length,byteorder="big")
    print(handshake_record_length)

    fragment_offset = struct.unpack(">3s",client_hello_packet[21:24])[0]
    fragment_offset = int.from_bytes(fragment_offset,byteorder="big")

    fragment_length = struct.unpack(">3s",client_hello_packet[24:27])[0]
    fragment_length = int.from_bytes(fragment_length,byteorder="big")

    sum_packet = fragment_offset + fragment_length
    if sum_packet != handshake_record_length:
        is_full_packet = False
    else:
        print("this is full packet")

    client_random = struct.unpack(">32s",client_hello_packet[29:61])[0]
    print(client_random)

    cipher_suite_client = struct.unpack(">HHHH",client_hello_packet[63:71])
    print(cipher_suite_client)
    cipher_suits_chosen = server_pick_cipher_suits(cipher_suite_client)
    print(cipher_suits_chosen)


    extension_key_share = struct.unpack(">H",client_hello_packet[81:83])[0]
    extension_key_share = extension_key_share.to_bytes(2,byteorder="big")

    if extension_key_share != key_exchange_ecdh:
        print("server not supports this version")
        return False

    client_public_key = struct.unpack(">32s",client_hello_packet[85:117])[0]
    print(client_public_key)


    return is_full_packet,client_random,client_public_key,cipher_suits_chosen









def server_hello(sequence_number,server_random,cipher_suite):
    global client_hello_packets
    server_hello_packet = b""

    sequence_number_bytes = handshake_message_sequence_number_func(sequence_number)
    handshake_message_sequence_number = handshake_msg.to_bytes(2,byteorder="big")


    server_hello_packet = supported_versions_server + server_hello_packet

    server_ecdh = ECDH()
    extension_key_share = extension_key_share_func(server_ecdh.public_key())
    server_hello_packet = extension_key_share + server_hello_packet

    extensions_length = len(server_hello_packet)
    extensions_length = extensions_length.to_bytes(2,byteorder="big")

    server_hello_packet = extensions_length + server_hello_packet
    server_hello_packet = b"\x00" + server_hello_packet

    server_hello_packet = cipher_suite + server_hello_packet
    server_hello_packet = legacy_session_id + server_hello_packet

    server_hello_packet = server_random + server_hello_packet
    server_hello_packet = version + server_hello_packet

    fragment_length = len(server_hello_packet)
    if fragment_length > 1200:
        message_splitting()
    else:
        fragment_length = fragment_length.to_bytes(3,byteorder="big")
        fragment_offset = b"\x00\x00\x00"
        server_hello_packet = handshake_message_sequence_number + fragment_offset + fragment_length + server_hello_packet

    server_hello_data = len(server_hello_packet)
    server_hello_data = server_hello_data.to_bytes(3,byteorder="big")

    server_hello_packet = server_hello_type + server_hello_data + server_hello_packet
    server_hello_packet = dtls_record_header(sequence_number_bytes,len(server_hello_packet).to_bytes(2,byteorder="big")) + server_hello_packet

    print(server_hello)
    return server_hello_packet,server_ecdh












def client_hello(sequence_number,client_random):
    global handshake_msg


    sequence_number_bytes = handshake_message_sequence_number_func(sequence_number)
    handshake_message_sequence_number = handshake_msg.to_bytes(2,byteorder="big")
    key_epoch = b"\x00\x00"

    client_hello_packet = b""

    extension_supported_groups = struct.pack("!HHHH",0x000a,0x0004,0x0002,0x001d)
    client_hello_packet = extension_supported_groups + client_hello_packet


    extension_encrypt_then_mac = struct.pack("!HH",0x0016,0x0000)
    client_hello_packet = extension_encrypt_then_mac + client_hello_packet


    extension_signature_algorithms = b""

    for value in signature_algorithms:
        extension_signature_algorithms += struct.pack("!H",value)

    client_hello_packet = extension_signature_algorithms + client_hello_packet

    extension_supported_versions = supported_versions + struct.pack("!H",0x0003) + len(dtls_13).to_bytes(1,byteorder="big") + dtls_13
    client_hello_packet =  extension_supported_versions + client_hello_packet

    ecdh_client = ECDH()

    extension_key_share = extension_key_share_func(ecdh_client.public_key())
    print("ecdh_client public_key:",ecdh_client.public_key())
    client_hello_packet = extension_key_share + client_hello_packet

    extension_length = len(client_hello_packet)
    extension_length_bytes = extension_length.to_bytes(2,byteorder="big")
    client_hello_packet = extension_length_bytes + client_hello_packet

    client_hello_packet = no_crime + client_hello_packet

    cipher_suits = b""

    for value in cipher_suits_dic.values():
        cipher_suits += struct.pack("!H",value)

    cipher_suits = cipher_suite_data + cipher_suits
    client_hello_packet = cipher_suits + client_hello_packet

    client_hello_packet = legacy_cookie + legacy_session_id + client_hello_packet
    client_hello_packet = client_random + client_hello_packet
    client_hello_packet = version + client_hello_packet

    fragment_length = len(client_hello_packet)
    if fragment_length > 1200:
        message_splitting()
    else:
        fragment_length = fragment_length.to_bytes(3,byteorder="big")
        fragment_offset = b"\x00\x00\x00"
        client_hello_packet = handshake_message_sequence_number + fragment_offset + fragment_length + client_hello_packet

    client_hello_packet = client_hello_type + fragment_length + client_hello_packet

    length_of_following_data_in_this_record = len(client_hello_packet).to_bytes(4,byteorder="big")

    client_hello_packet = dtls_record_header(sequence_number_bytes,length_of_following_data_in_this_record) + client_hello_packet




    print(client_hello_packet.hex())
    return client_hello_packet,ecdh_client





if __name__ == "__main__":
    random_num = random.randbytes(32)
    print(random_num)
    server_hello(client_hello(0,random_num),random.randbytes(32))