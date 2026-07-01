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

signature_algorithms_client = []

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
key_exchange_ecdh = [b"\x00\x1d"]
no_crime = b"\x01\x00"
cipher_suite_data = b"\x00\x06"
legacy_session_id = b"\x00"
legacy_cookie = b"\x00"
server_hello_type = b"\x02"
epoch = b"\x00\x00"





client_hello_packets_if_split = {}

def support_ecdh_group(group):

    if group in key_exchange_ecdh:
        return True
    return False


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


def message_splitting_recv():
    pass



def message_splitting():
    pass




def server_hello_parsing():
    pass



def header_parsing(packet):

    dtls_record_type = packet[0]

    dtls_protocol_version = struct.unpack(">H", packet[1:3])[0]
    dtls_protocol_version = dtls_protocol_version.to_bytes(2,byteorder="big")

    epoch_packet = struct.unpack(">H",packet[3:5])[0]
    sequence_number = struct.unpack(">6s",packet[5:11])[0]
    length = struct.unpack(">H",packet[11:13])[0]

    return dtls_record_type,dtls_protocol_version,epoch_packet,sequence_number,length




def tls_handshake_header_parsing(packet):

    record_type = packet[0]
    length_in_record = struct.unpack(">3s",packet[1:4])[0]

    return record_type,length_in_record



def client_hello_record_parsing(packet,length_in_record):
    global signature_algorithms

    data = packet[17:17+length_in_record]
    print("data: ", data.hex())
    print("packet: ",packet.hex())

    data = packet[25:25 + length_in_record]
    print("data2: ",data.hex())
    client_random = data[2:34]

    cipher_suits_length = data[36:38]
    cipher_suits_length = int.from_bytes(cipher_suits_length, byteorder="big")

    cipher_suits = data[38:38 + cipher_suits_length]
    cipher_suits_length = int(cipher_suits_length / 2)
    string_h = ">"

    for i in range(cipher_suits_length):
        string_h += "H"

    cipher_suits_lst = struct.unpack(string_h, cipher_suits)
    print(cipher_suits_lst)

    cipher_suits_in = server_pick_cipher_suits(cipher_suits_lst)
    print(cipher_suits_in)

    print( data[38 + cipher_suits_length + cipher_suits_length + 2].to_bytes(2,byteorder="big"))
    extension_length = data[38 + cipher_suits_length + cipher_suits_length + 2:38 + cipher_suits_length + cipher_suits_length + 4]
    print(extension_length.hex())
    extension_length = int.from_bytes(extension_length, byteorder="big")

    extension = data[38 + cipher_suits_length + cipher_suits_length + 4:38 + cipher_suits_length + cipher_suits_length + 4 + extension_length]
    print(extension.hex())

    client_chosen_group = extension[6:8]
    if not support_ecdh_group(client_chosen_group):
        print("the server supports this group")
        return None,None,False,None

    client_public_key = extension[10:42]
    print(client_public_key)

    extension_supported_versions = extension[42:]
    print(extension_supported_versions.hex())

    value_for_dtls = extension_supported_versions[5:7]

    if value_for_dtls != dtls_13:
        return None,None,None,None


    signature_algorithms_extension = extension_supported_versions[7:]
    print(signature_algorithms_extension.hex())

    signature_algorithms_extension_len = signature_algorithms_extension[4:6]
    signature_algorithms_extension_len = int.from_bytes(signature_algorithms_extension_len,byteorder="big")
    signature_algorithms_extension_client = signature_algorithms_extension[6:6+signature_algorithms_extension_len]
    print(signature_algorithms_extension_client.hex())

    string_h = ">"
    for i in range (int(signature_algorithms_extension_len/2)):
        string_h += "H"

    signature_algorithms_extension_client = struct.unpack(string_h,signature_algorithms_extension_client)

    for algorithm in signature_algorithms_extension_client:
        signature_algorithms_client.append(algorithm.to_bytes(2,byteorder="big"))




    return client_random,cipher_suits_in,client_chosen_group,client_public_key






def client_hello_parsing(client_hello_packet):

    dtls_record_type, dtls_protocol_version, epoch_packet, sequence_number, length = header_parsing(client_hello_packet)
    print("dtls_record_type: ",dtls_record_type," dtls_protocol_version: ",dtls_protocol_version," epoch_packet: ",epoch_packet," sequence_number: ",sequence_number," length: ",length)

    if dtls_record_type != 22:
        print("this packet is not Handshake packet")
        return None,None,None,None

    if dtls_protocol_version != version:
        print("this packet is not in the good version")
        return None,None,None,None



    record = client_hello_packet[13:length]
    record_type,length_in_record = tls_handshake_header_parsing(record)
    length_in_record = int.from_bytes(length_in_record,byteorder="big")

    print("record_type: ",record_type," length_in_record: ",length_in_record)



    if length_in_record > 1200:
        message_splitting_recv()
    else:
        client_random,cipher_suits_in,client_chosen_group,public_key_client = client_hello_record_parsing(client_hello_packet,length_in_record)
        return client_random,cipher_suits_in,client_chosen_group,public_key_client


    return True



def server_hello(sequence_number,server_random,cipher_suite,handshake_msg):
    server_hello_packet = b""
    msg_lst = []

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

    msg_lst.append(server_hello_packet)
    print(server_hello_packet.hex())
    return msg_lst,server_ecdh,sequence_number





def client_hello(sequence_number,client_random,handshake_msg):
    msg_lst = []

    sequence_number_bytes = handshake_message_sequence_number_func(sequence_number)
    handshake_message_sequence_number = handshake_msg.to_bytes(2,byteorder="big")

    client_hello_packet = b""
    is_finish = False

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
    print(len(client_hello_packet))

    length_of_following_data_in_this_record = len(client_hello_packet).to_bytes(2,byteorder="big")

    client_hello_packet = dtls_record_header(sequence_number_bytes,length_of_following_data_in_this_record) + client_hello_packet
    msg_lst.append(client_hello_packet)



    print(client_hello_packet.hex())
    return ecdh_client,msg_lst





if __name__ == "__main__":
    random_num = random.randbytes(32)
    print(random_num)
    b,c = client_hello(0,random_num,0)
    server_hello(0,random.randbytes(32),b"\x13\x01",0)
    y,z = client_hello(0,random_num,0)
    client_hello_parsing(z[0])