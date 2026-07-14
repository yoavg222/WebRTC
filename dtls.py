import struct
import hmac
import hashlib


from ECDH_class import ECDH
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding


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

supported_groups = [
    0x001d,
    0x0017,
    0x0018,
    0x0019,
    0x0100
]



signature_algorithms_server = [
    b'\x08\x04',
    b'\x08\x06',
    b'\x08\x0b',
    b'\x08\x05',
    b'\x08\x0a',
    b'\x08\x09',
    b'\x06\x03',
    b'\x05\x03'
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
epoch_after_encrypt = b"\x00\x01"
supported_groups_value = b"\x00\x0a"
encrypted_extensions_type = b"\x08"
header_info = b"\x2e"
handshake_message_sequence_number_certificate = b"\x00\x02"
handshake_message_type_certificate = b"\x0b"
handshake_msg_seq_cert_verify = b"\x00\x03"
handshake_msg_type_cert_verify = b"\x0f"
handshake_msg_seq_finished = b"\x00\x04"
finished_type = b"\x14"

server_hello_coming = False





def select_signature_algorithms(signature_algorithms_lst):

    for algorithm in signature_algorithms_server:
        if algorithm in signature_algorithms_lst:
            return algorithm

    return None


def support_ecdh_group(group):

    if group in key_exchange_ecdh:
        return True
    return False


def extension_key_share_func(public_key):
    return key_share + b"\x00\x26" + b"\x00\x24" + b"\x00\x1d" + b"\x00\x20" + public_key


def extension_key_share_func_server(public_key):
    return key_share + b"\x00\x24" + b"\x00\x1d" + b"\x00\x20" + public_key


def handshake_message_sequence_number_func(handshake_message_sequence_number):
    return handshake_message_sequence_number.to_bytes(6,byteorder="big")


def dtls_record_header(sequence_number,length,epoch_param):
    return handshake_type + version + epoch_param + sequence_number + length



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


def full_record_recv():
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
    fragment_length = struct.unpack(">3s",packet[9:12])[0]
    fragment_offset = struct.unpack(">3s",packet[6:9])[0]

    return record_type,length_in_record,fragment_length,fragment_offset



def client_hello_record_parsing(packet,length_in_record):

    data = packet[25:25 + length_in_record]
    client_random = data[2:34]

    cipher_suits_length = data[36:38]
    cipher_suits_length = int.from_bytes(cipher_suits_length, byteorder="big")

    cipher_suits = data[38:38 + cipher_suits_length]
    cipher_suits_length = int(cipher_suits_length / 2)
    string_h = ">"

    for i in range(cipher_suits_length):
        string_h += "H"

    cipher_suits_lst = struct.unpack(string_h, cipher_suits)


    cipher_suits_in = server_pick_cipher_suits(cipher_suits_lst)

    extension_length = data[38 + cipher_suits_length + cipher_suits_length + 2:38 + cipher_suits_length + cipher_suits_length + 4]
    extension_length = int.from_bytes(extension_length, byteorder="big")

    extension = data[38 + cipher_suits_length + cipher_suits_length + 4:38 + cipher_suits_length + cipher_suits_length + 4 + extension_length]


    client_chosen_group = extension[6:8]
    if not support_ecdh_group(client_chosen_group):
        print("the server supports this group")
        return None,None,False,None

    client_public_key = extension[10:42]
    extension_supported_versions = extension[42:]

    value_for_dtls = extension_supported_versions[5:7]

    if value_for_dtls != dtls_13:
        return None,None,None,None


    signature_algorithms_extension = extension_supported_versions[7:]


    signature_algorithms_extension_len = signature_algorithms_extension[4:6]
    signature_algorithms_extension_len = int.from_bytes(signature_algorithms_extension_len,byteorder="big")
    signature_algorithms_extension_client = signature_algorithms_extension[6:6+signature_algorithms_extension_len]


    string_h = ">"
    for i in range (int(signature_algorithms_extension_len/2)):
        string_h += "H"

    signature_algorithms_extension_client = struct.unpack(string_h,signature_algorithms_extension_client)

    for algorithm in signature_algorithms_extension_client:
        signature_algorithms_client.append(algorithm.to_bytes(2,byteorder="big"))




    return client_random,cipher_suits_in,client_chosen_group,client_public_key,signature_algorithms_client




def server_hello_record_parsing(packet,length_in_record):

    data = packet[25:25+length_in_record]

    server_version = data[0:2]

    if server_version != version:
        return None,None,None,None

    server_random = data[2:34]
    cipher_suite = data[35:37]

    extension_length = data[38:40]
    extension_length = int.from_bytes(extension_length,byteorder="big")

    last_extension = data[40: 40+extension_length]

    key_share_length = last_extension[2:4]
    key_share_length = int.from_bytes(key_share_length,byteorder="big")
    key_share_extension = last_extension[4:4+key_share_length]

    server_group = key_share_extension[0:2]
    public_key_length = key_share_extension[2:4]
    public_key_length = int.from_bytes(public_key_length,byteorder="big")
    server_public_key = key_share_extension[4:4+public_key_length]

    extension_supported_versions = last_extension[-2:]
    if extension_supported_versions != dtls_13:
        return None,None,None,None


    return server_random,cipher_suite,server_group,server_public_key




def client_hello_parsing(client_hello_packet):

    dtls_record_type, dtls_protocol_version, epoch_packet, sequence_number, length = header_parsing(client_hello_packet)
    print("dtls_record_type: ",dtls_record_type," dtls_protocol_version: ",dtls_protocol_version," epoch_packet: ",epoch_packet," sequence_number: ",sequence_number," length: ",length)

    if dtls_record_type != 22:
        print("this packet is not Handshake packet")
        return None,None,None,None,None

    if dtls_protocol_version != version:
        print("this packet is not in the good version")
        return None,None,None,None,None



    record = client_hello_packet[13:length]
    record_type,length_in_record,fragment_length,fragment_offset = tls_handshake_header_parsing(record)
    length_in_record = int.from_bytes(length_in_record,byteorder="big")
    fragment_length = int.from_bytes(fragment_length,byteorder="big")
    fragment_offset = int.from_bytes(fragment_offset,byteorder="big")

    print("record_type: ",record_type," length_in_record: ",length_in_record)



    if length_in_record > fragment_length or fragment_offset > 0:
        message_splitting()
    else:
        client_random,cipher_suits_in,client_chosen_group,public_key_client,signature_algorithms_client_lst = client_hello_record_parsing(client_hello_packet,fragment_length)
        return client_random,cipher_suits_in,client_chosen_group,public_key_client,signature_algorithms_client_lst


    return None,None,None,None,None



def server_hello_parsing(server_hello_packet):

    dtls_record_type, dtls_protocol_version, epoch_packet, sequence_number, length = header_parsing(server_hello_packet)
    print("dtls_record_type: ", dtls_record_type, " dtls_protocol_version: ", dtls_protocol_version, " epoch_packet: ",epoch_packet, " sequence_number: ", sequence_number, " length: ", length)

    if dtls_record_type != 22:
        print("this packet is not Handshake packet")
        return None,None,None,None

    if dtls_protocol_version != version:
        print("this packet is not in the good version")
        return None,None,None,None

    record = server_hello_packet[13:length]
    record_type,length_in_record,fragment_length,fragment_offset = tls_handshake_header_parsing(record)
    length_in_record = int.from_bytes(length_in_record,byteorder="big")
    fragment_length = int.from_bytes(fragment_length,byteorder="big")
    fragment_offset = int.from_bytes(fragment_offset,byteorder="big")

    print("record_type: ",record_type," length_in_record: ",length_in_record)



    if length_in_record > fragment_length or fragment_offset > 0:
        message_splitting()
    else:
        server_random,cipher_suits_in,server_chosen_group,public_key_server = server_hello_record_parsing(server_hello_packet,fragment_length)
        print("server hello: " ,server_random," ",cipher_suits_in," ",server_chosen_group," ",public_key_server)
        return server_random,cipher_suits_in,server_chosen_group,public_key_server


    return None,None,None,None



def server_hello(sequence_number,server_random,cipher_suite,handshake_msg):
    server_hello_packet = b""
    msg_lst = []

    sequence_number_bytes = handshake_message_sequence_number_func(sequence_number)
    handshake_message_sequence_number = handshake_msg.to_bytes(2,byteorder="big")


    server_hello_packet = supported_versions_server + server_hello_packet

    server_ecdh = ECDH()
    extension_key_share = extension_key_share_func_server(server_ecdh.public_key())
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



    server_hello_packet = server_hello_type + fragment_length + server_hello_packet
    server_hello_packet = dtls_record_header(sequence_number_bytes,len(server_hello_packet).to_bytes(2,byteorder="big"),epoch) + server_hello_packet

    msg_lst.append(server_hello_packet)
    return msg_lst,server_ecdh,sequence_number + 1




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

    length_of_following_data_in_this_record = len(client_hello_packet).to_bytes(2,byteorder="big")

    client_hello_packet = dtls_record_header(sequence_number_bytes,length_of_following_data_in_this_record,epoch) + client_hello_packet
    msg_lst.append(client_hello_packet)


    return ecdh_client,msg_lst





def server_encrypted_extensions_seq_num(packet):
    print("packet in server_encrypted_extensions_seq_num: ",packet.hex())
    return int.from_bytes(packet[1:3],byteorder="big")



def server_encrypted_extensions(seq_num,handshake_msg):

    encrypted_extensions_packet = b""

    for i in supported_groups:
        data = struct.pack("!H",i)
        encrypted_extensions_packet += data

    handshake_message_sequence_number = handshake_msg.to_bytes(2, byteorder="big")

    bytes_in_curves_list = len(supported_groups) * 2
    bytes_in_curves_list = bytes_in_curves_list.to_bytes(2,byteorder="big")

    bytes_of_supported_group_extension = len(supported_groups) * 2 + len(bytes_in_curves_list)
    bytes_of_supported_group_extension = bytes_of_supported_group_extension.to_bytes(2,byteorder="big")

    encrypted_extensions_packet = supported_groups_value + bytes_of_supported_group_extension +bytes_in_curves_list + encrypted_extensions_packet

    extension_length = len(encrypted_extensions_packet)
    print("extension_length: ",extension_length)

    extension_length = extension_length.to_bytes(2,byteorder="big")

    encrypted_extensions_packet = extension_length + encrypted_extensions_packet

    fragment_length = len(encrypted_extensions_packet)

    if fragment_length > 1200:
        message_splitting()
        return True


    else:
        fragment_length = fragment_length.to_bytes(3,byteorder="big")
        fragment_offset = b"\x00\x00\x00"
        bytes_of_handshake_message = fragment_length

        encrypted_extensions_packet = encrypted_extensions_type + bytes_of_handshake_message + handshake_message_sequence_number + fragment_offset + fragment_length + encrypted_extensions_packet
        encrypted_extensions_packet += handshake_type
        print("encrypted_extensions_packet: ",encrypted_extensions_packet.hex())

        return [encrypted_extensions_packet],seq_num + 1,seq_num + 1





def server_encrypted_extensions_parsing(packet):

    if packet[-1:] != handshake_type:
        print("something get wrong at server_encrypted_extensions_parsing")
        return None


    length_data = packet[1:4]
    length_data_int = int.from_bytes(length_data,byteorder="big")

    handshake_header = packet[4:12]
    fragment_length = packet[5:8]
    fragment_length_int = int.from_bytes(fragment_length,byteorder="big")

    data = packet[12:12+fragment_length_int]

    extensions_length = data[:2]
    extensions_length_int = int.from_bytes(extensions_length,byteorder="big")

    supported_groups_extension = data[2:2+extensions_length_int]
    print("supported_groups_extension: ",supported_groups_extension.hex())

    length_curve_length = supported_groups_extension[4:6]
    length_curve_length_int = int.from_bytes(length_curve_length,byteorder = "big")

    curve_lst = supported_groups_extension[6:6+length_curve_length_int]

    string_h = ">"
    supported_groups_lst = []

    for i in range(int(length_curve_length_int/2)):
        string_h += "H"


    tuple_supported_group = struct.unpack(string_h,curve_lst)

    for group in tuple_supported_group:
        group = group.to_bytes(2,byteorder="big")
        supported_groups_lst.append(group)

    return supported_groups_lst



def add_header_to_server_encrypted_packets(packet,header_info_input,record_number):

    record_length = len(packet)
    record_length_bytes = record_length.to_bytes(2,byteorder="big")

    # header_info_bytes = header_info.to_bytes(1,byteorder="big")
    record_number_bytes = record_number.to_bytes(2,byteorder="big")

    return header_info_input + record_number_bytes + record_length_bytes + packet





def unit_records(lst_record_1,lst_record_2):
    print(lst_record_1[0].hex())
    print(lst_record_2[0].hex())

    final_packet = b""


    if len(lst_record_1) > 1:
        print("this packet underwent fragmentation meaning its length exceeds the permitted limit.")
        return False,None


    else:
        final_packet += lst_record_1[0]


    if len(lst_record_2) > 1:
        print("this packet underwent fragmentation meaning its length exceeds the permitted limit.")
        return False,None


    else:
        final_packet += lst_record_2[0]

        if len(final_packet) > 1300:
            print("the unified package is too large.")
            return False,None

        else:
            print(final_packet.hex())
            return True,final_packet



def int_to_bytes(length,num_of_bytes,byteorder_input):

    return length.to_bytes(num_of_bytes,byteorder=byteorder_input)





def certificate(seq_num,certificate_der):

    certificate_packet = b""
    request_context = b"\x00"
    certificate_extensions = b"\x00\x00"


    certificate_packet = certificate_extensions + certificate_packet


    print("the_certificate in certificate: ",certificate_der.hex())

    certificate_packet = certificate_der + certificate_packet

    certificate_length = len(certificate_packet)
    certificate_length = int_to_bytes(certificate_length,3,"big")

    certificate_packet = certificate_length + certificate_packet

    certificate_length = len(certificate_packet)
    certificate_length = int_to_bytes(certificate_length,3,"big")

    certificate_packet = certificate_length + certificate_packet
    certificate_packet = request_context + certificate_packet

    fragment_length = len(certificate_packet)


    if fragment_length > 1200:
        message_splitting()

    else:
        fragment_length = int_to_bytes(fragment_length, 3, "big")
        fragment_offset = b"\x00\x00\x00"
        certificate_packet = handshake_message_sequence_number_certificate + fragment_offset + fragment_length + certificate_packet
        length_data = len(certificate_packet)
        length_data = int_to_bytes(length_data,3,"big")

        handshake_header = handshake_message_type_certificate + length_data
        certificate_packet = handshake_header + certificate_packet
        certificate_packet = certificate_packet + handshake_type

        return [certificate_packet],seq_num + 1,seq_num + 1




def certificate_parsing(packet):
    handshake_reconstruction_data = packet[4:12]
    fragment_length =  handshake_reconstruction_data[5:8]
    fragment_length = int.from_bytes(fragment_length,byteorder="big")

    data = packet[12:12+fragment_length]
    print(data)

    certificates_length = data[1:4]
    certificates_length = int.from_bytes(certificates_length,byteorder="big")

    certificates_data = data[4:4+certificates_length]

    bytes_of_certificate = certificates_data[0:3]
    bytes_of_certificate = int.from_bytes(bytes_of_certificate,byteorder="big")

    the_certificate = certificates_data[3:1 + bytes_of_certificate]
    print("the_certificate in certificate_parsing: ",the_certificate.hex())

    return the_certificate



#need to finish here the else logic
def check_if_full_packet(packet_lst):

    if len(packet_lst) == 1:
        return True,None
    else:
        return False,packet_lst




def remove_header(packet):

    msg_type = packet[0]
    msg_type = int_to_bytes(msg_type,1,"big")

    if msg_type == handshake_type or msg_type == handshake_type:
        packet_to_return = packet[25:]
        return packet_to_return

    else:
        packet_to_return = packet[12:]
        return packet_to_return




def signature_func(algorithm,packet,certificate_object):

    if algorithm == "RSA_PSS_RSAE_SHA256":


        private_key = certificate_object.get_private_key()

        signature = private_key.sign(
            packet,
            padding.PSS(mgf = padding.MGF1(hashes.SHA256()),
            salt_length = padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )

        print("signature: ",signature.hex())

        return signature

    else:
        return None






def certificate_verify(handshake_packets,signature,certificate_object,seq_num):


    client_hello_packet = handshake_packets["client_hello"]
    server_hello_packet = handshake_packets["server_hello"]
    server_encrypted_extensions_packet = handshake_packets["server_encrypted_extension"]
    server_certificate_packet = handshake_packets["server_certificate"]

    print("client_hello_packet in certificate_verify: ",client_hello_packet.hex())
    print("server_hello_packet in certificate_verify: ",server_hello_packet.hex())
    print("server_encrypted_extensions_packet in certificate_verify: ",server_encrypted_extensions_packet.hex())
    print("server_certificate_packet in certificate_verify: ",server_certificate_packet.hex())



    final_packet = client_hello_packet + server_hello_packet + server_encrypted_extensions_packet + server_certificate_packet
    print("final_packet in certificate_verify: ",final_packet.hex())

    if signature == b'\x08\x04':
        value = "RSA_PSS_RSAE_SHA256"

        signature_packet = signature_func(value,final_packet,certificate_object)

        length_signature = len(signature_packet)
        length_signature_bytes = length_signature.to_bytes(2,byteorder="big")
        value_signature = b'\x08\x04'

        packet_to_return = value_signature + length_signature_bytes + signature_packet

        fragment_length = len(packet_to_return)
        if fragment_length > 1200:
            message_splitting()

        else:
            fragment_length_bytes = fragment_length.to_bytes(3,byteorder="big")
            fragment_offset = b"\x00\x00\x00"

            packet_to_return = handshake_msg_seq_cert_verify + fragment_offset + fragment_length_bytes + packet_to_return

            packet_to_return = handshake_msg_type_cert_verify + fragment_length_bytes + packet_to_return + handshake_type

            return [packet_to_return],seq_num + 1,seq_num + 1


    else:
        return None,None,None




def extract_signature_cert_verify(packet):

    length = packet[9:12]
    length = int.from_bytes(length,byteorder="big")

    signature_value = struct.unpack(">H",packet[12:14])[0]
    data = packet[16:12+length]

    return data,signature_value




def hmac_sha256(sha_data,finished_key):
    return hmac.new(
        finished_key,
        sha_data,
        hashlib.sha256
    ).digest()



def handshake_finished(verify_data,seq_num):



    fragment_length = len(verify_data)

    if fragment_length > 1200:
        message_splitting()


    else:

        fragment_length_bytes = fragment_length.to_bytes(3,byteorder="big")
        fragment_offset = b"\x00\x00\x00"

        handshake_finished_packet = handshake_msg_seq_finished + fragment_offset + fragment_length_bytes
        handshake_finished_packet = finished_type + fragment_length_bytes + handshake_finished_packet

        handshake_finished_packet = handshake_finished_packet + verify_data + handshake_type

        return [handshake_finished_packet],seq_num + 1,seq_num + 1








def handshake_finish_parsing(packet):

    data_length = packet[1:4]
    fragment_length = packet[9:12]

    if fragment_length != data_length:
        print("poor handling of full_packet_recv()")
        return None,False


    fragment_length_int = int.from_bytes(fragment_length,byteorder="big")
    verify_data = packet[12:12+fragment_length_int]

    return verify_data














if __name__ == "__main__":
    # random_num = random.randbytes(32)
    # print(random_num)
    # b,c = client_hello(0,random_num,0)
    # # server_hello(0,random.randbytes(32),b"\x13\x01",0)
    # y,z = client_hello(0,random_num,0)
    # client_hello_parsing(z[0])
    #
    # g,h,s = server_hello(0,random.randbytes(32),b"\x13\x01",0)
    # server_hello_parsing(g[0])
    x = [b'\x16\xfe\xfd\x00\x00\x00\x00\x00\x00\x00\x00\x00b\x02\x00\x00V\x00\x00\x00\x00\x00\x00\x00V\xfe\xfd\xbdG\xce\xcf\xcc\xbeIGBGE~\x8e:=Vc\x93\xd9\xd1\x931\xc5\xb3C\xc2C\xc1h\xff\xa8h\x00\x13\x01\x00\x00.\x003\x00$\x00\x1d\x00 ,\xd9\x9f\xbd&\xa5R\x96Q\x97\xfe\x9a\x98?\xaf\x07\xe3\xba\xa9\x08\xa0Q\xdd\x82\xeb\xaf\xd5\xde\xc5\xe1\x95V\x00+\x00\x02\xfe\xfc']
    y = [b'.]\xad\x00/D\xafG\x12\n\x9f\xf7\xe7\xa1\xda\xc8 \x0b3F\x82uk\x13\xe7\xd3UN\x93\xc1\xd0\xaacKi\xea\x06ze-\xf2$\x81M\xa7\xd2\x0f\x9c\xe0\xf0\x0f\xce']
    unit_records(x,y)