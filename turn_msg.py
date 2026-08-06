import struct
import os

from stun_client import generate_transaction_id
from constant import STUN_MAGIC_COOKIE

allocate_request_type = b"\x00\x03"
error_response_type = b"\x00\x09"
error_code = b"\x00\x00\x04\x01"
requested_transport_type = b"\x00\x19"
lifetime_type = b"\x00\x0d"
udp_protocol = b"\x11"
rffu = b"\x00\x00\x00"
reason_phrase = "Unauthorized".encode()
lifetime_hour = 3600
realm = "MyTurn.com".encode()
realm_type = b"\x00\x14"
nonce_type = b"\x00\x15"


def build_channel_data():
    pass



def parsing_channel_data():
    pass




def padding(input_var):

    to_add = 16 - len(input_var)
    add = b""

    for i in range(to_add):
        add += b"\x00"

    return input_var + add



def build_allocate_response_error(transaction_id):

    magic_cookie = STUN_MAGIC_COOKIE

    transaction_id_pack = struct.pack("!12s",transaction_id)
    magic_cookie_pack = struct.pack("!I",magic_cookie)


    error_code_pack = error_code + padding(reason_phrase)
    error_code_pack_len = len(error_code_pack).to_bytes(2,byteorder="big")
    error_code_pack = error_response_type + error_code_pack_len + error_code_pack

    realm_packet = padding(realm)
    realm_packet_len = len(realm_packet).to_bytes(2,byteorder="big")
    realm_packet = realm_type + realm_packet_len + realm_packet

    nonce = os.urandom(32)
    print("nonce: ",nonce)


    len_nonce = len(nonce).to_bytes(2,byteorder="big")

    nonce_packet = nonce_type + len_nonce + nonce

    len_header = len(error_code_pack + realm_packet + nonce_packet).to_bytes(2,byteorder="big")
    packet = error_response_type + len_header + magic_cookie_pack + transaction_id_pack + error_code_pack + realm_packet + nonce_packet

    return packet,nonce



def build_allocate_msg():


    transaction_id = generate_transaction_id()
    print("build_allocate_msg transaction_id: ",transaction_id)

    magic_cookie = STUN_MAGIC_COOKIE

    transaction_id_pack = struct.pack("!12s",transaction_id)
    magic_cookie_pack = struct.pack("!I",magic_cookie)

    requested_transport = udp_protocol + rffu
    requested_transport_length = len(requested_transport)
    requested_transport_length_bytes = requested_transport_length.to_bytes(2,byteorder="big")
    requested_transport = requested_transport_type + requested_transport_length_bytes + requested_transport

    print("requested_transport: ",requested_transport.hex())

    lifetime = lifetime_hour.to_bytes(4,byteorder="big")
    lifetime_len = len(lifetime).to_bytes(2,byteorder="big")
    lifetime = lifetime_type + lifetime_len + lifetime

    print("lifetime: ",lifetime.hex())



    allocate_packet = magic_cookie_pack + transaction_id_pack + lifetime + requested_transport

    length_msg = len(lifetime + requested_transport)
    length_bytes = length_msg.to_bytes(2,byteorder = "big")

    allocate_packet = length_bytes + allocate_packet

    allocate_packet = allocate_request_type + allocate_packet

    return allocate_packet,transaction_id



def parsing_allocate_msg(packet):

    lifetime = None
    good_protocol = False
    has_username = False

    print("parsing_allocate_msg: ",packet)

    transaction_id = struct.unpack(">12s",packet[8:20])[0]
    print("parsing_allocate_msg transaction_id: ",transaction_id)

    data = packet[20:]



    while data:

        type_data = data[:2]

        if type_data == lifetime_type:

            lifetime = data[4:8]
            lifetime_int = int.from_bytes(lifetime,byteorder="big")

            print("lifetime_int: ",lifetime_int)
            lifetime = lifetime_int

            print(data)
            data = data[8:]

        elif type_data == requested_transport_type:

            requested_transport_protocol = data[4]

            if requested_transport_protocol == 17:
                good_protocol = True

            data = data[8:]



    return transaction_id,lifetime,good_protocol,has_username




def parsing_allocate_error_response(packet,transaction_id_input):
    transaction_id = struct.unpack(">12s",packet[8:20])[0]
    print("parsing_allocate_msg transaction_id: ",transaction_id)

    if transaction_id != transaction_id_input:
        return None,None,None


    realm_server = None
    nonce_server = None
    expected_reason_phrase = None


    data = packet[20:]

    while data:

        type_data = data[:2]

        if type_data == error_response_type:
            header = struct.unpack(">I",data[4:8])[0]
            header = header.to_bytes(4)

            if header == error_code:
                reason_phrase_server = data[8:24]
                lst = reason_phrase_server.split(b"\x00",1)

                if lst[0] == reason_phrase:
                    print("good reason_phrase")
                    expected_reason_phrase = True

                    data = data[24:]

        elif type_data == realm_type:

            realm_len = data[2:4]
            realm_len_int = int.from_bytes(realm_len,byteorder="big")

            realm_server_not_final = data[4:4+realm_len_int]
            realm_server_lst = realm_server_not_final.split(b"\x00",1)

            realm_server = realm_server_lst[0]

            data = data[4+realm_len_int:]


        elif type_data == nonce_type:

            nonce_len = data[2:4]
            nonce_len_int = int.from_bytes(nonce_len,byteorder="big")

            nonce_server = data[4:4 + nonce_len_int]

            print("nonce_server: ",nonce_server)


            data = data[4 + nonce_len_int:]


    return realm_server,nonce_server,expected_reason_phrase