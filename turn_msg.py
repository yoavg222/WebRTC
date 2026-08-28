import struct
import os
import hmac
import hashlib
import socket
import random

from stun_client import generate_transaction_id
from constant import STUN_MAGIC_COOKIE,SERVER_LIFETIME,ALLOCATE_TYPE,XOR_RELAYED_ADDRESS_TYPE,FAMILY_IPV4,MESSAGE_INTEGRITY_TYPE,XOR_RELAYED_ADDRESS_START,SERVER_USERNAME,SERVER_PASSWORD,CLIENT_PASSWORD,CLIENT_USERNAME,USERNAME_TYPE,ALLOCATE_REQUEST_TYPE, ERROR_RESPONSE_TYPE, ERROR_CODE, REQUESTED_TRANSPORT_TYPE, LIFETIME_TYPE, UDP_PROTOCOL, RFFU, REASON_PHRASE, LIFETIME_HOUR, REALM, REALM_TYPE, NONCE_TYPE
from constant import CHANNEL_NUMBER_TYPE,RFFU2


def transaction_id_cookie():

    magic_cookie = STUN_MAGIC_COOKIE

    transaction_id = generate_transaction_id()
    print("build_allocate_msg transaction_id: ",transaction_id)


    transaction_id_pack = struct.pack("!12s",transaction_id)
    magic_cookie_pack = struct.pack("!I",magic_cookie)

    return transaction_id,transaction_id_pack,magic_cookie_pack



def user_name_packet_message_integrity_packet(var):
    if var:
        first_user_name = SERVER_USERNAME
    else:
        first_user_name = CLIENT_USERNAME

    user_name = first_user_name.encode()
    user_name = padding(user_name)
    len_user_name = len(user_name).to_bytes(2,byteorder="big")
    user_name_packet = USERNAME_TYPE + len_user_name + user_name

    if var:
        password = SERVER_PASSWORD
    else:
        password = CLIENT_PASSWORD

    message_integrity = hmac_sha1(REALM, first_user_name, password)
    message_integrity_len = len(message_integrity).to_bytes(2, byteorder="big")
    message_integrity_packet = MESSAGE_INTEGRITY_TYPE + message_integrity_len + message_integrity


    return user_name_packet,message_integrity_packet



def xor_address(allocate_addr):

    packet_xor_address = XOR_RELAYED_ADDRESS_START + FAMILY_IPV4

    port = allocate_addr[1]
    cookie = STUN_MAGIC_COOKIE.to_bytes(4,byteorder="little")

    cookie_to_xor = cookie[:2]

    port_xor = int.from_bytes(cookie_to_xor,byteorder="little") ^ port
    port_xor_final = struct.pack("!H",port_xor)

    ip_bytes = socket.inet_aton(allocate_addr[0])
    ip_bytes_xor = int.from_bytes(cookie,byteorder="little") ^ int.from_bytes(ip_bytes,byteorder="little")
    ip_xor_final = struct.pack("!I",ip_bytes_xor)

    packet_xor_address = packet_xor_address + port_xor_final + ip_xor_final

    packet_xor_address_len = len(packet_xor_address).to_bytes(2,byteorder="big")
    packet_xor_relayed_address = XOR_RELAYED_ADDRESS_TYPE + packet_xor_address_len + packet_xor_address

    print("packet_xor_relayed_address: ",packet_xor_relayed_address)

    return packet_xor_relayed_address



def random_channel_number():
    return random.randint(16384,32767).to_bytes(4,byteorder="big")


def padding(input_var):

    to_add = 16 - len(input_var)
    add = b""

    for i in range(to_add):
        add += b"\x00"

    return input_var + add



def build_channel_bind_request(allocate_addr,var):

    nonce = os.urandom(32)

    transaction_id,transaction_id_pack,magic_cookie_pack = transaction_id_cookie()
    channel_number = random_channel_number()

    channel_number_packet = CHANNEL_NUMBER_TYPE + channel_number + RFFU2
    packet_xor_peer_address = xor_address(allocate_addr)

    user_name_packet,message_integrity_packet = user_name_packet_message_integrity_packet(var)
    nonce_packet,realm_packet = build_basic_response_error(nonce)


    len_packet = len(channel_number_packet + packet_xor_peer_address + user_name_packet + realm_packet + nonce_packet + message_integrity_packet).to_bytes(2,byteorder="big")

    return CHANNEL_NUMBER_TYPE + len_packet + magic_cookie_pack + transaction_id_pack + channel_number_packet + packet_xor_peer_address + user_name_packet + realm_packet + nonce_packet + message_integrity_packet


def build_basic_response_error(nonce):

    realm_packet = padding(REALM)
    realm_packet_len = len(realm_packet).to_bytes(2,byteorder="big")
    realm_packet = REALM_TYPE + realm_packet_len + realm_packet

    len_nonce = len(nonce).to_bytes(2,byteorder="big")

    nonce_packet = NONCE_TYPE + len_nonce + nonce

    return nonce_packet,realm_packet



def build_allocate_response_error(transaction_id):

    magic_cookie = STUN_MAGIC_COOKIE

    transaction_id_pack = struct.pack("!12s", transaction_id)
    magic_cookie_pack = struct.pack("!I", magic_cookie)


    error_code_pack = ERROR_CODE + padding(REASON_PHRASE)
    error_code_pack_len = len(error_code_pack).to_bytes(2,byteorder="big")
    error_code_pack = ERROR_RESPONSE_TYPE + error_code_pack_len + error_code_pack


    nonce = os.urandom(32)

    nonce_packet,realm_packet = build_basic_response_error(nonce)


    len_header = len(error_code_pack + realm_packet + nonce_packet).to_bytes(2,byteorder="big")
    packet = ERROR_RESPONSE_TYPE + len_header + magic_cookie_pack + transaction_id_pack + error_code_pack + realm_packet + nonce_packet

    return packet,nonce





def build_basic_allocate():


    transaction_id,transaction_id_pack,magic_cookie_pack = transaction_id_cookie()

    requested_transport = UDP_PROTOCOL + RFFU
    requested_transport_length = len(requested_transport)
    requested_transport_length_bytes = requested_transport_length.to_bytes(2,byteorder="big")
    requested_transport = REQUESTED_TRANSPORT_TYPE + requested_transport_length_bytes + requested_transport

    print("requested_transport: ",requested_transport.hex())

    lifetime = LIFETIME_HOUR.to_bytes(4,byteorder="big")
    lifetime_len = len(lifetime).to_bytes(2,byteorder="big")
    lifetime = LIFETIME_TYPE + lifetime_len + lifetime

    print("lifetime: ",lifetime.hex())


    return transaction_id,magic_cookie_pack,transaction_id_pack,lifetime,requested_transport



def build_allocate_msg(var):


    transaction_id, magic_cookie_pack, transaction_id_pack, lifetime, requested_transport  = build_basic_allocate()
    allocate_packet = magic_cookie_pack + transaction_id_pack

    if var:

        length_msg = len(lifetime + requested_transport)
        length_bytes = length_msg.to_bytes(2,byteorder = "big")

        allocate_packet = length_bytes + allocate_packet
        allocate_packet = ALLOCATE_REQUEST_TYPE + allocate_packet + lifetime + requested_transport
        return allocate_packet,transaction_id

    else:
        return allocate_packet,transaction_id,lifetime,requested_transport



def hmac_sha1(realm,user_name,password):

    if type(realm) != str:
        realm = realm.decode()

    msg = (realm + user_name + password).encode()
    key = hashlib.md5(msg).digest()

    hmac_final = hmac.new(key,msg,hashlib.sha1).digest()
    print("hmac_final: ",hmac_final)
    return hmac_final


def build_second_allocate_request(nonce,var):

    allocate_packet,transaction_id,lifetime,requested_transport = build_allocate_msg(False)

    nonce_packet,realm_packet = build_basic_response_error(nonce)
    user_name_packet,message_integrity_packet = user_name_packet_message_integrity_packet(var)

    len_packet = len(user_name_packet + message_integrity_packet + realm_packet + nonce_packet + lifetime + requested_transport).to_bytes(2, byteorder="big")

    allocate_packet = ALLOCATE_REQUEST_TYPE + len_packet  + allocate_packet + lifetime + requested_transport + user_name_packet + realm_packet + nonce_packet + message_integrity_packet

    return allocate_packet,transaction_id




def parsing_msg(packet):


    good_protocol = False
    is_error_response = False
    has_username = ""
    realm = None
    nonce = None
    message_integrity_client = None
    addr_allocate = None
    expected_reason_phrase = None
    lifetime = None
    channel_number = None

    print("parsing_allocate_msg: ",packet)

    transaction_id = struct.unpack(">12s",packet[8:20])[0]
    print("parsing_allocate_msg transaction_id: ",transaction_id)

    data = packet[20:]



    while data:

        type_data = data[:2]

        if type_data == LIFETIME_TYPE:

            lifetime = data[4:8]
            lifetime_int = int.from_bytes(lifetime,byteorder="big")
            lifetime = lifetime_int

            data = data[8:]

        elif type_data == REQUESTED_TRANSPORT_TYPE:

            requested_transport_protocol = data[4]

            if requested_transport_protocol == 17:
                good_protocol = True

            data = data[8:]


        elif type_data == USERNAME_TYPE:
            user_name_len = data[2:4]
            user_name_len_int = int.from_bytes(user_name_len,byteorder="big")
            has_username = data[4:4 + user_name_len_int]
            has_username = has_username.split(b"\x00",1)[0]

            print("has_username: ",has_username)

            data = data[4+ user_name_len_int:]


        elif type_data == REALM_TYPE:

            realm_len = data[2:4]
            realm_len_int = int.from_bytes(realm_len, byteorder="big")
            realm_server_not_final = data[4:4 + realm_len_int]
            realm_server_lst = realm_server_not_final.split(b"\x00", 1)

            realm = realm_server_lst[0]

            data = data[4 + realm_len_int:]

        elif type_data == NONCE_TYPE:

            nonce_len = data[2:4]
            nonce_len_int = int.from_bytes(nonce_len, byteorder="big")
            nonce = data[4:4 + nonce_len_int]

            data = data[4 + nonce_len_int:]


        elif type_data == MESSAGE_INTEGRITY_TYPE:

            message_integrity_len = data[2:4]
            message_integrity_len_int = int.from_bytes(message_integrity_len,byteorder="big")

            message_integrity_client = data[4:4+message_integrity_len_int]

            data = data[4+message_integrity_len_int:]


        elif type_data == XOR_RELAYED_ADDRESS_TYPE:
            print("data: ",data)
            xor_relayed_address_len = data[2:4]
            xor_relayed_address_len_int = int.from_bytes(xor_relayed_address_len,byteorder="big")

            xor_relayed_address_data = data[4:4+xor_relayed_address_len_int]

            family = xor_relayed_address_data[:2]
            print("packet_xor_relayed_address: ",family)

            if family == b"\x00\x01":
                port_xor = struct.unpack(">H",xor_relayed_address_data[2:4])[0]

                cookie = STUN_MAGIC_COOKIE.to_bytes(4, byteorder="little")
                cookie_to_xor = cookie[:2]
                port = port_xor ^ int.from_bytes(cookie_to_xor,byteorder="little")

                ip_xor = struct.unpack(">I",xor_relayed_address_data[4:8])[0]
                cookie = STUN_MAGIC_COOKIE.to_bytes(4, byteorder="little")

                cookie_int = int.from_bytes(cookie,byteorder="little")

                ip_xor = (cookie_int ^ ip_xor).to_bytes(4,byteorder="little")
                ip = '.'.join(str(c) for c in ip_xor)

                addr_allocate = (ip,port)

                data = data[4+xor_relayed_address_len_int:]


        elif type_data == ERROR_RESPONSE_TYPE:
            header = struct.unpack(">I",data[4:8])[0]
            header = header.to_bytes(4)

            if header == ERROR_CODE:
                reason_phrase_server = data[8:24]
                lst = reason_phrase_server.split(b"\x00",1)

                if lst[0] == REASON_PHRASE:
                    print("good reason_phrase")
                    expected_reason_phrase = True

                    is_error_response = True
                    data = data[24:]


    return transaction_id,lifetime,good_protocol,has_username,realm,nonce,message_integrity_client,addr_allocate,expected_reason_phrase,is_error_response,channel_number




def build_allocate_request_success(transaction_id,message_integrity_input,allocate_addr):

    packet_xor_relayed_address = xor_address(allocate_addr)

    message_integrity = hmac_sha1(REALM, message_integrity_input[0], message_integrity_input[1])
    message_integrity_len = len(message_integrity).to_bytes(2, byteorder="big")
    message_integrity_packet = MESSAGE_INTEGRITY_TYPE + message_integrity_len + message_integrity


    lifetime = SERVER_LIFETIME.to_bytes(4,byteorder="big")
    lifetime_len = len(lifetime).to_bytes(2,byteorder="big")
    lifetime = LIFETIME_TYPE + lifetime_len + lifetime



    packet_len = len(lifetime + message_integrity_packet + packet_xor_relayed_address).to_bytes(2,byteorder="big")
    packet = ALLOCATE_TYPE + packet_len + struct.pack("!I",STUN_MAGIC_COOKIE) + transaction_id + lifetime + message_integrity_packet + packet_xor_relayed_address
    return packet
