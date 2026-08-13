import struct
import socket
import os
from constant import SERVER_A,SERVER_B,STUN_MAGIC_COOKIE


STUN_METHOD = {'STUN_METHOD_BINDING':0x000001}
STUN_MSG_LENGTH = 0x0000
transaction_id = 0
MAGIC_COOKIE_MOST_SIGNIFICANT = 0x2112

def generate_transaction_id():
    generate_transaction_id_random = os.urandom(12)
    return generate_transaction_id_random




def stun_request(var):
    global transaction_id

    transaction_id = generate_transaction_id()
    header = struct.pack("!HHI12s",STUN_METHOD["STUN_METHOD_BINDING"],STUN_MSG_LENGTH,STUN_MAGIC_COOKIE,transaction_id)

    transaction_id_b = generate_transaction_id()
    header_b = struct.pack("!HHI12s", STUN_METHOD["STUN_METHOD_BINDING"], STUN_MSG_LENGTH, STUN_MAGIC_COOKIE,transaction_id_b)

    if var:

        return header,header_b,transaction_id,transaction_id_b

    else:
        return header,transaction_id





def binding_response_parsing(packet):


    msg_type = packet[:2]
    transaction_id_check = packet[2:]

    if msg_type != b"\x01\x01":
        return False,transaction_id_check


    return True,transaction_id_check



def parsing_binding_request_build_request_response(packet):
    transaction_id_check = packet[8:20]


    response = b"\x01\x01" + transaction_id_check
    return response


def stun_response_parsing(data_a,transaction_id_a,data_b,transaction_id_b):

    msg_type = data_a[:2]
    transaction_id_check = data_a[8:20]
    port_external_a = data_a[26:28]
    ip_external_a = data_a[28:32]


    port_external_a = struct.unpack(">H",port_external_a)[0] ^ MAGIC_COOKIE_MOST_SIGNIFICANT

    ip_external_a = struct.unpack(">I",ip_external_a)[0] ^ STUN_MAGIC_COOKIE
    ip_external_a = struct.pack(">I",ip_external_a)
    ip_external_a = socket.inet_ntoa(ip_external_a)
    ip_external_final = ip_external_a

    if msg_type != b"\x01\x01":
        return None,None,None

    if transaction_id_check != transaction_id_a:
        return None,None,None



    msg_type_b = data_b[:2]
    transaction_id_check_b = data_b[8:20]
    port_external_b = data_b[26:28]


    port_external_b = struct.unpack(">H",port_external_b)[0] ^ MAGIC_COOKIE_MOST_SIGNIFICANT


    if msg_type_b != b"\x01\x01":
        return None,None,None

    if transaction_id_check_b != transaction_id_b:
        return None,None,None

    if port_external_b != port_external_a:
        return ip_external_final, port_external_a, False

    return ip_external_final,port_external_a,True







def keep_alive_udp_socket(udp_socket):
    transaction_id_keep_alive = generate_transaction_id()
    header = struct.pack("!HHI12s", STUN_METHOD["STUN_METHOD_BINDING"], STUN_MSG_LENGTH, STUN_MAGIC_COOKIE,
                         transaction_id_keep_alive)
    print("header:", header)
    udp_socket.sendto(header, SERVER_A)
    data, addr = udp_socket.recvfrom(1024)
    print("data:", data)

