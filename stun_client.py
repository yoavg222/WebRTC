import struct
import socket
import os
from constant import SERVER_A,SERVER_B


STUN_MAGIC_COOKIE = 0x2112A442
STUN_METHOD = {'STUN_METHOD_BINDING':0x000001}
STUN_MSG_LENGTH = 0x0000
transaction_id = 0
MAGIC_COOKIE_MOST_SIGNIFICANT = 0x2112

def generate_transaction_id():
    generate_transaction_id_random = os.urandom(12)
    print("generate_transaction_id_random:",generate_transaction_id_random)
    return generate_transaction_id_random


def stun_request():
    global transaction_id
    port_external_a = -1
    port_external_b = -1
    ip_external_final = -1

    client_socket = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)

    print("Sending binding request to stun server")

    transaction_id = generate_transaction_id()
    header = struct.pack("!HHI12s",STUN_METHOD["STUN_METHOD_BINDING"],STUN_MSG_LENGTH,STUN_MAGIC_COOKIE,transaction_id)
    print("header:",header)

    client_socket.sendto(header,SERVER_A)
    data,addr = client_socket.recvfrom(1024)
    print("data:",data)

    msg_type = data[:2]
    transaction_id_check = data[8:20]
    port_external_a = data[26:28]
    ip_external_a = data[28:32]



    print("ip_external_a:",ip_external_a)
    print("port_external_a:",port_external_a)
    print("transaction_id_check:",transaction_id_check)
    print("msg_type:",msg_type)

    port_external_a = struct.unpack(">H",port_external_a)[0] ^ MAGIC_COOKIE_MOST_SIGNIFICANT
    print("port_a:",port_external_a)

    ip_external_a = struct.unpack(">I",ip_external_a)[0] ^ STUN_MAGIC_COOKIE
    ip_external_a = struct.pack(">I",ip_external_a)
    ip_external_a = socket.inet_ntoa(ip_external_a)
    ip_external_final = ip_external_a
    print("ip_external_a:",ip_external_final)

    if msg_type != b"\x01\x01":
        print("Error in msg_type")
        return None,None,None
    print("Good message type")

    if transaction_id_check != transaction_id:
        print("Error in transaction_id_check")
        return None,None,None

    print("Check the type of NAT table")

    transaction_id_b = generate_transaction_id()
    print("transaction_id_b:",transaction_id_b)

    header_b = struct.pack("!HHI12s", STUN_METHOD["STUN_METHOD_BINDING"], STUN_MSG_LENGTH, STUN_MAGIC_COOKIE,transaction_id_b)
    client_socket.sendto(header_b,SERVER_B)
    data_b,addr_b = client_socket.recvfrom(1024)
    print(data_b)

    msg_type_b = data_b[:2]
    transaction_id_check_b = data_b[8:20]
    port_external_b = data_b[26:28]

    port_external_b = struct.unpack(">H",port_external_b)[0] ^ MAGIC_COOKIE_MOST_SIGNIFICANT
    print("port_external_b:",port_external_b)
    print("transaction_id_check_b:",transaction_id_check_b)

    if msg_type_b != b"\x01\x01":
        print("Error in msg_type_b")
        return None,None,None,client_socket
    print("Good msg_type_b")

    if transaction_id_check_b != transaction_id_b:
        print("Error in transaction_id_check")
        return None,None,None,client_socket

    if port_external_b != port_external_a:
        print("You have a symmetric NAT")
        return ip_external_final, port_external_a, False,client_socket

    print("You have a full cone NAT ")
    return ip_external_final,port_external_a,True,client_socket



def keep_alive_udp_socket(udp_socket):
    transaction_id_keep_alive = generate_transaction_id()
    header = struct.pack("!HHI12s", STUN_METHOD["STUN_METHOD_BINDING"], STUN_MSG_LENGTH, STUN_MAGIC_COOKIE,
                         transaction_id_keep_alive)
    print("header:", header)
    udp_socket.sendto(header, SERVER_A)
    data, addr = udp_socket.recvfrom(1024)
    print("data:", data)

