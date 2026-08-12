import socket

from constant import SIGNALING_SERVER_PORT,DELIMITER_BYTES,IP_PORT_EXT_MSG,ROOM_REQUEST
from tcp_by_size import recvSend


def find_room(recv_send_crypt,ice_candidates,fingerprint_algorithm,fingerprints):
    room_client = input("Enter the room you want to connect with: ")
    room_request = ROOM_REQUEST + room_client
    recv_send_crypt.send_with_size(room_request)

    addr_to_send_lst = []
    for addr in ice_candidates:
        port_bytes = addr[1].to_bytes(2, byteorder="big")
        ip_bytes = addr[0].encode()

        addr_to_send_lst.append((port_bytes, ip_bytes))

    to_send_ip_port_ext = IP_PORT_EXT_MSG.encode() + DELIMITER_BYTES + addr_to_send_lst[0][0] + DELIMITER_BYTES + \
                          addr_to_send_lst[0][1] + DELIMITER_BYTES + addr_to_send_lst[1][0] + DELIMITER_BYTES + \
                          addr_to_send_lst[1][1] + DELIMITER_BYTES + addr_to_send_lst[2][0] + DELIMITER_BYTES + \
                          addr_to_send_lst[2][
                              1] + DELIMITER_BYTES + fingerprint_algorithm.encode() + DELIMITER_BYTES + fingerprints
    recv_send_crypt.send_with_size(to_send_ip_port_ext)


def create_client_socket_recv_send(signaling_server_ip):
    client_socket = socket.socket()
    client_socket.connect((signaling_server_ip, SIGNALING_SERVER_PORT))
    recv_send = recvSend(client_socket, None)

    return recv_send, client_socket