import socket
import threading
import time
import random

from stun_client import stun_request,keep_alive_udp_socket
from tcp_by_size import recvSend
from constant import SIGNALING_SERVER_IP_MAIN_SERVER,DH_START,DH_MSG,ROOM_REQUEST,DELIMITER,IP_PORT_EXT_MSG,SIGNALING_SERVER_PORT,SIGNALING_SERVER_IP_MAIN_CLIENT
from DH_class import DH
from hole_punching import connect_to_peer
from aiortc import RTCCertificate
from dtls import client_hello,client_hello_parsing,server_hello


class Main:
    stop_keep_alive = False

    def __init__(self,var):
        self.ip,self.port,self.is_full_cone_nat,self.udp_socket = stun_request()
        self.recv_send_crypt = None
        self.stop_keep_alive = False
        self.signaling_server_ip = var

        if self.signaling_server_ip:
            self.signaling_server_ip = SIGNALING_SERVER_IP_MAIN_SERVER
        else:
            self.signaling_server_ip = SIGNALING_SERVER_IP_MAIN_CLIENT

        self.recv_send, self.client_socket = self.create_client_socket_recv_send()
        self.certificate = RTCCertificate.generateCertificate()
        self.fingerprints = self.certificate.getFingerprints()

        self.other_fingerprints = None
        self.other_sha_algorithm = None

        self.other_ip = None
        self.other_port = None
        self.random_dtls = random.randbytes(32)
        self.other_random_dtls = None
        self.client_public_key = None
        self.cipher_suits = None
        self.msg_aeq_number = {}
        self.dtls_msg = []

    def keep_alive(self,udp_socket):

        while not self.stop_keep_alive:
            keep_alive_udp_socket(udp_socket)
            time.sleep(20)



    def hole_punching_func(self):
        print("start hole punching with:",self.other_ip, " , ",self.other_port)

        self.stop_keep_alive = True

        remote_peer_tuple = (self.other_ip,self.other_port)
        connect_to_peer(self.udp_socket,remote_peer_tuple,self.signaling_server_ip)



    def dtls_handshake_server(self):
        is_full = False
        disconnect = False
        while not is_full:
            data,addr = self.udp_socket.recvfrom(2048)

            is_full,self.other_random_dtls,self.client_public_key,self.cipher_suits = client_hello_parsing(data)
            print("is_full: ", is_full," other_random_dtls: ",self.other_random_dtls," client_public_key: ",self.client_public_key)


        server_hello_packet,server_ecdh = server_hello(0,self.random_dtls,self.cipher_suits)
        self.udp_socket.settimeout(1.5)
        self.udp_socket.sendto(server_hello_packet,(self.other_ip,self.other_port))


    def dtls_handshake_client(self):
        self.udp_socket.settimeout(1.5)
        disconnect = False
        client_hello_packet, ecdh_client = client_hello(0, self.random_dtls)

        while len(self.dtls_msg) < 5:
            self.udp_socket.sendto(client_hello_packet,(self.other_ip,self.other_port))

            try:
                data,addr = self.udp_socket.recvfrom(2048)

                if data == b"":
                    disconnect = True
                    break

                else:
                    print(data)
                    break


            except TimeoutError:
                continue

        if disconnect:
            self.udp_socket.close()
            return

        self.udp_socket.sendto(b"yes", (self.other_ip, self.other_port))


    def find_room(self):

        room_client = input("Enter the room you want to connect with: ")
        room_request = ROOM_REQUEST +room_client
        self.recv_send_crypt.send_with_size(room_request)

        to_send_ip_port_ext = IP_PORT_EXT_MSG + DELIMITER + str(self.ip) + DELIMITER + str(self.port) + DELIMITER + self.fingerprints[0].algorithm + DELIMITER + self.fingerprints[0].value
        self.recv_send_crypt.send_with_size(to_send_ip_port_ext)


    def create_client_socket_recv_send(self):
        client_socket = socket.socket()
        client_socket.connect((self.signaling_server_ip, SIGNALING_SERVER_PORT))
        recv_send = recvSend(client_socket, None)

        return recv_send,client_socket


    def save_other_random_dtls(self,random_dtls):
        self.other_random_dtls = random_dtls



    def main(self):
        print("---------------------------------")
        print("ip :", self.ip ," port : ",self.port," is_full_cone_nat :",self.is_full_cone_nat)

        t = threading.Thread(target=self.keep_alive,args = (self.udp_socket,))
        t.start()

        self.recv_send.send_with_size(DH_START)
        from_server = self.recv_send.recv_by_size().decode()

        if from_server != DH_MSG:
            print("Error in from_server")

        dh_client = DH()
        key = dh_client.dhp_key_exchange_client(self.recv_send)
        print("key from client: ",key)

        self.recv_send_crypt = recvSend(self.client_socket,key)
        self.find_room()

        data = self.recv_send_crypt.recv_by_size().decode()
        data_lst = data.split(DELIMITER)

        print("the other ip:",data_lst[2],"port ext: ",data_lst[1],"the hash_algorithm: ",data_lst[3],"the fingerprints_value: ",data_lst[4])
        self.other_sha_algorithm = data_lst[3]
        self.other_fingerprints = data_lst[4]

        self.other_ip = data_lst[2]
        self.other_port = int(data_lst[1])

        self.hole_punching_func()

        if self.signaling_server_ip == SIGNALING_SERVER_IP_MAIN_SERVER:
            self.dtls_handshake_server()
        else:
            self.dtls_handshake_client()


