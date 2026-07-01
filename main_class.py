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
from dtls import client_hello, client_hello_parsing, server_hello, handshake_type


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
        self.other_public_key = None
        self.cipher_suits = None
        self.group = None
        self.seq_number = 0
        self.ecdh_class = None
        self.lst_msg = []
        self.handshake_msg = []


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
        print("server start the dtls handshake")
        time_out_seconds = 1.75
        disconnect = False



        data,addr = self.udp_socket.recvfrom(2048)

        if data == b"":
            print("the other peer disconnect")
            disconnect = True

            if disconnect:
                self.udp_socket.close()
                return

        else:
            print(data)
            self.other_random_dtls,self.cipher_suits,self.group,self.other_public_key = client_hello_parsing(data)
            print("other_random_dtls: ",self.other_random_dtls," cipher_suits: ",self.cipher_suits," group: ",self.group," other_public_key: ",self.other_public_key)

        server_hello_packet,self.ecdh_class,self.seq_number =server_hello(self.seq_number,self.random_dtls,self.cipher_suits,0)
        self.seq_number += len(self.lst_msg)

        for msg in server_hello_packet:
            self.udp_socket.sendto(msg,(self.other_ip,self.other_port))









    def dtls_handshake_client(self):
        disconnect = False
        time_out_seconds = 1.75

        self.ecdh_class,self.lst_msg = client_hello(self.seq_number,self.random_dtls,0)
        self.seq_number += len(self.lst_msg)
        print("client start the dtls handshake")

        for msg in self.lst_msg:
            self.udp_socket.sendto(msg,(self.other_ip,self.other_port))

        self.udp_socket.settimeout(time_out_seconds)
        while True:
            try:
                data,addr = self.udp_socket.recvfrom(2048)

                if data == b"":
                    print("the other peer disconnect")
                    disconnect = True
                    break


                print(data)
                break

            except TimeoutError:
                time_out_seconds  = time_out_seconds * 2
                self.udp_socket.settimeout(time_out_seconds)
                for msg in self.lst_msg:
                    self.udp_socket.sendto(msg,(self.other_ip,self.other_port))

        if disconnect:
            self.udp_socket.close()
            return





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


