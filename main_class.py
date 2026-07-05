import socket
import threading
import time
import random

from stun_client import stun_request,keep_alive_udp_socket
from tcp_by_size import recvSend
from constant import SIGNALING_SERVER_IP_MAIN_SERVER,DH_START,DH_MSG,ROOM_REQUEST,DELIMITER,IP_PORT_EXT_MSG,SIGNALING_SERVER_PORT,SIGNALING_SERVER_IP_MAIN_CLIENT,SERVER_HELLO_TYPE_INT
from constant import HANDSHAKE_MSG_SERVER_HELLO,HANDSHAKE_MSG_CLIENT_HELLO,HANDSHAKE_MSG_ENCRYPTED_EXTENSIONS
from DH_class import DH
from hole_punching import connect_to_peer
from aiortc import RTCCertificate
from dtls import client_hello, client_hello_parsing,server_hello,server_hello_parsing,full_packet,tls_handshake_header_parsing,server_hello_type,encrypted_extensions_type,server_encrypted_extensions
from dtls import server_encrypted_extensions_seq_num,add_header_to_server_encrypted_extensions,parsing_dtls_packet,unit_records
from dtls_secure_session import DTLS13_SecureSession


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
            self.client_handshake_key = None
            self.client_handshake_iv = None
            self.client_record_number_key = None
            self.server_handshake_key = None
            self.server_handshake_iv = None
            self.server_record_number_key = None
            self.dtls_secure_encrypt = None
            self.dtls_secure_decrypt = None
            self.handshake_packets = {
                "server_hello":None,
                "client_hello":None,
                "server_encrypted_extension":None,
                "server_certificate":None,
                "server_cert_verify":None,
                "server_finished":None,
                "client_certificate":None,
                "client_cert_verify":None,
                "client_finished":None
            }
            self.other_seq_num = None
            self.seq_number_epoch = 0



        def keep_alive(self,udp_socket):

            while not self.stop_keep_alive:
                keep_alive_udp_socket(udp_socket)
                time.sleep(20)



        def hole_punching_func(self):
            print("start hole punching with:",self.other_ip, " , ",self.other_port)

            self.stop_keep_alive = True

            remote_peer_tuple = (self.other_ip,self.other_port)
            connect_to_peer(self.udp_socket,remote_peer_tuple,self.signaling_server_ip)



        def server_hello_logic(self, data):
            self.other_random_dtls, self.cipher_suits, self.group, self.other_public_key = server_hello_parsing(data)
            print("other_random_dtls: ", self.other_random_dtls, " cipher_suits: ", self.cipher_suits, " group: ",self.group, " other_public_key: ", self.other_public_key)

            self.ecdh_class.shared_key_calculate(self.other_public_key, self.group)
            self.client_handshake_key, self.client_handshake_iv, self.client_record_number_key, self.server_handshake_key, self.server_handshake_iv, self.server_record_number_key = self.ecdh_class.derived_key_func(self.cipher_suits)
            print("derived_key_client: ", self.client_handshake_key, " derived_key_server", self.server_handshake_key)

            self.dtls_secure_decrypt = DTLS13_SecureSession(self.server_handshake_key, self.server_handshake_iv,self.server_record_number_key)
            self.dtls_secure_encrypt = DTLS13_SecureSession(self.client_handshake_key, self.client_handshake_iv,self.client_record_number_key)



        def client_hello_logic(self,data):
            self.other_random_dtls, self.cipher_suits, self.group, self.other_public_key = client_hello_parsing(data)
            print("other_random_dtls: ", self.other_random_dtls, " cipher_suits: ", self.cipher_suits, " group: ",self.group, " other_public_key: ", self.other_public_key)



        def create_ecdh_keys(self):
            self.ecdh_class.shared_key_calculate(self.other_public_key, self.group)
            self.client_handshake_key, self.client_handshake_iv, self.client_record_number_key, self.server_handshake_key, self.server_handshake_iv, self.server_record_number_key = self.ecdh_class.derived_key_func(self.cipher_suits)
            print("derived_key_client: ", self.client_handshake_key, " derived_key_server", self.server_handshake_key)

            self.dtls_secure_encrypt = DTLS13_SecureSession(self.server_handshake_key,self.server_handshake_iv,self.server_record_number_key)
            self.dtls_secure_encrypt = DTLS13_SecureSession(self.client_handshake_key,self.server_handshake_iv,self.server_record_number_key)



        def dtls_handshake_server(self):

            self.udp_socket.settimeout(1)
            time_out_seconds = 1.75
            disconnect = False

            try:
                data,addr = self.udp_socket.recvfrom(1024)
                if data == b"Ack":
                    print("clean the socket buffer before the handshake")

            except TimeoutError:
                print("the socket buffer was clean")

            self.udp_socket.settimeout(None)
            print("server starts the handshake")

            counter_client_hello = 0

            while True:

                if counter_client_hello > 7:
                    self.udp_socket.close()
                    disconnect = True
                    break

                data,addr = self.udp_socket.recvfrom(2048)

                if data == b"":
                    print("the other peer disconnect")
                    disconnect = True
                    break


                else:
                    self.client_hello_logic(data)
                    if self.other_random_dtls is None or self.cipher_suits is None or self.group is None or self.other_public_key is None:
                        print("something gone wrong at hello_logic in dtls_handshake_server")
                        continue


                    else:
                        break


            if disconnect:
                return



            server_hello_packet,self.ecdh_class,self.seq_number = server_hello(self.seq_number,self.random_dtls,self.cipher_suits,HANDSHAKE_MSG_SERVER_HELLO)
            self.create_ecdh_keys()

            server_encrypted_extensions_packet,self.seq_number_epoch = server_encrypted_extensions(self.seq_number,HANDSHAKE_MSG_ENCRYPTED_EXTENSIONS)


            encrypted_extensions_packet_encrypt = []
            for msg in server_encrypted_extensions_packet:
                seq_num = server_encrypted_extensions_seq_num(msg)
                packet,header_info,record_number = self.dtls_secure_encrypt.encrypt_and_mask(seq_num,msg)
                packet = add_header_to_server_encrypted_extensions(packet,header_info,record_number)
                encrypted_extensions_packet_encrypt.append(packet)


            unit_work,msg = unit_records(server_hello_packet,encrypted_extensions_packet_encrypt)

            if unit_work:
                self.udp_socket.sendto(msg,(self.other_ip,self.other_port))

            else:
                for msg in server_hello_packet:
                    self.udp_socket.sendto(msg,(self.other_ip,self.other_port))

                for msg in encrypted_extensions_packet_encrypt:
                    self.udp_socket.sendto(msg,(self.other_ip,self.other_port))







        def dtls_handshake_client(self):
            disconnect = False
            time_out_seconds = 1.75
            counter = 0

            self.ecdh_class, client_hello_lst = client_hello(self.seq_number, self.random_dtls, HANDSHAKE_MSG_CLIENT_HELLO)
            self.seq_number += len(client_hello_lst)

            for msg in client_hello_lst:
                self.udp_socket.sendto(msg,(self.other_ip,self.other_port))

            self.udp_socket.settimeout(time_out_seconds)

            while True:
                try:
                    data,addr = self.udp_socket.recvfrom(2048)
                    counter = 0

                    if not data:
                        print("the other peer disconnect")
                        disconnect = True
                        break

                    else:
                        records_lst = parsing_dtls_packet(data)

                        for record in records_lst:
                            print(record)


                except TimeoutError:

                    if counter > 7:
                        print("too many attempts")

                    time_out_seconds = time_out_seconds * 2
                    self.udp_socket.settimeout(time_out_seconds)

                    counter += 1

                    self.ecdh_class, client_hello_lst = client_hello(self.seq_number, self.random_dtls,HANDSHAKE_MSG_CLIENT_HELLO)
                    self.seq_number += len(client_hello_lst)

                    for msg in client_hello_lst:
                        self.udp_socket.sendto(msg, (self.other_ip, self.other_port))






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




        def main(self):
            print("---------------------------------")
            print("ip : ", self.ip ," port : ",self.port," is_full_cone_nat :",self.is_full_cone_nat)

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


