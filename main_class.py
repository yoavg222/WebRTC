import socket
import threading
import time
import random
import hashlib

from stun_client import stun_request,keep_alive_udp_socket
from tcp_by_size import recvSend
from constant import SIGNALING_SERVER_IP_MAIN_SERVER,DH_START,DH_MSG,ROOM_REQUEST,DELIMITER,IP_PORT_EXT_MSG,SIGNALING_SERVER_PORT,SIGNALING_SERVER_IP_MAIN_CLIENT,CERTIFICATE_TYPE
from constant import HANDSHAKE_MSG_SERVER_HELLO,HANDSHAKE_MSG_CLIENT_HELLO,HANDSHAKE_MSG_ENCRYPTED_EXTENSIONS,HEADER_INFO_INT,HANDSHAKE_TYPE,ENCRYPTED_EXTENSIONS_TYPE,DELIMITER_BYTES
from DH_class import DH
from hole_punching import connect_to_peer
from aiortc import RTCCertificate
from dtls import client_hello, client_hello_parsing, server_hello, server_hello_parsing, full_packet, \
    tls_handshake_header_parsing, server_hello_type, encrypted_extensions_type, server_encrypted_extensions, \
    add_header_to_server_encrypted_packets,certificate_parsing,remove_header,check_if_full_packet,certificate_verify
from dtls import server_encrypted_extensions_seq_num,add_header_to_server_encrypted_packets,unit_records,server_encrypted_extensions_parsing,certificate,select_signature_algorithms
from dtls_secure_session import DTLS13_SecureSession
from build_certificate import BuildCertificate
from cryptography import x509
from cryptography.hazmat.primitives import hashes




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

            self.certificate_object = BuildCertificate()
            self.fingerprints,self.fingerprint_algorithm = self.certificate_object.fingerprint()


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
                "server_encrypted_extension":None,
                "server_certificate":None,
                "server_cert_verify":None,
                "server_finished":None,
                "client_hello":None,
                "client_certificate":None,
                "client_cert_verify":None,
                "client_finished":None,

            }
            self.other_seq_num = None
            self.seq_number_epoch = 0
            self.signature_algorithms_client_lst = None
            self.selected_algorithm = None
            self.other_rsa_public_key = None


        def supported_groups_logic(self,supported_groups_lst):
            if self.group in supported_groups_lst:
                return True
            return False



        def seq_number_logic(self,seq_number,seq_number_coming):

            for number in seq_number_coming:
                if number >= seq_number:
                    return None,False

            seq_number_coming.append(seq_number)
            return seq_number_coming,True


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
            # self.ecdh_class = ECDH()


            self.other_random_dtls, self.cipher_suits, self.group, self.other_public_key = server_hello_parsing(data)
            print("other_random_dtls: ", self.other_random_dtls, " cipher_suits: ", self.cipher_suits, " group: ",self.group, " other_public_key: ", self.other_public_key)

            self.ecdh_class.shared_key_calculate(self.other_public_key, self.group)
            self.client_handshake_key, self.client_handshake_iv, self.client_record_number_key, self.server_handshake_key, self.server_handshake_iv, self.server_record_number_key = self.ecdh_class.derived_key_func(self.cipher_suits)
            print("derived_key_client: ", self.client_handshake_key, " derived_key_server", self.server_handshake_key)

            self.dtls_secure_decrypt = DTLS13_SecureSession(self.server_handshake_key, self.server_handshake_iv,self.server_record_number_key)
            print("server_handshake_key in server_hello_logic: ",self.server_handshake_key.hex())

            self.dtls_secure_encrypt = DTLS13_SecureSession(self.client_handshake_key, self.client_handshake_iv,self.client_record_number_key)



        def client_hello_logic(self,data):
            self.other_random_dtls, self.cipher_suits, self.group, self.other_public_key,self.signature_algorithms_client_lst = client_hello_parsing(data)
            print("other_random_dtls: ", self.other_random_dtls, " cipher_suits: ", self.cipher_suits, " group: ",self.group, " other_public_key: ", self.other_public_key,"signature_algorithms_client_lst: ",self.signature_algorithms_client_lst)

            self.selected_algorithm = select_signature_algorithms(self.signature_algorithms_client_lst)

            if self.selected_algorithm is not None:
                return True
            return False



        def certificate_logic(self,packet):
            print(packet.hex())
            the_certificate = certificate_parsing(packet)
            the_certificate_2 = certificate_parsing(packet)

            print("the_certificate in certificate_logic: ",the_certificate.hex())


            if self.other_sha_algorithm == "sha-256":



                certificate_object_other = x509.load_der_x509_certificate(the_certificate_2)

                peer_fingerprint = certificate_object_other.fingerprint(hashes.SHA256())
                self.other_rsa_public_key = certificate_object_other.public_key()


                if self.other_fingerprints == peer_fingerprint:
                    return True
                return False

            else:
                return False






        def create_ecdh_keys(self):
            # self.ecdh_class = ECDH()

            self.ecdh_class.shared_key_calculate(self.other_public_key, self.group)
            self.client_handshake_key, self.client_handshake_iv, self.client_record_number_key, self.server_handshake_key, self.server_handshake_iv, self.server_record_number_key = self.ecdh_class.derived_key_func(self.cipher_suits)
            print("derived_key_client: ", self.client_handshake_key, " derived_key_server", self.server_handshake_key)

            self.dtls_secure_encrypt = DTLS13_SecureSession(self.server_handshake_key,self.server_handshake_iv,self.server_record_number_key)
            print("server_handshake_key in create_ecdh_keys: ",self.server_handshake_key.hex())


            self.dtls_secure_decrypt = DTLS13_SecureSession(self.client_handshake_key,self.server_handshake_iv,self.server_record_number_key)



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
                    client_hello_good = self.client_hello_logic(data)
                    client_hello_packet = remove_header(data)
                    self.handshake_packets["client_hello"] = client_hello_packet

                    if not client_hello_good:
                        disconnect = True
                        break

                    if self.other_random_dtls is None or self.cipher_suits is None or self.group is None or self.other_public_key is None:
                        print("something gone wrong at hello_logic in dtls_handshake_server")
                        disconnect = True
                        break


                    else:
                        break


            if disconnect:
                return



            server_hello_packet,self.ecdh_class,self.seq_number = server_hello(self.seq_number,self.random_dtls,self.cipher_suits,HANDSHAKE_MSG_SERVER_HELLO)

            if len(server_hello_packet) > 1:
                full_packet()
            else:
                server_hello_packet_without_header = remove_header(server_hello_packet[0])
                self.handshake_packets["server_hello"] = server_hello_packet_without_header

            self.create_ecdh_keys()
            server_encrypted_extensions_packet,self.seq_number_epoch,seq_num_server_encrypted_extensions = server_encrypted_extensions(self.seq_number_epoch,HANDSHAKE_MSG_ENCRYPTED_EXTENSIONS)

            if len(server_encrypted_extensions_packet) > 1:
                full_packet()

            else:
                server_encrypted_extensions_packet_without_header = remove_header(server_encrypted_extensions_packet[0])
                self.handshake_packets["server_encrypted_extension"] = server_encrypted_extensions_packet_without_header

            certificate_server,self.seq_number_epoch,seq_num_certificate = certificate(self.seq_number_epoch,self.certificate_object.to_der())

            if len(certificate_server) > 1:
                full_packet()
            else:
                certificate_server_without_header = remove_header(certificate_server[0])
                self.handshake_packets["server_certificate"] = certificate_server_without_header

            certificate_verify(self.handshake_packets,self.selected_algorithm,self.certificate_object)


            encrypted_extensions_packet_encrypt = []
            for msg in server_encrypted_extensions_packet:
                seq_num = seq_num_server_encrypted_extensions
                packet,header_info,record_number = self.dtls_secure_encrypt.encrypt_and_mask(seq_num,msg)
                packet = add_header_to_server_encrypted_packets(packet,header_info,record_number)
                encrypted_extensions_packet_encrypt.append(packet)


            certificate_packet_encrypt = []
            for msg in certificate_server:
                seq_num = seq_num_certificate
                packet,header_info,record_number = self.dtls_secure_encrypt.encrypt_and_mask(seq_num,msg)
                packet = add_header_to_server_encrypted_packets(packet,header_info,record_number)
                certificate_packet_encrypt.append(packet)


            unit_work,msg = unit_records(server_hello_packet,encrypted_extensions_packet_encrypt)

            if unit_work:
                self.udp_socket.sendto(msg,(self.other_ip,self.other_port))

                for msg in certificate_packet_encrypt:
                    self.udp_socket.sendto(msg,(self.other_ip,self.other_port))

            else:
                for msg in server_hello_packet:
                    self.udp_socket.sendto(msg,(self.other_ip,self.other_port))

                for msg in encrypted_extensions_packet_encrypt:
                    self.udp_socket.sendto(msg,(self.other_ip,self.other_port))

                for msg in certificate_packet_encrypt:
                    self.udp_socket.sendto(msg, (self.other_ip, self.other_port))



        def dtls_handshake_client(self):
            disconnect = False
            time_out_seconds = 1.75
            counter = 0
            coming_msg = {
                "server_hello": False,
                "server_encrypted_extension": False,
                "server_certificate": False,
                "server_cert_verify": False,
                "server_finished": False,
            }
            need_to_decrypt_lst = []
            seq_number_coming_epoch_0 = []
            seq_number_coming_epoch_1 = []

            self.ecdh_class, client_hello_lst = client_hello(self.seq_number, self.random_dtls,HANDSHAKE_MSG_CLIENT_HELLO)
            self.seq_number += len(client_hello_lst)

            for msg in client_hello_lst:
                self.udp_socket.sendto(msg, (self.other_ip, self.other_port))

            if check_if_full_packet(client_hello_lst):
                packet = remove_header(client_hello_lst[0])
                self.handshake_packets["client_hello"] = packet


            self.udp_socket.settimeout(time_out_seconds)

            while True:
                if disconnect:
                    break


                if (coming_msg["server_hello"] and coming_msg["server_encrypted_extension"] and coming_msg["server_certificate"]
                    and coming_msg["server_cert_verify"]):
                        break


                try:
                    data,addr = self.udp_socket.recvfrom(2048)
                    counter = 0

                    if not data:
                        print("the other peer disconnect")
                        disconnect = True
                        break

                    # data = full_packet()

                    current_len = 0
                    packet_len = len(data)
                    current_packet = data

                    while current_len < packet_len:
                        print("current packet in dtls_handshake_client: ", current_packet.hex())
                        if disconnect:
                            break

                        record_first_byte = current_packet[0]
                        record_first_byte_bytes = record_first_byte.to_bytes(1)

                        if record_first_byte_bytes == HANDSHAKE_TYPE:
                            print("this packet is a server hello packet")
                            record_header = current_packet[:13]
                            seq_number = int.from_bytes(record_header[5:11], byteorder="big")
                            seq_number_coming, work = self.seq_number_logic(seq_number, seq_number_coming_epoch_0)

                            if not work:
                                print("seq number warning")
                                disconnect = True
                                break

                            length = int.from_bytes(record_header[-2:], byteorder="big")
                            self.server_hello_logic(current_packet[:length + 13])

                            if self.other_random_dtls is None or self.cipher_suits is None or self.group is None or self.other_public_key is None:
                                print("something gone wrong at server_hello packet")

                            else:
                                self.handshake_packets["server_hello"] = remove_header(current_packet)
                                coming_msg["server_hello"] = True

                                current_len += length + len(record_header)
                                current_packet = current_packet[13 + length:]

                            for msg in need_to_decrypt_lst:
                                plain_text, seq = self.dtls_secure_decrypt.decrypt_and_mask(msg)
                                seq_number_coming, work = self.seq_number_logic(seq, seq_number_coming_epoch_1)
                                if not work:
                                    disconnect = True
                                    break
                                if plain_text[0] == ENCRYPTED_EXTENSIONS_TYPE:

                                    supported_groups_lst = server_encrypted_extensions_parsing(plain_text)
                                    good = self.supported_groups_logic(supported_groups_lst)

                                    if not good:
                                        disconnect = True
                                        print("something gone wrong at dtls_handshake_client")
                                        break
                                    else:
                                        print("good supported_groups_lst")

                                    coming_msg["server_encrypted_extension"] = True
                                    self.handshake_packets["server_encrypted_extension"] = remove_header(plain_text)

                                    current_len += length + len(record_header)
                                    current_packet = current_packet[5 + length:]

                                    need_to_decrypt_lst.remove(msg)


                                elif plain_text[0] == ENCRYPTED_EXTENSIONS_TYPE and coming_msg["server_encrypted_extension"]:

                                    mitm_check = self.certificate_logic(plain_text)

                                    if not mitm_check:
                                        print("warning strong suspicion to MITM attack!!")
                                        disconnect = True
                                        break

                                    else:
                                        print("successful verification check")
                                        coming_msg["server_certificate"] = True
                                        self.handshake_packets["server_certificate"] = remove_header(plain_text)

                                        current_len += length + len(record_header)
                                        current_packet = current_packet[5 + length:]



                        elif record_first_byte == HEADER_INFO_INT:
                            record_header = current_packet[:5]
                            length = int.from_bytes(current_packet[3:5], byteorder="big")

                            if coming_msg["server_hello"]:

                                print("current header in if coming_msg[server_hello]: ", current_packet.hex())
                                plain_text, seq_number = self.dtls_secure_decrypt.decrypt_and_mask(current_packet)

                                plain_text_handshake_mag_type = plain_text[0]
                                plain_text_handshake_mag_type = plain_text_handshake_mag_type.to_bytes(1)
                                work = self.seq_number_logic(seq_number, seq_number_coming_epoch_1)

                                if not work:
                                    disconnect = True
                                    break

                                if plain_text_handshake_mag_type == ENCRYPTED_EXTENSIONS_TYPE and not coming_msg["server_encrypted_extension"]:
                                    supported_groups_lst = server_encrypted_extensions_parsing(plain_text)
                                    good = self.supported_groups_logic(supported_groups_lst)
                                    if not good:
                                        disconnect = True
                                        print("something gone wrong at dtls_handshake_client")
                                        break
                                    else:
                                        print("good supported_groups_lst")

                                    coming_msg["server_encrypted_extension"] = True
                                    self.handshake_packets["server_encrypted_extension"] = remove_header(plain_text)

                                    current_len += length + len(record_header)
                                    current_packet = current_packet[5 + length:]

                                if plain_text_handshake_mag_type == CERTIFICATE_TYPE:
                                    if coming_msg["server_encrypted_extension"]:

                                        print(plain_text)
                                        mitm_check = self.certificate_logic(plain_text)

                                        if not mitm_check:
                                            print("warning strong suspicion to MITM attack!!")
                                            disconnect = True
                                            break

                                        else:
                                            print("successful verification check")
                                            coming_msg["server_certificate"] = True
                                            self.handshake_packets["server_certificate"] = remove_header(plain_text)

                                            current_len += length + len(record_header)
                                            current_packet = current_packet[5 + length:]

                                    else:
                                        need_to_decrypt_lst.append(current_packet)
                                        current_len += length + len(record_header)
                                        current_packet = current_packet[5 + length:]

                            else:
                                need_to_decrypt_lst.append(current_packet)
                                current_len += length + len(record_header)
                                current_packet = current_packet[5 + length:]




                except TimeoutError:
                    counter += 1
                    print(counter)
                    if counter >= 5:
                        print("too many attempts")
                        disconnect = True
                        continue

                    time_out_seconds *= 2
                    self.udp_socket.settimeout(time_out_seconds)

                    for msg in client_hello_lst:
                        self.udp_socket.sendto(msg, (self.other_ip, self.other_port))

            if disconnect:
                print("closing the socket")
                self.udp_socket.close()
                return





        print("finish handshake")





        def find_room(self):

            room_client = input("Enter the room you want to connect with: ")
            room_request = ROOM_REQUEST +room_client
            self.recv_send_crypt.send_with_size(room_request)


            port_bytes = self.port.to_bytes(2,byteorder="big")

            to_send_ip_port_ext = IP_PORT_EXT_MSG.encode() + DELIMITER_BYTES + self.ip.encode() + DELIMITER_BYTES + port_bytes + DELIMITER_BYTES + self.fingerprint_algorithm.encode() + DELIMITER_BYTES + self.fingerprints
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

            data = self.recv_send_crypt.recv_by_size()
            data_lst = data.split(DELIMITER_BYTES)

            # print("the other ip:",data_lst[2].decode(),"port ext: ",data_lst[1],"the hash_algorithm: ",data_lst[3],"the fingerprints_value: ",data_lst[4])
            self.other_sha_algorithm = data_lst[3].decode()
            self.other_fingerprints = data_lst[4]

            self.other_ip = data_lst[2].decode()
            self.other_port = int.from_bytes(data_lst[1],byteorder="big")

            self.hole_punching_func()

            if self.signaling_server_ip == SIGNALING_SERVER_IP_MAIN_SERVER:
                self.dtls_handshake_server()
            else:
                self.dtls_handshake_client()


