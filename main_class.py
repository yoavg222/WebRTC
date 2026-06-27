import socket
import threading
import time

from stun_client import stun_request,keep_alive_udp_socket
from tcp_by_size import recvSend
from constant import SIGNALING_SERVER_IP_MAIN_SERVER,DH_START,DH_MSG,ROOM_REQUEST,DELIMITER,IP_PORT_EXT_MSG,SIGNALING_SERVER_PORT,SIGNALING_SERVER_IP_MAIN_CLIENT
from DH_class import DH
from hole_punching import connect_to_peer
from quic import header_parser


class Main:
    stop_keep_alive = False

    def __init__(self,var):
        self.ip,self.port,self.is_full_cone_nat,self.udp_socket = stun_request()
        self.recv_send,self.client_socket = self.create_client_socket_recv_send()
        self.recv_send_crypt = None
        self.stop_keep_alive = False
        self.signaling_server_ip = var

        if self.signaling_server_ip:
            self.signaling_server_ip = SIGNALING_SERVER_IP_MAIN_SERVER
        else:
            self.signaling_server_ip = SIGNALING_SERVER_IP_MAIN_CLIENT


    def keep_alive(self,udp_socket):

        while not self.stop_keep_alive:
            keep_alive_udp_socket(udp_socket)
            time.sleep(20)



    def hole_punching_func(self,udp_soket,other_ip,other_port):
        print("start hole punching with:",other_ip, " , ",other_port)

        self.stop_keep_alive = True

        remote_peer_tuple = (other_ip,other_port)
        connect_to_peer(udp_soket,remote_peer_tuple)

        # udp_soket.sendto("yes".encode(),(other_ip,int(other_port)))
        data,addr = udp_soket.recvfrom(2048)
        header_form,fixed_bit,packet_type,reserved,pn_length = header_parser(data)
        print("header_form,fixed_bit,packet_type,reserved,pn_length : ",header_form,fixed_bit,packet_type,reserved,pn_length)




    def find_room(self):

        room_client = input("Enter the room you want to connect with: ")
        room_request = ROOM_REQUEST +room_client
        self.recv_send_crypt.send_with_size(room_request)

        to_send_ip_port_ext = IP_PORT_EXT_MSG + DELIMITER + str(self.ip) + DELIMITER + str(self.port)
        self.recv_send_crypt.send_with_size(to_send_ip_port_ext)


    def create_client_socket_recv_send(self):
        client_socket = socket.socket()
        client_socket.connect((self.signaling_server_ip, SIGNALING_SERVER_PORT))
        recv_send = recvSend(client_socket, None)

        return recv_send,client_socket



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

        print("the other ip:",data_lst[2],"port ext: ",data_lst[1])
        self.hole_punching_func(self.udp_socket,data_lst[2],data_lst[1])
