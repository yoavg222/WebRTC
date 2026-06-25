import socket
import threading
import time

from stun_client import stun_request,keep_alive_udp_socket
from tcp_by_size import recvSend
from constant import SIGNALING_SERVER_IP,DH_START,DH_MSG,ROOM_REQUEST,DELIMITER,IP_PORT_EXT_MSG,SIGNALING_SERVER_PORT
from DH_class import DH
from hole_punching import connect_to_peer

stop_keep_alive = False


def keep_alive(udp_socket):
    global stop_keep_alive

    while not stop_keep_alive:
        keep_alive_udp_socket(udp_socket)
        time.sleep(20)



def hole_punching_func(udp_soket,other_ip,other_port):
    global stop_keep_alive
    print("start hole punching with:",other_ip, " , ",other_port)

    stop_keep_alive = True

    remote_peer_tuple = (other_ip,other_port)
    connect_to_peer(udp_soket,remote_peer_tuple)

    udp_soket.sendto("yes".encode(),(other_ip,int(other_port)))





def find_room(recv_send_crypt,ip,port):

    room_client = input("Enter the room you want to connect with: ")
    room_request = ROOM_REQUEST +room_client
    recv_send_crypt.send_with_size(room_request)

    to_send_ip_port_ext = IP_PORT_EXT_MSG + DELIMITER + str(ip) + DELIMITER + str(port)
    recv_send_crypt.send_with_size(to_send_ip_port_ext)



def main():

    ip,port,is_full_cone_nat,udp_socket  = stun_request()
    print()
    print("---------------------------------")
    print("ip :", ip ," port : ",port," is_full_cone_nat :",is_full_cone_nat)

    t = threading.Thread(target=keep_alive,args = (udp_socket,))
    t.start()

    client_socket = socket.socket()
    client_socket.connect((SIGNALING_SERVER_IP,SIGNALING_SERVER_PORT))
    recv_send = recvSend(client_socket,None)

    recv_send.send_with_size(DH_START)
    from_server = recv_send.recv_by_size().decode()

    if from_server != DH_MSG:
        print("Error in from_server")

    dh_client = DH()
    key = dh_client.dhp_key_exchange_client(recv_send)
    print("key from client: ",key)

    recv_send = recvSend(client_socket,key)
    find_room(recv_send,ip,port)

    data = recv_send.recv_by_size().decode()
    data_lst = data.split(DELIMITER)

    print("the other ip:",data_lst[2],"port ext: ",data_lst[1])
    hole_punching_func(udp_socket,data_lst[2],data_lst[1])







if __name__ == "__main__":
    main()