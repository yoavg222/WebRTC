import socket

from stun_client import stun_request
from tcp_by_size import recvSend
from constant import SIGNALING_SERVER_IP,DH_START,DH_MSG,ROOM_REQUEST,DELIMITER,IP_PORT_EXT_MSG
from DH_class import DH



def find_room(recv_send_crypt,ip,port):

    room_client = input("Enter the room you want to connect with: ")
    room_request = ROOM_REQUEST +room_client
    recv_send_crypt.send_with_size(room_request)

    to_send_ip_port_ext = IP_PORT_EXT_MSG + DELIMITER + str(ip) + DELIMITER + str(port)
    recv_send_crypt.send_with_size(to_send_ip_port_ext)



def main():

    ip,port,is_full_cone_nat  = stun_request()
    print()
    print("---------------------------------")
    print("ip :", ip ," port : ",port," is_full_cone_nat :",is_full_cone_nat)


    client_socket = socket.socket()
    client_socket.connect((SIGNALING_SERVER_IP,12345))
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








if __name__ == "__main__":
    main()