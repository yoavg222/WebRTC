import socket
import threading
import time
from tcp_by_size import recvSend
from DH_class import DH
from constant import DH_START,IP_ADDRESS_ALLOWLISTING,DH_MSG
from constant import IP_PORT_EXT_MSG,DELIMITER,SIGNALING_SERVER_PORT

all_to_die = False
room_users_dic = {}
lock_room_users_dic = threading.Lock()



def find_two_to_room(recv_send_crypt):
    global room_users_dic

    data = recv_send_crypt.recv_by_size().decode()
    print("data in find_two_to_room: ",data)

    data_lst = data.split(DELIMITER)
    print(data_lst)

    port_ip_ex = recv_send_crypt.recv_by_size().decode()
    port_ip_ex_lst = port_ip_ex.split(DELIMITER)
    print(port_ip_ex_lst)

    ip_ex = port_ip_ex_lst[1]
    port_ex = port_ip_ex_lst[2]
    hash_algorithm = port_ip_ex_lst[3]
    fingerprints_value = port_ip_ex_lst[4]

    while True:

        try:
            with lock_room_users_dic:
                user_lst = room_users_dic[data_lst[1]]
                if user_lst[0] != recv_send_crypt:
                    user_lst.append(recv_send_crypt)

            if len(room_users_dic[data_lst[1]]) == 2:
                print("Found two peers in find_two_to_room")
                break

            time.sleep(1)

        except:
            with lock_room_users_dic:
                room_users_dic[data_lst[1]] = [recv_send_crypt]

    print(room_users_dic)

    sock_to_send = recv_send_crypt

    i = 0
    for i in range(2):
        sock_lst = room_users_dic[data_lst[1]]
        if sock_lst[i] != recv_send_crypt:
            sock_to_send = sock_lst[i]
        i+=1


    to_send = IP_PORT_EXT_MSG + DELIMITER + port_ex + DELIMITER + ip_ex + DELIMITER + hash_algorithm + DELIMITER + fingerprints_value
    sock_to_send.send_with_size(to_send)



def handle_client(sock,addr):
    print("New client connect:",addr)

    recv_send = recvSend(sock,None)
    data = recv_send.recv_by_size().decode()
    print(data)

    if data == DH_START:
        dh_server = DH()

        if dh_server.load_from_disk_dh() is None:
            dh_server.upload_to_disk_dh()

        recv_send.send_with_size(DH_MSG)
        key = dh_server.dh_key_exchange_server(recv_send)

        print("key from server: ",key)

        recv_send = recvSend(sock,key)
        find_two_to_room(recv_send)



def main():
    global all_to_die

    server_socket = socket.socket()
    server_socket.bind((IP_ADDRESS_ALLOWLISTING,SIGNALING_SERVER_PORT))
    server_socket.listen(2)

    i = 0
    threads = []

    while True:
        print("signalling server wait...")
        sock,addr = server_socket.accept()
        t = threading.Thread(target=handle_client,args = (sock,addr))

        t.start()
        i+=1
        threads.append(t)

        if i > 1000:
            print("\nMain thread: going down for maintenance")
            break

    all_to_die = True
    print("Main thread: waiting to all clients to die")
    for t in threads:
        t.join()
    server_socket.close()
    print('Bye ...')





if __name__ == "__main__":
    main()