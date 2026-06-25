import threading
import time


def connect_to_peer(udp_socket,remote_peer_tuple):

    hole_punched = threading.Event()
    punch_hole_thread = threading.Thread(target=punch_hole,args = (udp_socket,remote_peer_tuple,hole_punched))
    punch_hole_thread.start()

    msg,addr = udp_socket.recvfrom(1024)
    ip = remote_peer_tuple[0]
    port = int(remote_peer_tuple[1])

    print("msg in connect_to_peer: ",msg.decode())
    udp_socket.sendto("ACK".encode(),(ip,port))

    hole_punched.set()





def punch_hole(peer_socket,remote_peer_tuple,stop_event):
    while not stop_event.wait(1):

        ip = remote_peer_tuple[0]
        port = int(remote_peer_tuple[1])

        peer_socket.sendto("Punch Hole".encode(),(ip,port))

        time.sleep(1)