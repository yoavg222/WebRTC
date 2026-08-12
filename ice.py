import asyncio
import socket

from constant import IP_ADDRESS_ALLOWLISTING, SERVER_A, DH_MSG ,SERVER_B, TURN_IP,TURN_IP_CLIENT,DH_START,TURN_PORT,SIGNALING_SERVER_IP_MAIN_SERVER,SIGNALING_SERVER_IP_MAIN_CLIENT,SIGNALING_SERVER_PORT
from stun_client import stun_request, stun_response_parsing
from turn_msg import build_allocate_msg, build_second_allocate_request,parsing_allocate_msg
from tcp_by_size import recvSend
from DH_class import DH
from signaling_func import create_client_socket_recv_send,find_room
from constant import DELIMITER_BYTES


get_error_response = False
collect_ice_candidates = False
get_answer = False
local_addr = None
local_ip = None
ice_candidates_lst = []
finish_ice_candidates = False
nonce_server = None

found_local = False
found_ext = False
found_turn = False


turn_ip = None
signaling_server_ip = None
fingerprints_algorithm = None
fingerprint = None
other_fingerprint_algorithm = None
other_fingerprint = None

transaction_dic = {"a": [], "b": [], "turn": []}

msg_stun = []
msg_turn = []
lst_ice_other = []






class EchoUDPProtocol(asyncio.DatagramProtocol):



    def connection_made(self, transport):
        global local_addr
        global ice_candidates_lst
        global found_local

        print("connection made")
        self.transport = transport

        addr_allocate = self.transport.get_extra_info("sockname")
        port = addr_allocate[1]
        local_addr = (local_ip, port)
        print("local_addr: ", local_ip)

        ice_candidates_lst.insert(0, local_addr)
        found_local = True

        asyncio.create_task(self.help_function())
        print("here in asyncio.create_task")


    async def help_function(self):
        await asyncio.create_task(self.collect_ice_candidates_send())
        signaling_server_connection_good = self.signaling_server_connection()

        if signaling_server_connection_good:
            pass




    async def ice_frame_work(self):
        pass



    def signaling_server_connection(self):

        global other_fingerprint_algorithm
        global other_fingerprint
        global lst_ice_other


        recv_send,client_socket = create_client_socket_recv_send(signaling_server_ip)

        recv_send.send_with_size(DH_START)
        from_server = recv_send.recv_by_size().decode()

        if from_server != DH_MSG:
            print("Error in from_server")
            return False

        dh_client = DH()
        key = dh_client.dhp_key_exchange_client(recv_send)
        print("key from client: ", key)

        recv_send_crypt = recvSend(client_socket, key)
        find_room(recv_send_crypt,ice_candidates_lst,fingerprints_algorithm,fingerprint)

        port_ip_ex = recv_send_crypt.recv_by_size()
        port_ip_ex_lst = port_ip_ex.split(DELIMITER_BYTES)
        print(port_ip_ex_lst)

        print(port_ip_ex_lst[0])

        type_msg = port_ip_ex_lst[0]
        port_ip_ex_lst.remove(type_msg)

        port1 = int.from_bytes(port_ip_ex_lst[0], byteorder="big")
        port2 = int.from_bytes(port_ip_ex_lst[2], byteorder="big")
        port3 = int.from_bytes(port_ip_ex_lst[4], byteorder="big")

        ip1 = port_ip_ex_lst[1].decode()
        ip2 = port_ip_ex_lst[3].decode()
        ip3 = port_ip_ex_lst[5].decode()

        other_fingerprint_algorithm = port_ip_ex_lst[6].decode()
        other_fingerprint = port_ip_ex_lst[7]

        print("port1: ",port1," port2: ",port2," port3: ",port3)
        print("ip1: ",ip1," ip2: ",ip2," ip3: ",ip3)

        lst_ice_other = [(ip1, port1), (ip2, port2), (ip3, port3)]
        print(lst_ice_other)
        print(ice_candidates_lst)

        other_fingerprint = other_fingerprint
        other_fingerprint_algorithm = other_fingerprint_algorithm

        print("can start the ice framework")

        return True


    def datagram_received(self, data, addr):
        print("datagram_received")

        if not finish_ice_candidates:
            asyncio.create_task(self.collect_ice_candidates_recv(data))



    async def collect_ice_candidates_recv(self, data):

        global msg_stun
        global ice_candidates_lst
        global found_ext
        global get_error_response
        global msg_turn
        global found_turn
        global finish_ice_candidates

        type_data = data[:2]

        if type_data == b"\x01\x01":
            msg_stun.append(data)
            if len(msg_stun) >= 2:
                ip_external_final, port_external_a, is_full_cone_nat = stun_response_parsing(
                    msg_stun[0],
                    transaction_dic["a"][0],
                    msg_stun[1],
                    transaction_dic["b"][0],
                )

                if ip_external_final is None or port_external_a is None or is_full_cone_nat is None:
                    msg_stun.remove(msg_stun[0])
                    msg_stun.remove(msg_stun[1])

                    del transaction_dic["a"][0]
                    del transaction_dic["b"][0]

                elif is_full_cone_nat:
                    ice_candidates_lst.insert(1, (ip_external_final, port_external_a))
                    found_ext = True
                    print("found_ext: ", (ip_external_final, port_external_a))



                else:
                    ice_candidates_lst.insert(1, (None, None))
                    found_ext = True
                    print("symmetrical nat")

        else:
            transaction_id, lifetime, good_protocol, has_username, realm, nonce, message_integrity_client, addr_allocate, expected_reason_phrase, is_error_response = parsing_allocate_msg(
                data)

            if is_error_response:
                get_error_response = True
                msg_turn.append((build_second_allocate_request(nonce)))
            else:
                addr_append = (TURN_IP, addr_allocate[1])
                ice_candidates_lst.insert(2, addr_append)
                print("addr: ",addr_append)

                found_turn = True

                if found_ext and found_turn and found_local:
                    finish_ice_candidates = True



        asyncio.current_task().cancel()
        try:
            await asyncio.current_task()

        except asyncio.CancelledError:
            print("task cancelled")

        finally:
            print("full task cancelled")




    async def collect_ice_candidates_send(self):

        global get_error_response
        global transaction_dic
        global found_ext
        global msg_turn

        while not finish_ice_candidates:


            if not found_ext:
                header, header_b, transaction_id, transaction_id_b = stun_request()

                transaction_dic["a"].append(transaction_id)
                transaction_dic["b"].append(transaction_id_b)

                raw_socket = self.transport.get_extra_info("socket")
                raw_socket = raw_socket._sock


                raw_socket.sendto(header, SERVER_A)
                print(header)
                print("send data: ", header)
                await asyncio.sleep(1)
                raw_socket.sendto(header_b, SERVER_B)
                print("send data: ", header_b)

            if not get_error_response:

                allocate_packet, transaction_id = build_allocate_msg(True)
                print("allocate_packet: ",allocate_packet)

                self.transport.sendto(allocate_packet, (turn_ip, TURN_PORT))
                transaction_dic["turn"].append(transaction_id)

            else:
                print(msg_turn[0])
                self.transport.sendto(msg_turn[0][0], (turn_ip, TURN_PORT))
                transaction_dic["turn"].append(msg_turn[0][1])

            await asyncio.sleep(2)


    async def ice_framework_send(self):
        pass


    async def ice_framework_recv(self):
        pass


    def signaling_server(self):
        pass



async def run_ice(var,fingerprints,fingerprint_algorithm):

    global turn_ip
    global signaling_server_ip
    global fingerprint,fingerprints_algorithm

    fingerprint = fingerprints
    fingerprints_algorithm = fingerprint_algorithm

    if var:
        turn_ip = TURN_IP
        signaling_server_ip = SIGNALING_SERVER_IP_MAIN_SERVER
    else:
        turn_ip = TURN_IP_CLIENT
        signaling_server_ip = SIGNALING_SERVER_IP_MAIN_CLIENT



    global local_addr
    global local_ip
    global ice_candidates_lst

    hostname = socket.gethostname()
    local_ip = socket.gethostbyname(hostname)

    print("local_ip: ", local_ip)

    loop = asyncio.get_running_loop()
    transport, _ = await loop.create_datagram_endpoint(
        lambda: EchoUDPProtocol(), local_addr=(IP_ADDRESS_ALLOWLISTING, 0)
    )

    try:
        await asyncio.Future()

    finally:
        transport.close()