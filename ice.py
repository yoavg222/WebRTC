import asyncio
import socket

from constant import IP_ADDRESS_ALLOWLISTING, SERVER_A, DH_MSG ,SERVER_B, TURN_IP,TURN_IP_CLIENT,DH_START,TURN_PORT,SIGNALING_SERVER_IP_MAIN_SERVER,SIGNALING_SERVER_IP_MAIN_CLIENT,SIGNALING_SERVER_PORT
from stun_client import stun_request,build_use_candidate,stun_response_parsing,binding_response_parsing,parsing_binding_request_build_request_response
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
selected_addr = None
found_local = False
found_ext = False
found_turn = False
get_host = False
get_hole_punching = False
get_turn_ext = False
get_turn = False
is_control = None
finish = False
turn_ip = None
signaling_server_ip = None
fingerprints_algorithm = None
fingerprint = None
other_fingerprint_algorithm = None
other_fingerprint = None
pairs = []
transaction_dic = {"a": [], "b": [], "turn": []}
msg_stun = []
msg_turn = []
lst_ice_other = []
ice_candidates = []
priority_success = []
transaction_id_lst = []
future = None

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




    def datagram_received(self, data, addr):
        print("datagram_received")

        if not finish_ice_candidates:
            asyncio.create_task(self.collect_ice_candidates_recv(data))

        else:
            asyncio.create_task(self.ice_framework_recv(data,addr))


    async def help_function(self):

        global selected_addr
        global future


        await asyncio.create_task(self.collect_ice_candidates_send())
        signaling_server_connection_good = self.signaling_server_connection()

        if signaling_server_connection_good:

            task1 = asyncio.create_task(self.ice_framework_send())
            task2 =  asyncio.create_task(self.timer_ice_frame_work())

            await task1
            await task2

            print("selected_addr: ",selected_addr)

            if future is not None:
                future.set_result((selected_addr,self.transport,other_fingerprint_algorithm,other_fingerprint))





    async def timer_ice_frame_work(self):

        global finish

        await asyncio.sleep(8)
        finish = True



    async def ice_framework_send(self):

        global get_host
        global get_hole_punching
        global get_turn_ext
        global get_turn
        global selected_addr


        need_await = False
        current_priority = None
        need_break = False

        while True:

            if need_break:
                break

            if need_await:
                await asyncio.sleep(0.5)

            for ice_candidate in pairs:

                if ice_candidate["is_success"]:
                    print("success")
                    if ice_candidate["priority"] > 0:
                        if current_priority is not None:
                            if ice_candidate["priority"] > current_priority:
                                need_break = True
                                break

                            else:
                                current_priority = ice_candidate["priority"]
                                selected_addr = ice_candidate["remote"]

                        else:
                            selected_addr = ice_candidate["remote"]
                            current_priority = ice_candidate["priority"]
                            need_await = True
                            break

                    else:
                        selected_addr = ice_candidate["remote"]
                        need_break = True
                        break


                request,transaction_id = stun_request(False)
                ice_candidate["current_transaction_id"].append(transaction_id)
                self.transport.sendto(request,ice_candidate["remote"])

                await asyncio.sleep(0.02)

        if is_control:
            while not finish:
                packet,transaction_id = build_use_candidate()
                self.transport.sendto(packet,selected_addr)
                transaction_id_lst.append(transaction_id)

                await asyncio.sleep(0.03)




    async def ice_framework_recv(self,data,addr):

        global priority_success
        global finish
        global selected_addr

        is_good,transaction_id = binding_response_parsing(data)
        print("transaction_id: ",transaction_id)

        if is_good:
            if transaction_id in transaction_id_lst:
                finish = True
                selected_addr = addr


            for ice_candidate in pairs:
                if transaction_id in ice_candidate["current_transaction_id"]:
                    ice_candidate["is_success"] = True
                    priority_success.append(ice_candidate)
                    break

        elif not is_good:
            response = parsing_binding_request_build_request_response(data)
            self.transport.sendto(response,addr)

        else:
            response = parsing_binding_request_build_request_response(data)
            self.transport.sendto(response,addr)
            selected_addr = addr


    def signaling_server_connection(self):

        global other_fingerprint_algorithm
        global other_fingerprint
        global lst_ice_other
        global ice_candidates
        global pairs

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


        priority = 0
        for candidate in ice_candidates_lst:
            for other_candidate in lst_ice_other:
                pairs.append({
                    "local":candidate,
                    "remote":other_candidate,
                    "current_transaction_id":[],
                    "priority":priority,
                    "is_success":False
                })

                priority += 1

        pairs.sort(key=lambda item: item["priority"])
        other_fingerprint = other_fingerprint
        other_fingerprint_algorithm = other_fingerprint_algorithm

        print("can start the ice framework")

        return True





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
                header, header_b, transaction_id, transaction_id_b = stun_request(True)

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



async def run_ice(var,fingerprints,fingerprint_algorithm):

    global turn_ip
    global signaling_server_ip
    global fingerprint,fingerprints_algorithm
    global is_control
    global local_addr
    global local_ip
    global ice_candidates_lst
    global future

    fingerprint = fingerprints
    fingerprints_algorithm = fingerprint_algorithm

    if var:
        turn_ip = TURN_IP
        signaling_server_ip = SIGNALING_SERVER_IP_MAIN_SERVER
        is_control = var


    else:
        turn_ip = TURN_IP_CLIENT
        signaling_server_ip = SIGNALING_SERVER_IP_MAIN_CLIENT
        is_control = var




    hostname = socket.gethostname()
    local_ip = socket.gethostbyname(hostname)

    print("local_ip: ", local_ip)

    loop = asyncio.get_running_loop()
    future = loop.create_future()
    transport, _ = await loop.create_datagram_endpoint(
        lambda: EchoUDPProtocol(), local_addr=(IP_ADDRESS_ALLOWLISTING, 0)
    )

    try:
        result = await future

        addr = result[0]
        new_sock = result[1]
        other_algorithm = result[2]
        fingerprint = result[3]

        new_sock = new_sock.get_extra_info("socket")
        new_sock = new_sock._sock

        return addr,new_sock,is_control,other_algorithm,fingerprint


    except:
        return False,False