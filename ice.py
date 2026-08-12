import asyncio
import socket

from constant import IP_ADDRESS_ALLOWLISTING, SERVER_A, SERVER_B, TURN_IP, TURN_PORT
from stun_client import stun_request, stun_response_parsing
from turn_msg import build_allocate_msg, build_second_allocate_request,parsing_allocate_msg


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

transaction_dic = {"a": [], "b": [], "turn": []}

msg_stun = []
msg_turn = []

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

        asyncio.create_task(self.collect_ice_candidates_send())
        # asyncio.run(self.help_function())



    # async def help_function(self):




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
                print("add: ",addr_append)

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

                self.transport.sendto(allocate_packet, (TURN_IP, TURN_PORT))
                transaction_dic["turn"].append(transaction_id)

            else:
                print(msg_turn[0])
                self.transport.sendto(msg_turn[0][0], (TURN_IP, TURN_PORT))
                transaction_dic["turn"].append(msg_turn[0][1])

            await asyncio.sleep(2)


    async def ice_framework_send(self):
        pass


    async def ice_framework_recv(self):
        pass


    def signaling_server(self):
        pass



async def run_ice():

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


if __name__ == "__main__":
    asyncio.run(run_ice())