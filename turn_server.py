import asyncio
import time

from constant import TURN_PORT,IP_ADDRESS_ALLOWLISTING
from turn_msg import parsing_allocate_msg,build_allocate_response_error

dic_allocate = {}
dic_to_refresh = {}
dic_nonce = {}
allocate_request_type = b"\x00\x03"
error_response_type = b"\x00\x09"




class EchoUDPProtocol(asyncio.DatagramProtocol):
    def connection_made(self, transport):
        self.transport = transport
        asyncio.create_task(self.clean_dic_to_refresh())
        asyncio.create_task(self.clean_dic_nonce())

    def datagram_received(self, data, addr):
        message = data
        asyncio.create_task(self.handle_msgs(message,addr))


    def check_dic_allocate(self):
        global dic_allocate
        global dic_to_refresh
        global dic_nonce

        pass


    async def handle_allocate_request(self,data,addr):

        global dic_allocate
        global dic_to_refresh
        global dic_nonce


        print("get allocate request from: ",addr)


        transaction_id,lifetime,good_protocol,has_username = parsing_allocate_msg(data)
        print("transaction_id: ",transaction_id," lifetime: ",lifetime," good_protocol: ",good_protocol)


        if not has_username:
            packet,nonce = build_allocate_response_error(transaction_id)
            dic_nonce[addr] = [nonce,time.time]

            self.transport.sendto(packet,addr)



    async def handle_msgs(self,data,addr):

        global dic_allocate
        global dic_to_refresh
        global dic_nonce

        request_type = data[0:2]


        if request_type == allocate_request_type:
            await self.handle_allocate_request(data,addr)



    async def clean_dic_to_refresh(self):
        global dic_allocate
        global dic_to_refresh
        global dic_nonce

        while True:
            await asyncio.sleep(600)

            current_time = time.time()

            to_delete = [user for user,allocation in dic_to_refresh.items() if current_time - allocation["time"][1] > 600]

            for user in to_delete:
                del dic_to_refresh[user]



    async def clean_dic_nonce(self):

        global dic_allocate
        global dic_to_refresh
        global dic_nonce

        while True:
            await asyncio.sleep(300)

            current_time = time.time()

            to_delete = [addr for addr,nonce in dic_nonce.items() if current_time - nonce[1] > 300]

            for addr in to_delete:
                del dic_nonce[addr]




async def run_server():
    print("Starting UDP server")


    loop = asyncio.get_running_loop()
    transport, _ = await loop.create_datagram_endpoint(
        lambda: EchoUDPProtocol(),
        local_addr=(IP_ADDRESS_ALLOWLISTING,TURN_PORT)
    )

    try:
        await asyncio.Future()
    finally:
        transport.close()




if __name__ == "__main__":
    asyncio.run(run_server())