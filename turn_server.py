import asyncio
import time

from constant import TURN_PORT,IP_ADDRESS_ALLOWLISTING,REALM
from turn_msg import parsing_allocate_msg,build_allocate_response_error,hmac_sha1,build_allocate_request_success
from sqlalchemy import Table,Column,MetaData,String
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy import select

dic_allocate = {}
dic_to_refresh = {}
dic_nonce = {}
dic_long_term_credentials = {}

allocate_request_type = b"\x00\x03"
error_response_type = b"\x00\x09"


meta = MetaData()
users_table = Table(
    "users",
    meta,
    Column("username",String,nullable=True,unique=True),
    Column("password",String,nullable=True)
)


engine = create_async_engine(
    "sqlite+aiosqlite:///sample.db",
    echo = True
)



class EchoUDPProtocol(asyncio.DatagramProtocol):
    def connection_made(self, transport):
        self.transport = transport
        asyncio.create_task(self.clean_dic_to_refresh())
        asyncio.create_task(self.clean_dic_nonce())


    def datagram_received(self, data, addr):
        message = data
        asyncio.create_task(self.handle_msgs(message,addr))


    def check_message_integrity(self,message_integrity,user_tuple):

        username = user_tuple[0]
        password = user_tuple[1]

        print("username: ",username," password: ",password)

        check = hmac_sha1(REALM,username,password)

        if check == message_integrity:
            return True
        else:
            return False



    async def handle_allocate_request(self,data,addr):

        global dic_allocate
        global dic_to_refresh
        global dic_nonce


        print("get allocate request from: ",addr)


        transaction_id, lifetime, good_protocol, has_username, realm, nonce, message_integrity_client, addr_allocate, expected_reason_phrase, is_error_response = parsing_allocate_msg(data)
        print("transaction_id: ",transaction_id," lifetime: ",lifetime," good_protocol: ",good_protocol)


        if has_username == "":
            packet,nonce = build_allocate_response_error(transaction_id)
            dic_nonce[addr] = [nonce,time.time]
            dic_long_term_credentials[addr] = [nonce,True]
            self.transport.sendto(packet,addr)

        else:
            print("get second response")
            print("transaction_id: ", transaction_id, " lifetime: ", lifetime, " good_protocol: ", good_protocol," username: ",has_username," realm: ",realm," nonce: ",nonce," message_integrity: ",message_integrity_client)

            try:
                if dic_long_term_credentials[addr][0] == nonce:
                    print("you can continue")
                else:
                    asyncio.current_task().cancel()
                    try:
                         await asyncio.current_task()

                    except asyncio.CancelledError:
                        print("task cancelled")

                    finally:
                        print("full task cancelled")

                try:
                    async with engine.connect() as conn:
                        statement = select(users_table).where(
                            users_table.c.username == has_username.decode()
                        )

                        result = await conn.execute(statement)
                        result = result.all()[0]


                        check = self.check_message_integrity(message_integrity_client,result)

                        if check:

                            try:
                                addr_allocate = dic_allocate[addr][0]
                                packet = build_allocate_request_success(transaction_id, result, addr_allocate)
                                self.transport.sendto(packet, addr)


                            except KeyError:
                                loop = asyncio.get_running_loop()

                                transport, _ = await loop.create_datagram_endpoint(
                                    lambda: EchoUDPProtocol(),
                                    local_addr=(IP_ADDRESS_ALLOWLISTING, 0)
                                )
                                addr_allocate = transport.get_extra_info("sockname")
                                print("addr allocate: ",addr_allocate)


                                dic_allocate[addr] = (addr_allocate,transport)
                                packet = build_allocate_request_success(transaction_id,result,addr_allocate)
                                self.transport.sendto(packet,addr)

                            else:
                                asyncio.current_task().cancel()
                                try:
                                    await asyncio.current_task()

                                except asyncio.CancelledError:
                                    print("task cancelled")

                                finally:
                                    print("full task cancelled")


                    await engine.dispose()

                except:
                    asyncio.current_task().cancel()
                    try:
                        await asyncio.current_task()

                    except asyncio.CancelledError:
                        print("task cancelled")

                    finally:
                        print("full task cancelled")


            except:
                asyncio.current_task().cancel()
                try:
                    await asyncio.current_task()

                except asyncio.CancelledError:
                    print("task cancelled")

                finally:
                    print("full task cancelled")





    async def handle_msgs(self,data,addr):

            global dic_allocate
            global dic_to_refresh
            global dic_nonce

            request_type = data[0:2]

            if request_type == allocate_request_type:
                await self.handle_allocate_request(data, addr)


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

            to_delete = [addr for addr,nonce in dic_nonce.items() if current_time - nonce[0] > 300]

            for addr in to_delete:
                del dic_nonce[addr]




async def run_server():
    print("Starting UDP server")


    async with engine.begin() as conn:
        await conn.run_sync(meta.create_all)

        statement = select(users_table).where(
            users_table.c.username == "yoav"
        )

        result = await conn.execute(statement)
        result = result.all()

        if not result:
            print("in db")
            await conn.execute(
                users_table.insert(),[
                    {"username":"yoav","password":"yoav2202"},
                    {"username": "uri", "password": "1804"}
                ]
            )

    await engine.dispose()
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