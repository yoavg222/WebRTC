import asyncio


host_success = False
hole_punching_success = False
turn_external_success = False
turn_success = False

status_dic = {}

class EchoUDPProtocol(asyncio.DatagramProtocol):

    def connection_made(self,transport):
        self.transport = transport




    def datagram_received(self, data, addr):
        pass


    async def try_to_connect(self):
        global status_dic

        pass


async def run_ice(address):
    print("Starting ICE framework")

    loop = asyncio.get_running_loop()
    transport,_ = await loop.create_datagram_endpoint(
        lambda: EchoUDPProtocol(),
        local_addr= address
    )

    try:
        await asyncio.sleep(10)
    finally:
        transport.close()





async def main(ice_candidates,lst_ice_other):

    global status_dic

    lst_addr = [{ice_candidates[0]:lst_ice_other[0]},{ice_candidates[1]:lst_ice_other[1]},{ice_candidates[2]:lst_ice_other[1]},{ice_candidates[2]:lst_ice_other[2]}]

    host_task = run_ice(lst_addr[0])
    hole_punching_task = run_ice(lst_addr[1])
    turn_external_task = run_ice(lst_addr[2])
    turn_task = run_ice(lst_addr[3])

    status_dic[host_task] = host_success
    status_dic[hole_punching_task] = hole_punching_success
    status_dic[turn_external_task] = turn_external_success
    status_dic[turn_task] = turn_success







