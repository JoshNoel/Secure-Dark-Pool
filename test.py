from authority import Server
from client_creator import Client
import multiprocessing as mp
import json
import os
import traceback

SERVER_ADDR = "http://localhost"
SERVER_NAME = "localhost"
SERVER_RPC_PORT = 8000

# Sending Pallier keys takes 136 bytes
# RSA-OAESP needs 136+2+2*SHA1DigestSize lambda bits
# lambda bits it multiple of 256 in this case at least 1536
LAMBDA_BITS = 1536

def run_client(test_file):
    client = Client(LAMBDA_BITS, SERVER_NAME, SERVER_RPC_PORT)
    try:
        client.register()
    except Exception as e:
        print("Registration Failed: " + str(e))
        traceback.print_exc()
        client.kill()
        return -1

    test = None
    with open('test_cases/'+test_file) as f:
        test = json.load(f)

    # TODO: Check file format
    client.run_test_case(test)

    client.kill()
    return 0

def run_server():
    server = Server(SERVER_NAME, SERVER_RPC_PORT)
    server.run()

if __name__ == "__main__":
    ctx = mp.get_context('spawn')
    print("Instantiating Server")
    p_server = ctx.Process(name="pool_server", target=run_server, daemon=False)
    p_server.start()

    print("Instantiating Clients")
    client_1 = ctx.Process(name="poll_rpc_client1", target=run_client, args=('trades_1_1.json',), daemon=True)
    client_2 = ctx.Process(name="pool_rpc_client2", target=run_client, args=('trades_1_2.json',), daemon=True)

    print("Running Registration Test")
    client_1.start()
    client_2.start()
    client_1.join()
    client_2.join()
