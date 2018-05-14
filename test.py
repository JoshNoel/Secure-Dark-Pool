from authority import Server
from client_creator import Client
import multiprocessing as mp

SERVER_ADDR = "http://localhost"
SERVER_NAME = "localhost"
SERVER_RPC_PORT = 8000

# Sending Pallier keys takes 268 bits
LAMBDA_BITS = 1024

def run_client(test):
        client = Client(LAMBDA_BITS, SERVER_NAME, SERVER_RPC_PORT)

        client.register()
        client.run_test_case(test)

def run_server():
    server = Server(SERVER_NAME, SERVER_RPC_PORT)
    server.run()

if __name__ == "__main__":
    ctx = mp.get_context('spawn')
    print("Instantiating Server")
    p_server = ctx.Process(name="pool_server", target=run_server, daemon=False)
    p_server.start()

    print("Instantiating Clients")
    client_1 = ctx.Process(name="poll_rpc_client", target=run_client, args=(None,), daemon=True)
    client_2 = ctx.Process(name="pool_rpc_client", target=run_client, args=(None,), daemon=True)

    print("Running Registration Test")
    client_1.start()
    client_2.start()
    client_1.join()
    client_2.join()
    p_server.terminate()

    print("Testing Key Exchange...")

