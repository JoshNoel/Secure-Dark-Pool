from authority import Server
import client_creator
import multiprocessing as mp

SERVER_ADDR = "http://localhost"
SERVER_NAME = "localhost"
SERVER_RPC_PORT = 8000

def run_client_test(client, test):
    client.register()
    client.run_test_case(test)


if __name__ == "__main__":
    print("Instantiating Server")
    server = Server(SERVER_NAME, SERVER_RPC_PORT)
    server.run()

    print("Instantiating Clients")
    client_1 = Client(SERVER_ADDR, SERVER_RPC_PORT)
    client_2 = Client(SERVER_ADDR, SERVER_RPC_PORT)

    print("Running Registration Test")
    p_client_1 = mp.Process(target=run_client_test, args=(client_1, None))
    p_client_2 = mp.Process(target=run_client_test, args=(client_2, None))
    p_client_1.start()
    p_client_2.start()

    print("Testing Key Exchange...")

