#!/bin/python3 from xmlrpc.server import SimpleXMLRPCServer
from xmlrpc.server import SimpleXMLRPCRequestHandler
from random import shuffle
import threading
import socket
import multiprocessing as mp
import time
import random

AVAIL_PORTS = range(8001, 8010)
REGISTRATION_PERIOD_LEN = 15    # Time on key-refresh where new clients can join pool
KEY_REFRESH_INTERVAL = 300      # Length of single key-cycle
MATCHED_TRADE = 0
UNMATCHED_TRADE = -1
INVALID_ARG_ERR = -2
INVALID_METHOD_ERR = -3
POOL_FULL = -4
OUTSIDE_REG_PERIOD = -5

# Structure definitions
#   outstanding_trade: (offering_client_id, pallier_ciphers)

class CARequestHandler(SimpleXMLRPCRequestHandler):
    rpc_paths = ('/register')

class ClientHandler:
    @staticmethod
    def _send_key_refresh(sock_client):
        sock_client.send(b'key_refresh')
    @staticmethod
    def _match_trade(client_id, ciphers, cur_trades):
        for trade_id, outstanding_trade in cur_trades.items():
            offering_client = outstanding_trade[0]
            offering_ciphers = outstanding_trade[1]
            for c in offering_ciphers:
                

    @staticmethod
    def _del_trade(trade_id):
        """
        Deletes trade from outstanding trades list. Call on completion or cancellation.
        Return 0 on success, -1 on failure
        """
        #TODO: Verify deletion with authentication key if trade_id in self.cur_trades: del self.cur_trades[trade_id] return 0 else:
        return INVALID_ARG_ERR


    @staticmethod
    def _post_trade(num_clients, cur_trades, client_id, ciphers):
        """
        Posts given transID list (ciphers) to server, tagged with users id. 
        Server stores list of pallier encrypted ciphertexts corresponding to 
        transaction with every other currently connected client. 
        Returns trade's id on sucess. On invalid ciphers list returns -1
        """
        #TODO: Return authentication key with trade. Use for deletion authentication
        if not isinstance(ciphers, dict) and len(ciphers) == num_clients - 1:
            return INVALID_ARG_ERR
        if _match_trade(client_id, ciphers, cur_trades):
            return MATCHED_TRADE

        trade_id = random.randint()
        cur_trades[trade_id] = (client_id, ciphers)
        return trade_id

    @staticmethod
    def process_requests(client_id, port, refresh_q, trades, num_clients):
        """
        run() method of all ClientHandler processes. Takes in all state necessary to run client.
        """
        sock_server = socket.socket()
        host = socket.gethostname()
        sock_server.bind((host, port))
        sock_server.listen(1)
        sock_client, addr = sock_server.accept()
        while True:
            # Check for key refresh
            if not refresh_q.empty():
                refresh_q.get()
                send_key_refresh(sock_client)

            # Receive message from client and attempt to parse it
            b = sock_client.recv(1024)
            msg = json.loads(b.decode('utf-8'))
            method = msg['method']
            params = msg['params']
            
            res = b'0'
            if method == 'post_trade':
                res = _post_trade(num_keys, trades, *params)
            elif method == 'del_trade':
                res = _del_trade(*params)
            else:
                res = bytes(INVALID_METHOD_ERR)

            sock_client.send(res)

class KeyStore:
    def __init__(self):
        self._rsa_keys = {}
        self._pal_keys = {}

    def add_rsa_key(self, key):
        """
        Adds RSA public key to the store. Returns random id for key
        """
        i = random.randint()
        self._rsa_keys[i] = key
        return i

    def add_pal_key(self, key):
        """
        Adds pallier key pair (plaintext PK, encrypted SK) key to the store. Returns random id for key
        """
        i = random.randint()
        self._rsa_keys[i] = key
        return i


    def get_key_list(self):
        """
        Returns current public key list in randomized order
        """
        return shuffle(_pub_keys.values())

    def num_keys(self):
        return len(self._pub_keys)

class CentralAuthority:
    """
    Holds outside interface for clients to interact with server. On registration opens socket connection to client in
    subsubprocess. Functions exposed through _dispatch.
    """
    #TODO: Use user id for secure socket reconnection
    def __init__(self):
        mp.set_start_method('spawn')
        self.manager = mp.Manager()
        self.ticker_map = {"APPL": 1} #TODO: Load tickers and generate map
        self.clients = {} # Holds (client_id, refresh_q) Where refresh_q is a mp Queue for passing key refresh messages
        self.open_ports = AVAIL_PORTS
        self.key_store = KeyStore()
        self.refresh_thread = threading.Timer(KEY_REFRESH_INTERVAL, key_refresh)
        self.start_clients_thread = threading.Timer(REGISTRATION_PERIOD_LEN, start_clients)
        self.timer_start = time.time()
        self.refresh_thread.start()
        self.cur_trade_id = MATCHED_TRADE + 1
        # Shared memory dict among all client handler processes
        self.cur_trades = self.manager.dict()

        self.reg_done = False
        self.key_event = mp.Lock() # 

    def start_clients(self):
        """
        Starts all client processes created during registration period through call to 'register'
        """
        for client_id, assigned_port in self.clients.items():
            q = mp.Queue()
            mp.Process(target=Client.process_requests, args=(client_id, assigned_port, q, self.cur_trades,
                        self.key_store.num_keys), daemon=True).start()
        self.reg_done = True


    def key_refresh(self):
        """
        Called every 5 minutes to invalidate public keys
        """
        #TODO: Immediate communication lock on key refresh
        # Reset server state
        self.open_ports = AVAIL_PORTS
        self.key_store.refresh()
        self.cur_trades = {}
        for client_id, q in self.clients.items():
            q.put(1)

        # Restart refresh timer
        self.timer_start = time.time()
        self.refresh_thread = threading.Timer(KEY_REFRESH_INTERVAL, key_refresh)
        self.refresh_thread.start()

    def register(self, pub_key):
        """
        Registers a new client with the central authority. pub_key := (RSA_PK, PALLIER_PK). Stored state is public key and it's corresponding unique ID.
        After receipt of client_id and ticker mapping, client should query_keys until they are given (i.e. reg period is
        over). If they are the pallier generator for this key cycle, they should then post pallier keys over RPC.
        sucess. Server only opens ports once registration period is over.
        Returns: Client uid, assigned port, ticker mapping
        """
        if len(self.open_ports) == 0:
            return POOL_FULL, -1, -1
        client_id = self.key_store.add_key(pub_key)

        i = random.randrange(0,len(self.open_ports))
        assigned_port = self.open_ports[i]
        del self.open_ports[i]

        self.clients[client_id] = assigned_port
        return client_id, assigned_port, self.ticker_map

    def query_refresh_timer(self):
        """
        Returns start of current key expiry interval
        """
        return self.timer_start

    def query_refresh_interval(self):
        return KEY_REFRESH_INTERVAL

    def query_pub_keys(self):
        """
        Returns all current public keys in key store
        """
        return self.key_store.get_key_list()


    def _dispatch(self, method, params):
        if method == 'register':
            return self.register(*params)
        elif method == 'query_refresh_timer':
            return self.query_refresh_timer()
        elif method == 'query_refresh_interval':
            return self.query_refresh_interval()
        elif method == 'query_pub_keys':
            return self.query_keys()
        else:
            return INVALID_METHOD_ERR

# Create server
if __name__ == "__main__":
    server = SimpleXMLRPCServer(("localhost", 8000), requestHandler=CentralAuthority)
    server.register_introspection_functions()

    server.register_instance(CentralAuthority())

    # Run the server's main loop
    server.serve_forever()
