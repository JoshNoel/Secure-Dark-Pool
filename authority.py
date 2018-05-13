#!/bin/python3 from xmlrpc.server import SimpleXMLRPCServer
from xmlrpc.server import SimpleXMLRPCRequestHandler, SimpleXMLRPCServer
from random import shuffle
import threading
import socket
import multiprocessing as mp
import time
import random
import itertools
from pool_types import *
import json
import ast

AVAIL_PORTS = range(8001, 8010)
REGISTRATION_PERIOD_LEN = 5    # Time on key-refresh where new clients can join pool
KEY_REFRESH_INTERVAL = 300      # Length of single key-cycle
MAX_TRADE_ID = 10000
MAX_CLIENT_ID = 10000

# Structure definitions
#   outstanding_trade: (offering_client_id, pallier_ciphers)

class CARequestHandler(SimpleXMLRPCRequestHandler):
    rpc_paths = ('/RPC2')

class ClientHandler:
    @staticmethod
    def _send_key_refresh(sock_client):
        sock_client.send(b'key_refresh')
    @staticmethod
    def _match_trade(client_pub_key, ciphers, cur_trades):
        return True
       # for trade_id, outstanding_trade in cur_trades.items():
       #     offering_client = outstanding_trade[0]
       #     offering_ciphers = outstanding_trade[1]
       #     for c in offering_ciphers:

    @staticmethod
    def _del_trade(trade_id):
        """
        Deletes trade from outstanding trades list. Call on completion or cancellation.
        Return 0 on success, -1 on failure
        """
        #TODO: Verify deletion with authentication key if trade_id in self.cur_trades: del self.cur_trades[trade_id] return 0 else:
        return INVALID_ARG_ERR


    @staticmethod
    def _post_trade(client_pub_key, num_clients, cur_trades, ciphers):
        """
        Posts given transID list (ciphers) to server, tagged with users id. 
        Server stores list of pallier encrypted ciphertexts corresponding to 
        transaction with every other currently connected client. 
        Returns trade's id on sucess. On invalid ciphers list returns -1
        """
        #TODO: Return authentication key with trade. Use for deletion authentication
        if not isinstance(ciphers, dict) and len(ciphers) == num_clients - 1:
            return INVALID_ARG_ERR
        if _match_trade(client_pub_key, ciphers, cur_trades):
            return MATCHED_TRADE

        trade_id = random.randint(0, MAX_TRADE_ID)
        cur_trades[trade_id] = (client_id, ciphers)
        return trade_id

    @staticmethod
    def _post_pallier_keys(client_pub_key, pall_cntr, pall_lock, pall_dict, pall_keys):
        """
        pall_keys is dict of form {pub_key: (PALL_PK, ENC(PALL_SK))}, where PALL_SK encrypted with pub_key.
        This function adds the keys to the shared dictionary, pall_dict.
        """
        with pall_lock:
            for pub_key, pair in pall_keys.items():
                # Since dict keys must be strings when sent as json objects
                pub_key = ast.literal_eval(pub_key)
                d = pall_dict[pub_key]
                d[client_pub_key] = pair
                pall_dict[pub_key] = d
                print("SERVER: added pallier key for (" + str(pub_key) + ", " + str(client_pub_key) + ")")
            pall_cntr.value -= 1

        return AUTH_SUCCESS

    @staticmethod
    def _query_pall_pairs(pub_key, pall_dict, pall_cntr, pall_lock):
        """
        Returns: {other_client_pub_key: pall_pair} where the pallier key pairs are those generated by other clients to communicate
        with this client
        """
        x = 0
        with pall_lock:
            x = pall_cntr.value

        while x > 0:
            print("SERVER: Pall Cntr - " + str(x))
            time.sleep(3)
            x = pall_cntr.value

        print("SERVER: Returning pallier keys for - " + str(pub_key))
        return {str(k): v for k,v in pall_dict[pub_key].items()}

    @staticmethod
    def process_requests(server_name, client_id, pub_key, port, refresh_q, trades, num_clients, 
                         start_event, gen_pall_list, pall_key_cntr, pall_key_lock, pall_dict):
        """
        run() method of all ClientHandler processes. Takes in all state necessary to run client.
        client_id: id of client that process is responsible for. Known only by the owner client.
        pub_key: The client's public key. The exposed identity on any client communication. Used to forward pallier keys
        port: server port assigned to client during registration
        refresh_q: Multiprocessing queue to which server pushed '1' to notify all clientHandler's of key refresh
        trades: Shared trades dict that holds all outstanding trades. Used for matching and posting trades
        num_clients: Holds number of clients in current registration period
        start_event: All client handler's wait for this event to indicate end of registration period
        gen_pall_list: list of public keys generated by server for which client must generate pallier keys
        pall_key_cntr: Shared integer that ensures all clients post pallier keys before any can query
        pall_key_lock: Used to ensure atomicity of pall_key_cntr
        pall_dict: shared memory dictionary into which all clientHandler's store the posted pallier pairs
        """
        sock_server = socket.socket()
        host = server_name
        print("SERVER: host = " + str(host))
        sock_server.bind((host, port))
        sock_server.listen(1)
        print("SERVER: listening for client " + str(client_id))
        sock_client, addr = sock_server.accept()
        print("SERVER: client " + str(client_id) + " connected")

        # Issue pallier generation request
        start_event.wait()

        msg_gen_pall = {'method': 'gen_pall', 'params': gen_pall_list}
        sock_client.send(json.dumps(msg_gen_pall).encode('utf-8'))

        # Now loop to accept trade requests
        while True:
            # Check for key refresh
            if not refresh_q.empty():
                refresh_q.get()
                send_key_refresh(sock_client)

            # Receive message from client and attempt to parse it
            b = sock_client.recv(4096)
            if b == b'':
                continue
            msg = json.loads(b.decode('utf-8'))
            print("SERVER: Recieved Message - " + str(msg))
            method = msg['method']
            params = msg['params']
           
            if method == 'post_pall_keys':
                res = ClientHandler._post_pallier_keys(pub_key, pall_key_cntr, pall_key_lock, pall_dict, *params)
            elif method == 'query_pall_keys':
                res = ClientHandler._query_pall_pairs(pub_key, pall_dict, pall_key_cntr, pall_key_lock)
            elif method == 'post_trade':
                res = ClientHandler._post_trade(pub_key, num_clients, trades, *params)
            elif method == 'del_trade':
                res = ClientHandler._del_trade(*params)
            else:
                res = AUTH_INVALID_METHOD_ERR

            sock_client.send(json.dumps(res).encode('utf-8'))

class KeyStore:
    def __init__(self):
        self._rsa_keys = {}

    def add_rsa_key(self, key):
        """
        Adds RSA public key to the store. Returns random id for key
        """
        # FIXME: Need to expand client id space
        i = random.randint(0, MAX_CLIENT_ID)
        self._rsa_keys[i] = key
        print("SERVER: id = " + str(i) + ", key = " + str(self._rsa_keys[i]))
        return i

    def get_rsa_list(self):
        """
        Returns current public key list in randomized order
        """
        l = list(self._rsa_keys.values())
        random.shuffle(l)
        return l

    def serv_get_rsa(self):
        """
        Returns raw dictionary. Only for internal server use. client_id keys should be kept secret
        """
        return self._rsa_keys

    def num_keys(self):
        return len(self._rsa_keys)

class CentralAuthority:
    """
    Holds outside interface for clients to interact with server. On registration opens socket connection to client in
    subsubprocess. Functions exposed through _dispatch.
    """
    #TODO: Use user id for secure socket reconnection
    def __init__(self, server_name):
        self.server_name = server_name
        self.manager = mp.Manager()
        self.ticker_map = {"APPL": 1} #TODO: Load tickers and generate map
        self.open_ports = list(AVAIL_PORTS)
        self.key_store = KeyStore()
        self.refresh_thread = threading.Timer(KEY_REFRESH_INTERVAL, self.key_refresh)
        self.start_clients_thread = threading.Timer(REGISTRATION_PERIOD_LEN, self.start_clients)
        self.timer_start = time.time()

        self.clients = {} # Holds (client_id, refresh_q) Where refresh_q is a mp Queue for passing key refresh messages
        self.cur_trades = self.manager.dict() # Shared memory dict among all client handler processes

        self.pall_key_gen = {} # Holds the dict generated by gen_pall_pairs(). Once complete this is sent to each client

        # Holds the pallier key pairs that need to be sent to client_id of rsa_pub_key as pallier pair was created by other client in the pair
        self.pall_keys = self.manager.dict() # {recipient_pub_key: (sender_id, (PALL_PK, ENC(PALL_SK))... } 

        self.reg_done = False
        self.start_event = mp.Event() # Event to notify clients that registration period is over, and pal_key_gen is correct

        self.pall_key_cntr = self.manager.Value('i', 0, lock=False)
        self.pall_key_lock = mp.Lock()

    def gen_pall_pairs(self):
        """
        For every client generates list of other clients for which it should generate their pallier pair.
        Sets self.pall_key_gen to dict of form {client_id: [pub_keys]} where pub_keys is a list of other client's RSA public keys it should generate
        pallier key for
        """
        #TODO: Ensure even split of key generation across clients
        assert self.reg_done
        res = {k: list() for k in self.clients.keys()}
        for pair in itertools.combinations(self.clients.keys(), 2):
            g = random.randint(0,1)
            gen_client = pair[g]
            rec_client = pair[g ^ 1]
            res[gen_client].append(self.key_store.serv_get_rsa()[rec_client])

        print("SERVER: pall_key_gen = " + str(res))
        self.pall_key_gen.update(res)
        self.start_event.set()

    def start_clients(self):
        """
        Starts all client processes created during registration period through call to 'register'
        """
        self.reg_done = True
        self.pall_key_cntr.value = len(self.clients)
        for key in self.key_store.get_rsa_list():
            self.pall_keys[key] = {}

        pall_gen_assignment = self.gen_pall_pairs()
        ctx = mp.get_context('spawn')
        for client_id, info in self.clients.items():
            assigned_port = info[0]
            pub_key = info[1]
            q = mp.Queue()
            # Launches client handler process. daemon=True means client handlers are killed when server process is
            ctx.Process(target=ClientHandler.process_requests, name="pool_client", args=(self.server_name, client_id, 
                        pub_key, assigned_port, q, self.cur_trades, self.key_store.num_keys, 
                        self.start_event, self.pall_key_gen[client_id], self.pall_key_cntr,
                        self.pall_key_lock, self.pall_keys), daemon=True).start()


    def key_refresh(self):
        """
        Called every 5 minutes to invalidate public keys
        """
        #TODO: Immediate communication lock on key refresh
        # Reset server state
        self.open_ports = AVAIL_PORTS
        self.key_store.refresh()
        self.cur_trades = {}
        for client_id, refresh_q in self.clients.items():
            refresh_q.put(1)

        # Restart refresh timer
        self.timer_start = time.time()
        self.refresh_thread = threading.Timer(KEY_REFRESH_INTERVAL, key_refresh)
        self.refresh_thread.start()
        self.start_event.clear()

    def register(self, pub_key):
        """
        Registers a new client with the central authority. pub_key := (RSA_PK, PALLIER_PK). Stored state is public key and it's corresponding unique ID.
        After receipt of client_id and ticker mapping, client should query_keys until they are given complete RSA public key
        list (i.e. reg period is over). All clients then receive message from server after connecting containing list of
        RSA public keys they should generate pallier keys for. Server only starts client handlers once registration period is over.
        Returns: Client uid, assigned port, ticker mapping. Check client_uid >= 0 for error code
        """
        pub_key = tuple(json.loads(pub_key))
        if len(self.open_ports) == 0:
            return AUTH_POOL_FULL, -1, -1
        if not self.start_clients_thread.is_alive():
            if self.reg_done:
                return AUTH_OUTSIDE_REG_PERIOD, -1, -1
            else:
                self.start_clients_thread.start()
                self.refresh_thread.start()

        client_id = self.key_store.add_rsa_key(pub_key)
        assigned_port = random.choice(self.open_ports)
        self.open_ports.remove(assigned_port)

        self.clients[client_id] = (assigned_port, pub_key)
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
        if self.reg_done:
            x = json.dumps(self.key_store.get_rsa_list())
            return x
        else:
            return AUTH_IN_REG_PERIOD

    
    def _dispatch(self, method, params):
        if method == 'register':
            return self.register(*params)
        elif method == 'query_refresh_timer':
            return self.query_refresh_timer()
        elif method == 'query_refresh_interval':
            return self.query_refresh_interval()
        elif method == 'query_pub_keys':
            return self.query_pub_keys()
        else:
            return AUTH_INVALID_METHOD_ERR

class Server:
    def __init__(self, name, port):
        self.server = SimpleXMLRPCServer((name, port), requestHandler=CARequestHandler)
        self.server.register_introspection_functions()

        self.server.register_instance(CentralAuthority(name))
    def run(self):
        # Run the server's main loop
        self.server.serve_forever()
