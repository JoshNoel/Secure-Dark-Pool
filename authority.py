#!/bin/python3 from xmlrpc.server import SimpleXMLRPCServer
from xmlrpc.server import SimpleXMLRPCRequestHandler, SimpleXMLRPCServer
from random import shuffle
import threading
import socket
import multiprocessing as mp
import time
import random
import itertools
import pool_types

AVAIL_PORTS = range(8001, 8010)
REGISTRATION_PERIOD_LEN = 15    # Time on key-refresh where new clients can join pool
KEY_REFRESH_INTERVAL = 300      # Length of single key-cycle

# Structure definitions
#   outstanding_trade: (offering_client_id, pallier_ciphers)

class CARequestHandler(SimpleXMLRPCRequestHandler):
    rpc_paths = ('/')

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

        trade_id = random.randint()
        cur_trades[trade_id] = (client_id, ciphers)
        return trade_id

    @staticmethod
    def _post_pallier_keys(client_pub_key, pall_cntr, pall_lock, pall_dict, pall_keys):
        """
        pall_keys is dict of form {pub_key: (PALL_PK, ENC(PALL_SK))}, where PALL_SK encrypted with pub_key.
        This function adds the keys to the shared dictionary, pall_dict.
        """
        key_store.add_pal_keys(pall_keys)
        with pall_lock:
            for pub_key, pair in pall_keys.items():
                if pub_key not in pall_dict:
                    pall_dict[pub_key] = {}
                pall_dict[pub_key][client_pub_key] = pair

            pall_cntr -= 1

        return True

    @staticmethod
    def _query_pall_pairs(pub_key, pall_dict):
        """
        Returns: {other_client_pub_key: pall_pair} where the pallier key pairs are those generated by other clients to communicate
        with this client
        """
        if pall_cntr > 0:
            return False
        return pall_dict[pub_key]

    @staticmethod
    def process_requests(client_id, pub_key, port, refresh_q, trades, num_clients, start_event, gen_pall_list,
                         pall_key_cntr, pall_key_lock, pall_dict):
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
        host = socket.gethostname()
        sock_server.bind((host, port))
        sock_server.listen(1)
        sock_client, addr = sock_server.accept()

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
            b = sock_client.recv(1024)
            msg = json.loads(b.decode('utf-8'))
            method = msg['method']
            params = msg['params']
            
            res = b'0'
            if method == 'post_pall_keys':
                res = _post_pallier_keys(pub_key, pall_key_cntr, pall_key_lock, pall_dict, *params)
            elif method == 'query_pall_keys':
                res = _query_pall_pairs(pall_dict, pub_key)
            if method == 'post_trade':
                res = _post_trade(pub_key, num_clients, trades, *params)
            elif method == 'del_trade':
                res = _del_trade(*params)
            else:
                res = bytes(AUTH_INVALID_METHOD_ERR)

            sock_client.send(json.dumps(res).encode('utf-8'))

class KeyStore:
    def __init__(self):
        self._rsa_keys = {}

    def add_rsa_key(self, key):
        """
        Adds RSA public key to the store. Returns random id for key
        """
        i = random.randint()
        self._rsa_keys[i] = key
        return i

    def get_rsa_list(self):
        """
        Returns current public key list in randomized order
        """
        return shuffle(_rsa_keys.values())

    def num_keys(self):
        return len(self._rsa_keys)

class CentralAuthority:
    """
    Holds outside interface for clients to interact with server. On registration opens socket connection to client in
    subsubprocess. Functions exposed through _dispatch.
    """
    #TODO: Use user id for secure socket reconnection
    def __init__(self):
        self.manager = mp.Manager()
        self.ticker_map = {"APPL": 1} #TODO: Load tickers and generate map
        self.open_ports = AVAIL_PORTS
        self.key_store = KeyStore()
        self.refresh_thread = threading.Timer(KEY_REFRESH_INTERVAL, self.key_refresh)
        self.start_clients_thread = threading.Timer(REGISTRATION_PERIOD_LEN, self.start_clients)
        self.timer_start = time.time()

        self.clients = {} # Holds (client_id, refresh_q) Where refresh_q is a mp Queue for passing key refresh messages
        self.cur_trades = self.manager.dict() # Shared memory dict among all client handler processes

        self.pall_key_gen = {} # Holds the dict generated by gen_pall_pairs(). Once complete this is sent to each client

        # Holds the pallier key pairs that need to be sent to client_id of rsa_pub_key as pallier pair was created by other client in the pair
        self.pall_keys = {} # {recipient_pub_key: (sender_id, (PALL_PK, ENC(PALL_SK))... } 

        self.reg_done = False
        self.start_event = mp.Event() # Event to notify clients that registration period is over, and pal_key_gen is correct
        self.pall_gen_sem = mp.Semaphore() #Semaphore to block client handlers until all pallier keys generated

    def gen_pall_pairs(self):
        """
        For every client generates list of other clients for which it should generate their pallier pair.
        Sets self.pall_key_gen to dict of form {client_id: [pub_keys]} where pub_keys is a list of other client's RSA public keys it should generate
        pallier key for
        """
        #TODO: Ensure even split of key generation across clients
        assert self.reg_done
        res = {}
        for pair in itertools.combinations(self.clients.keys(), 2):
            g = random.randint(0,1)
            gen_client = pair[g]
            rec_client = pair[g ^ 1]
            res[gen_client].append(self.key_store.get_rsa_list[rec_client])

        self.pall_key_gen.update(res)
        self.start_event.set()

    def start_clients(self):
        """
        Starts all client processes created during registration period through call to 'register'
        """
        self.reg_done = True
        pall_gen_assignment = gen_pall_pairs()
        ctx = mp.get_context('spawn')
        for client_id, info in self.clients.items():
            assigned_port = info[0]
            pub_key = info[1]
            q = mp.Queue()
            # Launches client handler process. daemon=True means client handlers are killed when server process is
            ctx.Process(target=Client.process_requests, args=(client_id, pub_key, assigned_port, q, self.cur_trades,
                        self.key_store.num_keys, self.start_event, self.pall_key_gen[client_id], self.pall_gen_sem), daemon=True).start()


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
        if len(self.open_ports) == 0:
            return AUTH_POOL_FULL, -1, -1
        if not start_clients_thread.is_alive():
            if reg_done:
                return AUTH_OUTSIDE_REG_PERIOD, -1, -1
            else:
                start_clients_thread.start()
                refresh_thread.start()

        client_id = self.key_store.add_key(pub_key)

        i = random.randrange(0,len(self.open_ports))
        assigned_port = self.open_ports[i]
        del self.open_ports[i]

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
        if reg_done:
            return self.key_store.get_key_list()
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
        elif method == 'query_pall_pairs':
            return self.query_pall_pairs(*params)
        else:
            return AUTH_INVALID_METHOD_ERR

class Server:
    def __init__(self, name, port):
        self.server = SimpleXMLRPCServer((name, port), requestHandler=CentralAuthority)
        self.server.register_introspection_functions()

        self.server.register_instance(CentralAuthority())
    def run(self):
        # Run the server's main loop
        self.server.serve_forever()
