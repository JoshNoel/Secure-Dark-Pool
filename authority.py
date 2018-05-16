#!/bin/python3 
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
import pickle
import sys
from Crypto.Random import random
import struct

AVAIL_PORTS = range(8001, 8010)
REGISTRATION_PERIOD_LEN = 7    # Time on key-refresh where new clients can join pool
KEY_REFRESH_INTERVAL = 300      # Length of single key-cycle
MAX_TRADE_ID = 10000
MAX_CLIENT_ID = 10000
MATCH_WAIT_TIME = 2

# Structure definitions
#   outstanding_trade: (offering_client_id, pallier_ciphers)

def generate_tickers():
    #TODO: Load ticker list and dynamically generate tickers
    tickers = {
        "APPL": 1,
        "MSFT": 2}
    return tickers

class CARequestHandler(SimpleXMLRPCRequestHandler):
    rpc_paths = ('/RPC2')

class ClientHandler(mp.Process):
    def _send_message(self, message):
        send_msg = pickle.dumps(message)
        length = struct.pack('!I', len(send_msg))
        send_msg = length + send_msg
        self.sock.send(send_msg)
        #self.sock_client.send(pickle.dumps(message))

    def _handle_msg(self, msg):
        if msg['type'] == 'refresh':
            self.send_message(msg)
        elif msg['type'] == 'table':
            self.matched_items['table'] = msg['data']
        elif msg['type'] == 'c':
            self.matched_items['c'] = msg['data']
        elif msg['type'] == 'notify_vol':
            self.matched_items['notify_vol'] = msg['data']
        elif msg['type'] == 'min_vol':
            self.matched_items['min_vol'] = msg['data']

    def _wait_item(self, item_name):
        while True:
            msg = self.comm_q.get()
            if msg['type'] == 'refresh':
                self._send_message(msg)
            elif msg['type'] == item_name:
                return msg['data']
            else:
                return AUTH_MISTYPED_MSG

    def _send_table(self, other_pub_key, trade_ids, table):
        self.matched_pub = other_pub_key
        self.comm_qs[other_pub_key].put({"type": "table", "data": table})
        if self.matched_items["table"] is not None:
            x = self.matched_items["table"]
            self.matched_items["table"] = None
            return x
        return self._wait_item("table")

    def _send_c(self, c):
        self.comm_qs[self.matched_pub].put({"type": "c", "data": c})
        if self.matched_items["c"] is not None:
            x = self.matched_items["c"]
            self.matched_items["c"] = None
            return x
        return self._wait_item("c")

    def _nofify_vol(self, cipher):
        self.comm_qs[self.matched_pub].put({"type": "notify_vol", "data": cipher})
        if self.matched_items["notify_vol"] is not None:
            x = self.matched_items["notify_vol"]
            self.matched_items["notify_vol"] = None
            return x
        return self._wait_item("notify_vol")

    def _send_min_vol(self, cipher):
        self.comm_qs[self.matched_pub].put({"type": "min_vol", "data": cipher})
        if self.matched_items["min_vol"] is not None:
            x = self.matched_items["min_vol"]
            self.matched_items["min_vol"] = None
            return x
        self.matched_pub = None
        return self._wait_item("min_vol")

    def _query_trades(self):
        for trade_id, ciphers in self.cur_trades[self.client_id]['original'].items():
            self._match_trade(trade_id, ciphers)

        return self.cur_trades[self.client_id]['computed']

    def _match_trade(self, trade_id, ciphers):
        d = None
        view = None
        with self.pall_lock:
            view = self.cur_trades[self.client_id]
            if trade_id not in view['computed']:
                view['computed'][trade_id] = {}

            d = view['computed'][trade_id]
        for client_id, t in self.cur_trades.items():
            if client_id == self.client_id:
                continue
            for other_trade_id, other_cipher_dict in t['original'].items():
                pall_pub = self.pall_dict[self.client_pub_key][self.pub_key_dict[client_id]][0]
                hidden_and_encrypted = other_cipher_dict[self.client_pub_key] + ciphers[self.pub_key_dict[client_id]]
                #hidden_and_encrypted *= EncodedNumber.encode(pall_pub, pall_pub.get_random_lt_n())
                hidden_and_encrypted *= random.randint(-pall_pub.n//3, pall_pub.n//3)
                d[other_trade_id] = (self.pub_key_dict[client_id], hidden_and_encrypted)

        with self.pall_lock:
            view['computed'][trade_id] = d
            self.cur_trades[self.client_id] = view


    def _del_trade(self, trade_id):
        """
        Deletes trade from outstanding trades list. Call on completion or cancellation.
        Return 0 on success, -1 on failure
        """
        with self.pall_lock:
            t = self.cur_trades[self.client_id]
            del t['original'][trade_id]
            del t['computed'][trade_id]
            self.cur_trades[self.client_id] = t
            self.num_outstanding.value -= 1
        return AUTH_SUCCESS

    def _post_trade(self, ciphers):
        """
        Posts given transID list (ciphers) to server, tagged with users id. 
        Server stores list of pallier encrypted ciphertexts corresponding to 
        transaction with every other currently connected client. 
        Returns trade's id on sucess. On invalid ciphers list returns -1
        """
        #TODO: Return authentication key with trade. Use for deletion authentication
        if not isinstance(ciphers, dict) and len(ciphers) == num_clients - 1:
            return INVALID_ARG_ERR

        trade_id = random.randint(0, MAX_TRADE_ID)
        with self.pall_lock:
            d = self.cur_trades[self.client_id]['original']
            d[trade_id] = ciphers
            t = self.cur_trades[self.client_id]
            t['original'] = d
            self.cur_trades[self.client_id] = t
            self.num_outstanding.value += 1

        return trade_id

    def _post_pallier_keys(self, pall_keys):
        """
        pall_keys is dict of form {pub_key: (PALL_PK, ENC(PALL_SK))}, where PALL_SK encrypted with pub_key.
        This function adds the keys to the shared dictionary, pall_dict.
        """
        with self.pall_lock:
            for pub_key, pair in pall_keys.items():
                # Since dict keys must be strings when sent as json objects
                pub_key = ast.literal_eval(pub_key)
                d_other = self.pall_dict[pub_key]
                d_other[self.client_pub_key] = pair
                self.pall_dict[pub_key] = d_other
                d_sender = self.pall_dict[self.client_pub_key]
                d_sender[pub_key] = pair
                self.pall_dict[self.client_pub_key] = d_sender

                print("SERVER: added pallier key for (" + str(pub_key) + ", " + str(self.client_pub_key) + ")")
            self.pall_cntr.value -= 1

        return AUTH_SUCCESS

    def _query_pall_pairs(self):
        """
        Returns: {other_client_pub_key: pall_pair} where the pallier key pairs are those generated by other clients to communicate
        with this client
        """
        x = None
        wait_time = 0
        sleep_time = 1
        with self.pall_lock:
            x = self.pall_cntr.value

        while x > 0 and wait_time < REGISTRATION_PERIOD_LEN:
            print("SERVER: Pall Cntr - " + str(x))
            time.sleep(sleep_time)
            wait_time += sleep_time
            with self.pall_lock:
                x = self.pall_cntr.value

        if x > 0:
            # Timeout before all keys pushed
            return AUTH_QUERY_TIMEOUT

        print("SERVER: Returning pallier keys for - " + str(self.client_pub_key))
        return {str(k): v for k,v in self.pall_dict[self.client_pub_key].items()}

    def __init__(self, server_name, client_id, pub_key_dict, port, comm_qs, trades, num_clients, 
                         start_event, gen_pall_list, pall_key_cntr, pall_key_lock, pall_dict,
                        num_outstanding):
        """
        run() method of all ClientHandler processes. Takes in all state necessary to run client.
        client_id: id of client that process is responsible for. Known only by the owner client.
        pub_key_dict: Dictionary of client_id to public key. The exposed identity on any client communication. Used to forward pallier keys
        port: server port assigned to client during registration
        comm_qs: {pub_key: Q} - Maps to multiprocessing queue to which clients and server push information
        trades: Shared trades dict that holds all outstanding trades. Used for matching and posting trades
        num_clients: Holds number of clients in current registration period
        start_event: All client handler's wait for this event to indicate end of registration period
        gen_pall_list: list of public keys generated by server for which client must generate pallier keys
        pall_key_cntr: Shared integer that ensures all clients post pallier keys before any can query
        pall_key_lock: Used to ensure atomicity of pall_key_cntr
        pall_dict: shared memory dictionary into which all clientHandler's store the posted pallier pairs
        num_outstanding: number of outstanding trades across all clients
        """
        super(ClientHandler, self).__init__(daemon=True, name="ClientHandler")
        self.server_name = server_name
        self.client_id = client_id
        self.client_pub_key = pub_key_dict[self.client_id]
        self.pub_key_dict = pub_key_dict
        self.port = port
        self.comm_qs = comm_qs
        self.comm_q = comm_qs[self.client_pub_key]
        self.cur_trades = trades
        self.num_clients = num_clients
        self.start_event = start_event
        self.gen_pall_list = gen_pall_list
        self.pall_cntr = pall_key_cntr
        self.pall_lock = pall_key_lock
        self.pall_dict = pall_dict
        self.num_outstanding = num_outstanding
        self.sock_client = None

        self.matched_pub = None
        self.matched_items = {'table': None, 'c': None, 'notify_vol': None, 'min_vol': None}

    def run(self):
        sock_server = socket.socket()
        host = self.server_name
        print("SERVER: host = " + str(host))
        sock_server.bind((host, self.port))
        sock_server.listen(2)
        print("SERVER: listening for client {} at {}".format(self.client_id, self.port))
        sock_client, addr = sock_server.accept()
        self.sock_client = sock_client
        print("SERVER: client " + str(self.client_id) + " connected")

        # Issue pallier generation request
        self.start_event.wait()

        msg_gen_pall = {'method': 'gen_pall', 'params': self.gen_pall_list}
        self.sock_client.send(pickle.dumps(msg_gen_pall))

        # Now loop to accept trade requests
        while True:
            # Check for key refresh
            if not self.comm_q.empty():
                msg = self.comm_q.get()
                self._handle_msg(msg)
                
            # Receive message from client and attempt to parse it
            #b = self.sock_client.recv(15000)
            buf = b''
            while len(buf) < 4:
                buf += self.sock_client.recv(4-len(buf))
            length = struct.unpack('!I', buf)[0]
            data = b''
            while len(data) < length:
                data += self.sock_client.recv(length - len(data))
            msg = pickle.loads(data)

            #if b == b'':
            #    continue
            #msg = pickle.loads(b)
            #print("SERVER: Recieved Message - " + str(msg))
            method = msg['method']
            params = msg['params']
           
            if method == 'post_pall_keys':
                res = self._post_pallier_keys(*params)
            elif method == 'query_pall_keys':
                res = self._query_pall_pairs()
            elif method == 'post_trade':
                res = self._post_trade(*params)
            elif method == 'query_trades':
                res = self._query_trades()
            elif method == 'del_trade':
                res = self._del_trade(*params)
            elif method == 'send_table':
                res = self._send_table(*params)
            elif method == 'send_c':
                res = self._send_c(*params)
            elif method == 'notify_volume':
                res = self._nofify_vol(*params)
            elif method == 'send_min_volume':
                res = self._send_min_vol(*params)
            elif method == 'finish_trade':
                res = self._del_trade(*params)
            else:
                res = AUTH_INVALID_METHOD_ERR
            
            print("SERVER: Returning = {}".format(res))
            resp_bytes = pickle.dumps(res)
            length = struct.pack('!I', len(resp_bytes))
            resp_bytes = length + resp_bytes
            self.sock_client.send(resp_bytes)
            #self.sock_client.sendall(resp_bytes)

    def terminate(self):
        if self.sock_client is not None:
            self.sock_client.close()
        super(ClientHandler, self).terminate()

class KeyStore:
    def __init__(self):
        self._rsa_keys = {}
        self._id_map = {}

    def add_rsa_key(self, key):
        """
        Adds RSA public key to the store. Returns random id for key
        """
        # FIXME: Need to expand client id space
        i = random.randint(0, MAX_CLIENT_ID)
        self._rsa_keys[i] = key
        self._id_map[key] = i
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

    def serv_get_id(self, pub_key):
        """
        Returns client_id given public key
        """
        return self._id_map[pub_key]

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
        self.ticker_map = generate_tickers() #TODO: Load tickers and generate map
        self.open_ports = list(AVAIL_PORTS)
        self.key_store = KeyStore()
        # Now done in self.match_trades
        self.refresh_thread = threading.Timer(KEY_REFRESH_INTERVAL, self.key_refresh)
        self.start_clients_thread = threading.Timer(REGISTRATION_PERIOD_LEN, self.start_clients)
        self.timer_start = time.time()

        self.clients = {} # Holds (client_id, comm_q) Where comm_q is a mp Queue for passing messages
        self.cur_trades = self.manager.dict() # Shared memory dict among all client handler processes
        self.num_outstanding = self.manager.Value('i', 0, lock=False)

        self.pall_key_gen = {} # Holds the dict generated by gen_pall_pairs(). Once complete this is sent to each client

        # Holds the pallier key pairs that need to be sent to client_id of rsa_pub_key as pallier pair was created by other client in the pair
        self.pall_keys = self.manager.dict() # {recipient_pub_key: (sender_id, (PALL_PK, ENC(PALL_SK))... } 

        self.reg_done = False
        self.start_event = mp.Event() # Event to notify clients that registration period is over, and pal_key_gen is correct

        self.pall_key_cntr = self.manager.Value('i', 0, lock=False)
        self.pall_key_lock = mp.Lock()

        self.active_procs = []
        self.num_active_clients = 0

        self.comm_qs = {}

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
        print("SERVER: Starting Client Processes...")
        self.reg_done = True
        self.pall_key_cntr.value = len(self.clients)
        for key in self.key_store.get_rsa_list():
            self.pall_keys[key] = {}
        for client_id in self.clients.keys():
            self.cur_trades[client_id] = {'original': {}, 'computed': {}}

        pall_gen_assignment = self.gen_pall_pairs()
        ctx = mp.get_context('spawn')
        for client_id, info in self.clients.items():
            assigned_port = info[0]
            pub_key = info[1]
            # Launches client handler process. daemon=True means client handlers are killed when server process is
            proc = ClientHandler(self.server_name, client_id, 
                        self.key_store.serv_get_rsa(), assigned_port, self.comm_qs, self.cur_trades, self.key_store.num_keys, 
                        self.start_event, self.pall_key_gen[client_id], self.pall_key_cntr,
                        self.pall_key_lock, self.pall_keys, self.num_outstanding)
            proc.start()
            self.active_procs.append(proc)
            self.num_active_clients += 1

#    def match_trades(self):
#        start_time = time.clock()
#        while time.clock() - start_time < KEY_REFRESH_INTERVAL:
#            with self.pall_key_lock:
#                d = self.cur_trades
#                for client_id, trades in self.cur_trades:
#                    if len(trades['computed']) == self.num_outstanding:
#                        continue
#                    for client_id2, new_trades in self.cur_trades:
#                        if client_id == client_id2:
#                            continue
#                        for trade_id, ciphers in new_trades['original']:
#            time.sleep(MATCH_WAIT_TIME)
#
#        self.key_refresh()

    def key_refresh(self):
        """
        Called every 5 minutes to invalidate public keys
        """
        #TODO: Immediate communication lock on key refresh
        # Reset server state
        self.open_ports = AVAIL_PORTS
        self.key_store.refresh()
        self.cur_trades = {}
        for pub_key, comm_q in self.comm_qs.items():
            comm_q.put({'type': 'refresh', 'data': self.key_store.serv_get_id(pub_key)})

        # Restart refresh timer
        self.timer_start = time.time()
        self.refresh_thread = threading.Timer(KEY_REFRESH_INTERVAL, key_refresh)
        self.refresh_thread.start()
        self.start_event.clear()

    def register(self, pub_key):
        """
        Registers a new client with the central authority. pub_key := (RSA_PK, ENC(RSA_SK)). Stored state is public key and it's corresponding unique ID.
        After receipt of client_id and ticker mapping, client should query_keys until they are given complete RSA public key
        list (i.e. reg period is over). All clients then receive message from server after connecting containing list of
        RSA public keys they should generate pallier keys for. Server only starts client handlers once registration period is over.
        Returns: Client uid, assigned port, ticker mapping. Check client_uid >= 0 for error code
        """
        print("SERVER: Registering Client")
        pub_key = tuple(pickle.loads(pub_key.data))
        if len(self.open_ports) == 0:
            return AUTH_POOL_FULL, -1, -1
        if not self.start_clients_thread.is_alive():
            if self.reg_done:
                return AUTH_OUTSIDE_REG_PERIOD, -1, -1
            else:
                self.start_clients_thread.start()
                self.refresh_thread.start()
        # Create Communication Queue
        self.comm_qs[pub_key] = mp.Queue()
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
            x = pickle.dumps(self.key_store.get_rsa_list())
            return x
        else:
            return AUTH_IN_REG_PERIOD

    
    def kill_client(self):
        """
        Before exiting all clients must call this function.
        Returns: True if server is dying, False otherwise
        """
        self.num_active_clients -= 1
        if self.num_active_clients <= 0:
            # Kill server
            for proc in self.active_procs:
                proc.terminate()
            # Give processes time to die
            time.sleep(3)
            sys.exit(0)
            return True
        return False

    def _dispatch(self, method, params):
        if method == 'register':
            return self.register(*params)
        elif method == 'query_refresh_timer':
            return self.query_refresh_timer()
        elif method == 'query_refresh_interval':
            return self.query_refresh_interval()
        elif method == 'query_pub_keys':
            return self.query_pub_keys()
        elif method == 'kill_client':
            # Only logic is to kill server when no active clients
            return self.kill_client()
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
