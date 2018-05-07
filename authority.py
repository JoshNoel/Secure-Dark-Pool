#!/bin/python3
from xmlrpc.server import SimpleXMLRPCServer
from xmlrpc.server import SimpleXMLRPCRequestHandler
from random import shuffle
import threading
import time
import random

KEY_REFRESH_INTERVAL = 300
MATCHED_TRADE = 0
UNMATCHED_TRADE = -1
INVALID_ARG_ERR = -2
INVALID_METHOD_ERR = -3


class RequestHandler(SimpleXMLRPCRequestHandler):
    rpc_paths = ('/access')

class KeyStore:
    def __init__(self):
        self._pub_keys = {}

    def add_key(self, key):
        """
        Adds public key to the store
        """
        i = random.randint()
        self._pub_keys[i] = key
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
    Holds outside interface for clients to interact with server. Functions exposed through _dispatch
    """
    def __init__(self):
        self.key_store = KeyStore()
        self.refresh_thread = threading.Timer(KEY_REFRESH_INTERVAL, key_refresh)
        self.timer_start = time.time()
        self.refresh_thread.start()
        self.cur_trade_id = MATCHED_TRADE + 1
        self.cur_trades = {}
        self.matched = []


    def key_refresh(self):
        """
        Called every 5 minutes to invalidate public keys
        """
        self.key_store.refresh()

    def register(self, pub_key):
        """
        Registers a new client with the central authority. Stored state is simply public key.
        Returns: Ticker -> TransID dict
        """
        self.key_store.add_key(pub_key)
        return 0

    def match_trade(self, user1_id, in_offers):
        for trade_id, trade in cur_trades.items():
            for user2_id, offers in in_offers.items():



    def query_matches(self, user_id):
        

    def query_keys(self):
        """
        Returns all current public keys in key store
        """
        return self.key_store.get_key_list()

    def query_refresh_timer(self):
        """
        Returns start of current key expiry interval
        """
        return self.timer_start

    def query_refresh_interval(self):
        return KEY_REFRESH_INTERVAL

    def post_trade(self, user_id, ciphers):
        """
        Posts given transID list (ciphers) to server, tagged with users id. 
        Server stores list of pallier encrypted ciphertexts corresponding to 
        transaction with every other currently connected client. 
        Returns trade's id on sucess. On invalid ciphers list returns -1
        """
        #TODO: Return authentication key with trade. Use for deletion authentication
        if not isinstance(ciphers, dict) and len(ciphers) == self.key_store.num_keys - 1:
            return INVALID_ARG_ERR
        if match_trade(ciphers):
            return MATCHED_TRADE
        self.cur_trades[self.cur_trade_id] = (user_id, ciphers)
        self.cur_trade_id += 1
        return self.cur_trade_id - 1

    def del_trade(self, trade_id):
        """
        Deletes trade from outstanding trades list. Call on completion or cancellation.
        Return 0 on success, -1 on failure
        """
        #TODO: Verify deletion with authentication key if trade_id in self.cur_trades: del self.cur_trades[trade_id] return 0 else:
            return INVALID_ARG_ERR

    def get_outstanding_trades(self):
        """
        Returns dictionary of current outstanding trades
        """
        return self.cur_trades

    def _dispatch(self, method, params):
        if method == 'register':
            return self.register(*params)
        elif method == 'query_keys':
            return self.query_keys()
        elif method == 'query_refresh_timer':
            return self.query_refresh_timer()
        elif method == 'query_refresh_interval':
            return self.query_refresh_interval()
        elif method == 'post_trade':
            return self.post_trade(*params)
        elif method == 'del_trade':
            return self.del_trade(*params)
        elif method == 'get_outstanding_trades':
            return self.get_outstanding_trades()
        else:
            return INVALID_METHOD_ERR

# Create server
if __name__ == "__main__":
    server = SimpleXMLRPCServer(("localhost", 8000), requestHandler=CentralAuthority)
    server.register_introspection_functions()

    server.register_instance(CentralAuthority())

    # Run the server's main loop
    server.serve_forever()
