from phe import paillier, encoding
from Crypto.PublicKey.RSA import generate, construct
from Crypto.Cipher import PKCS1_OAEP
import xmlrpc.client as xmlrpclib
from pool_types import *
import socket
import sys
import json
import time
import collections
import ast
import base64
import pickle

class Client():
    def __init__(self, lambda_bits, server_name, server_rpc_port):
        self.lb = lambda_bits

        #generate secure RSA public/private key pairs
        self.rsa_priv = generate(self.lb)
        self.rsa_pub = self.rsa_priv.publickey()
        self.proxy = xmlrpclib.ServerProxy("http://" + server_name + ":"+ str(server_rpc_port))
        self.server_name = server_name
        self.sock = None

        self.i = None
        self.server_port = None
        self.ticker_map = None

        self.pub_keys = None
        self.pall_keys = {}
        self.waiting_trades = set()

    def kill(self):
        try:
            self.proxy.kill_client()
            if self.sock is not None:
                self.sock.close()
        except xmlrpclib.Fault as e:
            # ignore if server RPC kills itself
            pass

    def get_keys(self):
        return self.proxy.query_keys()

    def send_message(self, msg, filter_trade_data=True):
        """
        Sends message to server through socket.
        Message format: {'method': ClientHandler_method_name, 'params': [...]}
        filter_trade_data: If false, method will not filter out trade data responses. For use when
        sending trade messages.
        Note that trade responses may come over socket in this time, but they will be filtered out.
        Returns: Response to sent message as server always sends response
        """
        assert isinstance(msg, dict)
        assert 'method' in msg and 'params' in msg
        assert type(msg['method']) == str 
       
        print("CLIENT: Sending Message - " + str(msg))
        send_msg = pickle.dumps(msg)
        self.sock.send(send_msg)
       
        # Filters out trade responses received over socket
        message_resp_parsed = False
        while (not message_resp_parsed):
            resp = pickle.loads(self.sock.recv(4096))
            print("CLIENT: Recieved Response - " + str(resp))

            # Check if error received
            if isinstance(resp, collections.Hashable) and resp in AUTH_ERRORS and resp != AUTH_SUCCESS:
                raise RuntimeError("CLIENT: Recieved Error - " + auth_geterror(resp))

            # Check if this is a response to outstanding trade
            if filter_trade_data and isinstance(resp, dict) and 'trade_data' in resp:
                self.parse_trade_resp(resp)
                continue

            message_resp_parsed = True
        return resp

    def register(self):
        # Need to send integers > 64-bits as strings
        self.i, self.server_port, self.ticker_map = self.proxy.register(pickle.dumps((self.rsa_pub.publickey().n,
                                                                        self.rsa_pub.publickey().e)))
        if self.i < 0:
            raise RuntimeError(auth_geterror(self.i))

        # Get public key list from server
        while self.pub_keys is None:
            time.sleep(1)
            query_pub_res = self.proxy.query_pub_keys()
            if query_pub_res != AUTH_IN_REG_PERIOD:
                res = pickle.loads(query_pub_res.data)
                self.pub_keys = []
                for keydata in res:
                    self.pub_keys.append(keydata)

        print("CLIENT: pub_keys = " + str(self.rsa_pub.n))
        print("CLIENT: priv_d = " + str(self.rsa_priv.d))

        # Initialize socket connection
        self.sock = socket.socket()
        print("CLIENT {}: connecting to {} at {}".format(self.i, self.server_name, self.server_port))
        
        x = -1
        while x != 0:
            x = self.sock.connect_ex((self.server_name, self.server_port))
            time.sleep(1)
        print("Client Connected")

        # On connection server sends the public keys to generate pallier pairs for
        gen_pall_msg = pickle.loads(self.sock.recv(4096))
        print("CLIENT: Pallier Gen Message Recv - " + str(gen_pall_msg))
        gen_pall_key_list = [tuple(l) for l in gen_pall_msg['params']]
        enc_pall_keys = self.generate_pal(gen_pall_key_list)

        # Send generated pallier key pairs to server
        post_pall_msg = {'method': 'post_pall_keys', 'params': [enc_pall_keys,]}
        self.send_message(post_pall_msg)
        #send_pall_msg = json.dumps(send_pall_msg).encode('utf-8')
        #self.sock.send(send_pall_msg)

        # Query pallier keys, Server blocks until all clients have posted
        query_pall_keys = {'method': 'query_pall_keys', 'params': []}
        serv_pall_keys = self.send_message(query_pall_keys)
        # Convert string public keys back to tuples
        serv_pall_keys = {ast.literal_eval(k): v for k,v in serv_pall_keys.items()}

        # serv_pall_keys = json.loads(self.sock.recv(1024).decode('utf-8'))
        self.update_pall_keys(serv_pall_keys)
        print("CLIENT: Pallier keys updated - " + str(self.pall_keys))
        
    def generate_pal(self, pub_keys):
        res = {}
        for j in range(len(pub_keys)):
            pal_pub_ij, pal_priv_ij = paillier.generate_paillier_keypair()

            j_public_e = pub_keys[j][1]
            j_public_n = pub_keys[j][0]

            pubkey = construct(tuple(pub_keys[j]))
            cipher = PKCS1_OAEP.new(pubkey)
            #convert priv_ij to binary (encrypt (p,q) and then rebuild private key on decryption
            #convert pub_ij to binary. Send (g,n) and then rebuild public key on decryption

            private_p = pickle.dumps(pal_priv_ij.p)
            private_q = pickle.dumps(pal_priv_ij.q)
            #private_bytes = pickle.dumps((pal_priv_ij.p, pal_priv_ij.q))
            #print("DEBUG - private_bytes ({}) = {}".format(len(private_bytes), private_bytes))
            ciphertext_p = cipher.encrypt(private_p)
            ciphertext_q = cipher.encrypt(private_q)
            pal_priv_ij_encrypt = str((ciphertext_p, ciphertext_q))
            pal_pub_str = str((pal_pub_ij.g, pal_pub_ij.n))

            # Save unencrypted pallier keys tagged with public key of other user
            self.pall_keys[pub_keys[j]] = (pal_pub_ij, pal_priv_ij)
            #output pal_priv_ij_encrypt
            res[str(pub_keys[j])] = (pal_pub_str, pal_priv_ij_encrypt)
        return res

    
    def update_pall_keys(self, pall_keys):
        """
        Updates local pallier key dict given encrypted pallier key dictionary mapping {user_pub_key: (PALL_PK,
        ENC(PALL_SK))} where ENC uses the current user's secret key
        """
        for rsa_pub, pair in pall_keys.items():
            if rsa_pub in self.pall_keys:
                continue
            pub_key = ast.literal_eval(pair[0])
            g = pub_key[0]
            n = pub_key[1]
            print("DEBUG: - {} = {}".format(type(n), n))
            pall_pub = paillier.PaillierPublicKey(n)
            pall_pub.g = g
            
            print("DEBUG - pub_key = " + str((self.rsa_priv.n, self.rsa_priv.e)))
            print("DEBUG - priv_key = " + str((self.rsa_priv.d)))
            cipher_data = ast.literal_eval(pair[1])
            print("DEBUG - ciphertexts = " + str(cipher_data))

            cipher = PKCS1_OAEP.new(self.rsa_priv)
            p = pickle.loads(cipher.decrypt(cipher_data[0]))
            q = pickle.loads(cipher.decrypt(cipher_data[1]))

            #print("DEBUG - private_p = " + str(private_p))
            #print("DEBUG - private_q = " + str(private_q))
            #priv_data = pickle.loads(private_bytes)
            #print("DEBUG - " + str(priv_data))
            #p = priv_data[0]
            #q = priv_data[1]

            print("DEBUG - (p: {},\n q: {},\n n: {}".format(p, q, n))
            pall_priv = paillier.PaillierPrivateKey(pall_pub, p, q)

            self.pall_keys[rsa_pub] = (pall_pub, pall_priv)

    def send_trade(self, trade):
        """
        Sends trade to server through list of paillier encrypted ciphertexts for every other
        client in the network.
        """
        ticker_encoding = int(self.ticker_map[trade['ticker']])
        if trade['val'] < 0:
            ticker_encoding *= -1
        print("CLIENT - Sending Trade: {}: {} = {}".format(trade['ticker'], trade['val'], ticker_encoding))
        ciphers = {}
        for rsa_pub, pall_pair in self.pall_keys.items():
            pall_pub = pall_pair[0]
            # Encode value to support signed integers
            e = encoding.EncodedNumber.encode(pall_pub, ticker_encoding)
            ciphers[rsa_pub] = pall_pub.encrypt(e)

        msg = {'method': 'post_trade', 'params': [ciphers]}
        resp = self.send_message(msg, filter_trade_data=False)

        # Server should only return error or trade_id
        if isinstance(resp, collections.Hashable) and resp in AUTH_ERRORS:
            print("CLIENT - Error sending trade: " + auth_geterror(resp))
            return False

        self.waiting_trades.add(resp)

    def query_trades(self, resp):
        """
        Iterates over outstanding trades on server to search for match
        """
        msg = {'method': 'query_trades', 'params':[]}
        resp = send_msg(msg, filter_trade_data=False)
        for trade_id, d in resp.items():
            for other_trade_id, data in d.items():
                other_pub_key = data[0]
                comp_ciper = data[1]
                if encoding.EncodedNumber.decode(self.pall_keys[other_pub_key][1].decrypt(comp_cipher)) == 0:
                    print("CLIENT - Match Found!!")

    def run_test_case(self, trades):
        """
        Loads list of trades in order to simulate trades.
        trades := [{ticker: ticker, val: trade_value}, ...]
        """
        # Do trades
        TEST_TIMEOUT_INT = 5
        print("TEST: trades = {}".format(trades))
        for trade in trades:
            if not self.send_trade(trade):
                return False
            cur_time = start_time = time.clock()
            while cur_time - start_time < TEST_TIMEOUT_INT:
                self.query_trades()

        self.query_trades()
