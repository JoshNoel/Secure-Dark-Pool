import rsa.key as k
from phe import paillier
from Crypto.PublicKey.RSA import construct
import xmlrpc.client as xmlrpclib
from pool_types import *
import socket
import sys
import json
import time
import collections
import ast

class Client():
    def __init__(self, lambda_bits, server_name, server_rpc_port):
        self.lb = lambda_bits

        #generate secure RSA public/private key pairs
        self.p, self.q = k.find_p_q(lambda_bits)
        self.e, self.d = k.calculate_keys(self.p, self.q)
        self.n = self.p * self.q

        self.proxy = xmlrpclib.ServerProxy("http://" + server_name + ":"+ str(server_rpc_port))
        self.server_name = server_name
        self.sock = None

        self.i = None
        self.server_port = None
        self.ticker_map = None

        self.pub_keys = None
        self.pall_keys = {}

    def get_keys(self):
        return self.proxy.query_keys()

    def send_message(self, msg):
        assert isinstance(msg, dict)
        assert 'method' in msg and 'params' in msg
        assert type(msg['method']) == str 
       
        print("CLIENT: Sending Message - " + str(msg))
        send_msg = json.dumps(msg).encode('utf-8')
        self.sock.send(send_msg)

        resp = json.loads(self.sock.recv(4096).decode('utf-8'))
        print("CLIENT: Recieved Response - " + str(resp))
        if isinstance(resp, collections.Hashable) and resp in AUTH_ERRORS and resp != AUTH_SUCCESS:
            raise RuntimeError("CLIENT: Recieved Error - " + auth_geterror(resp))

        return resp

    def register(self):
        # Need to send integers > 64-bits as strings
        self.i, self.server_port, self.ticker_map = self.proxy.register(json.dumps((self.e, self.n)))
        if self.i < 0:
            raise RuntimeError(auth_geterror(self.i))

        # Get public key list from server
        while (not isinstance(self.pub_keys, list)):
            time.sleep(5)
            self.pub_keys = json.loads(self.proxy.query_pub_keys())

        print("CLIENT: pub_keys = " + str(self.pub_keys))
    
        # Initialize socket connection
        self.sock = socket.socket()
        print("CLIENT: connecting to " + str(self.server_name))
        self.sock.connect((self.server_name, self.server_port))
        print("Client Connected")

        # On connection server sends the public keys to generate pallier pairs for
        gen_pall_msg = json.loads(self.sock.recv(1024).decode('utf-8'))
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
            p_prime, q_prime = k.find_p_q(self.lb)
            pal_pub_ij, pal_priv_ij = paillier.generate_paillier_keypair()

            j_public_e = pub_keys[j][0]
            j_public_n = pub_keys[j][1]

            pubkey = construct(pub_keys[j])
            #convert priv_ij to binary (encrypt (p,q) and then rebuild private key on decryption
            #convert pub_ij to binary. Send (g,n) and then rebuild public key on decryption

            private_bytes = json.dumps((pal_priv_ij.p, pal_priv_ij.q)).encode('utf-8')
            pal_priv_ij_encrypt = str(pubkey.encrypt(private_bytes, None))
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
        for pub_key, pair in pall_keys.items():
            privkey = construct((self.n, self.e, self.d))
            pair[0] = ast.literal_eval(pair[0])
            n = pair[0][1]
            g = pair[0][0]
            pall_pub = paillier.PaillierPublicKey(n)
            pall_pub.g = g
          
            print("CLIENT: Test - " + str(pair[1]))
            priv_data = privkey.decrypt(pair[1]).decode('utf-8')
            p = priv_data[0]
            q = priv_data[1]

            pall_priv = paillier.PaillierPrivateKey(pall_pub, p, q)

            print("CLIENT: Test - " + str(pall_pub), str(pall_priv))

            self.pall_keys[pub_key] = (pall_pub, pall_priv)

    def run_test_case(self, trades):
        """
        In the future will load trades dictionary in order to simulate trades
        """
        # Do trades
        return True


