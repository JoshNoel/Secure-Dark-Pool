import rsa.key as k
from phe import paillier
from Crypto.PublicKey.RSA import construct
import xmlrpc.client as xmlrpclib
import pool_types
import socket
import sys
import json

class Client():
    def __init__(self, lambda_bits, server_addr, server_rpc_port):
        self.lb = lambda_bits

        #generate secure RSA public/private key pairs
        self.p, self.q = k.find_p_q(lambda_bits)
        self.e, self.d = k.calculate_keys(self.p, self.q)
        self.n = self.p * self.q

        self.proxy = xmlrpclib.ServerProxy(server_addr + ":"+ str(server_rpc_port))
        self.server_addr = server_addr
        self.sock = None

        self.i = None
        self.server_port = None
        self.ticker_map = None

        self.pub_keys = None
        self.pall_keys = {}

    def get_keys(self):
        return self.proxy.query_keys()

    def register(self):
        # Need to send integers > 64-bits as strings
        self.i, self.server_port, self.ticker_map = self.proxy.register(json.dumps((self.e, self.n)).encode('utf-8'))
        if self.i < 0:
            print(auth_geterror(self.i))

        # Get public key list from server
        while (not isinstance(self.pub_keys, list)):
            thread.sleep(5)
            self.pub_keys = self.proxy.query_pub_keys()

        print("Public Keys: " + str(self.pub_keys))
    
        # Initialize socket connection
        self.sock = socket.socket()
        sock.connect((self.server_addr, self.server_port))
        print("Client Connected")

        # On connection server sends the public keys to generate pallier pairs for
        gen_pall_msg = json.loads(sock.recv(1024).decode('utf-8'))
        gen_pall_key_list = gen_pall_msg[1]
        enc_pall_keys = generate_pal(gen_pall_key_list)

        # Send generated pallier key pairs to server
        send_pall_msg = {'method': 'post_pall_keys', 'params': enc_pall_keys}
        send_pall_msg = json.dumps(send_pall_msg).encode('utf-8')
        sock.send(send_pall_msg)

        # Query pallier keys, Server blocks until all clients have posted
        serv_pall_keys = json.loads(sock.recv(1024).decode('utf-8'))
        self.pall_keys.update(serv_pall_keys)

    def generate_pal(self, pub_keys):
        for j in range(len(pub_keys)):
            p_prime, q_prime = k.find_p_q(self.lb)
            pal_pub_ij, pal_priv_ij = paillier.generate_paillier_keypair()

            j_public_e = pub_keys[j][0]
            j_public_n = pub_keys[j][1]

            pubkey = construct(pub_keys[j])
            #convert priv_ij to binary

            #??? might not work
            private_bytes = pal_priv_ij.encode('UTF-8')
            pal_priv_ij_encrypt = pubkey.encrypt(private_bytes, None)

            # Save unencrypted pallier keys tagged with public key of other user
            self.pall_keys[pub_keys[j]] = (pal_pub_ij, pal_priv_ij)
            #output pal_priv_ij_encrypt
            return (pal_pub_ij, pal_priv_ij_encrypt)

        
    def run_test_case(self, trades):
        """
        In the future will load trades dictionary in order to simulate trades
        """
        # Do trades
        return True


