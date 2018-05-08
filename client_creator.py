import rsa.key as k
from phe import paillier
from Crypto.PublicKey.RSA import construct
import xmlrpc.client as xmlrpclib

SERVER_ADDR = "http://localhost"
SERVER_RPC_PORT = 8000

class Client():
    def __init__(self, lambda_bits):
        self.lb = lambda_bits

        #generate secure RSA public/private key pairs
        self.p, self.q = k.find_p_q(lambda_bits)
        self.e, self.d = k.calculate_keys(self.p, self.q)
        self.n = self.p * self.q

        self.proxy = xmlrpclib.ServerProxy(SERVER_ADDR + ":"+ SERVER_RPC_PORT)

        self.i = None

    def get_keys(self):
        return self.proxy.query_keys()

    def register(self):
        self.i = self.proxy.register((self.e, self.n))

    def generate_pal(self):
        keys = self.get_keys()
        for j in range(len(keys)):
            p_prime, q_prime = k.find_p_q(self.lb)
            pal_pub_ij, pal_priv_ij = paillier.generate_paillier_keypair()

            j_public_e = keys[j][0]
            j_public_n = keys[j][1]

            pubkey = construct(keys[j])
            #convert priv_ij to binary

            #??? might not work
            private_bytes = pal_priv_ij.encode('UTF-8')
            pal_priv_ij_encrypt = pubkey.encrypt(private_bytes, None)

            #output pal_priv_ij_encrypt

            #send to server
