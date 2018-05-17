from phe import paillier, encoding
from Crypto.PublicKey.RSA import generate, construct
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import random
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
import struct

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
        self.waiting_trades = {}

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
       
        #print("CLIENT: Sending Message - " + str(msg))
        send_msg = pickle.dumps(msg)
        length = struct.pack('!I', len(send_msg))
        send_msg = length + send_msg
        self.sock.send(send_msg)
       
        # Filters out trade responses received over socket
        message_resp_parsed = False
        while (not message_resp_parsed):
            buf = b''
            while len(buf) < 4:
                buf += self.sock.recv(4-len(buf))
            length = struct.unpack('!I', buf)[0]
            data = b''
            while len(data) < length:
                data += self.sock.recv(length - len(data))
            resp = pickle.loads(data)
            #resp = pickle.loads(self.sock.recv(15000))
            #print("CLIENT: Recieved Response - " + str(resp))

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
        perf_time = time.clock()
        self.i, self.server_port, self.ticker_map = self.proxy.register(pickle.dumps((self.rsa_pub.publickey().n,
                                                                        self.rsa_pub.publickey().e)))
        if self.i < 0:
            raise RuntimeError(auth_geterror(self.i))

        print("PERF: Reg time: {}".format(time.clock() - perf_time))
        # Get public key list from server
        while self.pub_keys is None:
            time.sleep(1)
            query_pub_res = self.proxy.query_pub_keys()
            if query_pub_res != AUTH_IN_REG_PERIOD:
                res = pickle.loads(query_pub_res.data)
                self.pub_keys = []
                for keydata in res:
                    self.pub_keys.append(keydata)

        #print("CLIENT: pub_keys = " + str(self.rsa_pub.n))
        #print("CLIENT: priv_d = " + str(self.rsa_priv.d))

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
        perf_time = time.clock()
        #print("CLIENT: Pallier Gen Message Recv - " + str(gen_pall_msg))
        gen_pall_key_list = [tuple(l) for l in gen_pall_msg['params']]
        enc_pall_keys = self.generate_pal(gen_pall_key_list)

        print("PERF: Paill Gen Time: {}".format(time.clock() - perf_time))
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
        #print("CLIENT: Pallier keys updated - " + str(self.pall_keys))
        
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
            res[str(pub_keys[j])] = (pal_pub_ij, pal_priv_ij_encrypt)
        return res

    
    def update_pall_keys(self, pall_keys):
        """
        Updates local pallier key dict given encrypted pallier key dictionary mapping {user_pub_key: (PALL_PK,
        ENC(PALL_SK))} where ENC uses the current user's secret key
        """
        for rsa_pub, pair in pall_keys.items():
            if rsa_pub in self.pall_keys:
                continue
            #pub_key = ast.literal_eval(pair[0])
            #g = pub_key[0]
            #n = pub_key[1]
            pall_pub = pair[0]#paillier.PaillierPublicKey(n)
            #pall_pub.g = g
            
            #print("DEBUG - pub_key = " + str((self.rsa_priv.n, self.rsa_priv.e)))
            #print("DEBUG - priv_key = " + str((self.rsa_priv.d)))
            cipher_data = ast.literal_eval(pair[1])
            #print("DEBUG - ciphertexts = " + str(cipher_data))

            cipher = PKCS1_OAEP.new(self.rsa_priv)
            p = pickle.loads(cipher.decrypt(cipher_data[0]))
            q = pickle.loads(cipher.decrypt(cipher_data[1]))

            #print("DEBUG - private_p = " + str(private_p))
            #print("DEBUG - private_q = " + str(private_q))
            #priv_data = pickle.loads(private_bytes)
            #print("DEBUG - " + str(priv_data))
            #p = priv_data[0]
            #q = priv_data[1]

            #print("DEBUG - (p: {},\n q: {},\n n: {}".format(p, q, n))
            pall_priv = paillier.PaillierPrivateKey(pall_pub, p, q)

            self.pall_keys[rsa_pub] = (pall_pub, pall_priv)

    def send_trade(self, trade):
        """
        Sends trade to server through list of paillier encrypted ciphertexts for every other
        client in the network.
        """
        if 'amt' not in trade or 'ticker' not in trade:
            raise ValueError("Malformed trade: {}".format(trade))

        if abs(trade['amt']) > MAX_TRADE_VOL:
            raise ValueError("Trade volume too large {}. Max is {}".format(abs(trade['amt']), MAX_TRADE_VOL))

        ticker_encoding = int(self.ticker_map[trade['ticker']])
        if trade['amt'] < 0:
            ticker_encoding *= -1
        print("CLIENT - Sending Trade: {}: {} = {}".format(trade['ticker'], trade['amt'], ticker_encoding))
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

        trade_id = resp
        self.waiting_trades[trade_id] = trade
        return True

    def generate_table(self, volume, pall_pub):
        volume_bits = auth_getvolumebits(volume)
        # Now make the table
        enc_0 = pall_pub.encrypt(paillier.EncodedNumber.encode(pall_pub, 0))
        enc_r = pall_pub.encrypt(paillier.EncodedNumber.encode(pall_pub, random.randint(-pall_pub.n//3, pall_pub.n//3)))

        table = [[None]*VOLUME_NUM_BITS, [None]*VOLUME_NUM_BITS]
        for i in range(len(table)):
            for j in range(VOLUME_NUM_BITS):
                table[i][j] = enc_r

        for i,bit in enumerate(volume_bits):
            table[bit][i] = enc_0

        return table

    def complete_trade(self, trade_id, other_trade_id, other_pub_key):
        # First generate new pallier key-pair to maintain volume-secrecy

        # Now create bit representation of trade volume
        volume = self.waiting_trades[trade_id]['amt'] #Note: Max volume checked during trade send
        print("ORIG VOL: {}".format(volume))
        lower_vol = 0
        other_pub_key = construct(other_pub_key)

        perf_time = time.clock()
        # Buyer initiates (i.e. volume > 0)
        if volume > 0:
            pall_pub, pall_priv = paillier.generate_paillier_keypair()
            table = self.generate_table(volume, pall_pub)
            #print("DEBUG: volume_bits = {}\n table = {}".format(volume_bits, table))
            msg = {'method': 'send_table', 'params': [(other_pub_key.n, other_pub_key.e), (trade_id, other_trade_id), table]}

            # Wait to recieve dummy table
            print("DEBUG: (buyer) Sending table")
            x = self.send_message(msg)
            # Could not get trading lock
            if x == False:
                return False

            # Send fake c vector
            print("DEBUG: (buyer) Sending fake_c")
            fake_c = [pall_pub.encrypt(random.randint(-pall_pub.n//3, pall_pub.n//3)) for i in range(VOLUME_NUM_BITS)]
            msg = {'method':'send_c', 'params': [fake_c]}

            # Recieve real result vector
            c = self.send_message(msg)
           
            # Decrypt c vector
            greater = False
            vals = []
            for i in range(VOLUME_NUM_BITS):
                # In this case we don't care about overflow, only values that lead to 0
                try:
                    vals.append(pall_priv.decrypt_encoded(c[i]).decode())
                except OverflowError as e:
                    pass

            for val in vals:
                if val == 0:
                    greater = True
                    break

            print("DEBUG: (buyer) Sending notify volume")
            if greater == True:
                # Buy > Sell (i.e. x > y)
                # Send 0 to indicate that y should send the lower value
                msg = {'method': 'notify_volume', 'params': [other_pub_key.encrypt(0, None)[0]]}
                self.send_message(msg)
                print("Buy is greater")
            else:
                # Send the lower value to the other client
                msg = {'method': 'notify_volume', 'params': [other_pub_key.encrypt(volume, None)[0]]}
                self.send_message(msg)
                lower_vol = volume
                print("Sell is greater")

            # Send fake volume notification
            print("DEBUG: (buyer) Sending min volume")
            msg = {'method': 'send_min_volume', 'params': [other_pub_key.encrypt(lower_vol, None)[0]]}
            resp = self.send_message(msg)
            if lower_vol == 0:
                lower_vol = self.rsa_priv.decrypt(resp)

            print("CLIENT: (buyer) Completed trade {} with final volume = {}".format(self.waiting_trades[trade_id], lower_vol))
        else:
            # Seller waits for buyer to send table, sends fake table to hide selling
            fake_pall_pub, fake_pall_priv = paillier.generate_paillier_keypair()
            fake_table = self.generate_table(random.randint(-1000000, 1000000), fake_pall_pub)
            msg = {'method': 'send_table', 'params': [(other_pub_key.n, other_pub_key.e), (trade_id, other_trade_id), fake_table]}
            

            print("DEBUG: (seller) sending fake table")
            #Wait to recieve real table
            table = self.send_message(msg)
            if not table:
                return False
            pall_pub = table[0][0].public_key

            # Compute c vector
            y_volume_bits = auth_getvolumebits(abs(volume))
            c = []#[None]*VOLUME_NUM_BITS
            zero_enc = zero_encode(y_volume_bits)
            for t in zero_enc:
                n = len(y_volume_bits)-1
                x = None
                k = paillier.EncodedNumber.encode(pall_pub, random.randint(-pall_pub.n//3, pall_pub.n//3))
                for i in range(len(t)):
                    if x is None:
                        x = table[t[0]][i]
                    else:
                        x += table[t[i]][i]
                c.append(x*k)

            while len(c) < len(y_volume_bits):
                c.append(pall_pub.encrypt(random.randint(-pall_pub.n//3, pall_pub.n//3)))

            #for i in range(VOLUME_NUM_BITS):
            #    if y_volume_bits[i] == 0:
            #        val = table[1][i]
            #        k = random.randint(-pall_pub.n//3, pall_pub.n//3)
            #        for j in range(i+1, VOLUME_NUM_BITS):
            #            val += table[y_volume_bits[j]][j]
            #        val *= k
            #        c[i] = val
            #    else:
            #        c[i] = pall_pub.encrypt(random.randint(-pall_pub.n//3, pall_pub.n//3))

            random.shuffle(c)
            
            print("DEBUG: (seller) sending c")
            msg = {'method':'send_c', 'params': [c]}
            # Recieve fake c vector
            fake_c = self.send_message(msg)

            print("DEBUG: (seller) sending fake notify volume")
            # Send fake volume notification to get response from other client
            msg = {'method': 'notify_volume', 'params': [other_pub_key.encrypt(0, None)[0]]}
            buyer_notify = self.rsa_priv.decrypt(self.send_message(msg))
            
            print("DEBUG: (seller) sending minimum volume")
            # Send minimum volume if we need to
            if buyer_notify == 0:
                msg = {'method': 'send_min_volume', 'params': [other_pub_key.encrypt(abs(volume), None)[0]]}
                lower_vol = abs(volume)
                self.send_message(msg)
                print("(seller) Buy is Greater")
            else:
                msg = {'method': 'send_min_volume', 'params': [other_pub_key.encrypt(0, None)[0]]}
                lower_vol = self.rsa_priv.decrypt(self.send_message(msg))
                print("(seller) Sell is Greater")


            print("CLIENT: (seller) Completed trade {} with final volume = {}".format(self.waiting_trades[trade_id], lower_vol))

            print("PERF: Volume Calc time: {}".format(time.clock() - perf_time))
        if lower_vol != 0:
            msg = {'method': 'finish_trade', 'params': [trade_id]}
            self.send_message(msg)
            return True

        raise RuntimeError("Trade Matched, but not completed") 

    def query_trades(self):
        """
        Iterates over outstanding trades on server to search for match
        """
        msg = {'method': 'query_trades', 'params':[]}
        resp = self.send_message(msg, filter_trade_data=False)
        for trade_id, d in resp.items():
            keys = list(d.keys())
            random.shuffle(keys)
            for other_trade_id in keys:
                data = d[other_trade_id]
                other_pub_key = data[0]
                comp_cipher = data[1]
                decrypted = -1
                try:
                    decrypted = self.pall_keys[other_pub_key][1].decrypt_encoded(comp_cipher).decode()
                except OverflowError as e:
                    # Ignore overflows, we only care about 0
                    pass
                if decrypted == 0:
                    print("CLIENT - Match found {}: {} <=> {}".format(self.waiting_trades[trade_id], trade_id, other_trade_id))
                    # Attempt to open channel through CA and compute volume
                    if self.complete_trade(trade_id, other_trade_id, other_pub_key):
                        print("PERF: Match time: {}".format(time.clock() - self.perf_time))
                        del self.waiting_trades[trade_id]
                    else:
                        print("CLIENT - Match found but could not get lock {}: {} <=> {}".format(self.waiting_trades[trade_id], trade_id, other_trade_id))
                    return

    def run_test_case(self, trades):
        """
        Loads list of trades in order to simulate trades.
        trades := [{ticker: ticker, val: trade_value}, ...]
        """
        # Do trades
        TEST_TIMEOUT = 15
        TRADE_TEST_INTERVAL = 2
        print("TEST: trades = {}".format(trades))
        start_test_time = time.clock()
        self.perf_time = time.clock()
        for trade in trades:
            if not self.send_trade(trade):
                raise RuntimeError("CLIENT - Error sending trade: ".format(trade))
           # cur_time = trade_time = time.clock()
           # while cur_time - trade_time < TRADE_TEST_INTERVAL:
           #     self.query_trades()
           #     cur_time = time.clock()
        while len(self.waiting_trades) > 0:
            self.query_trades()
            time.sleep(0.1)

        print("CLIENT - Done Running Test Case")
