import struct
import datetime

from Crypto.Cipher import AES
from . import crypto_utils
from dh import create_dh_key, calculate_dh_secret
from Crypto.Hash import HMAC
from Crypto.Hash import SHA256

timestamp_format = "%d-%m-%Y %H:%M:%S:%f"
timestamp_length = 26

class StealthConn(object):
    def __init__(self, conn, client=False, server=False, verbose=False):
        self.conn = conn
        self.cipher = None
        self.client = client
        self.server = server
        self.verbose = verbose
        self.block_size = 16  # bytes (128-bit)
        self.iv = None  # initialization variable
        self.key = None
        self.time_of_last_communication = None
        self.initiate_session()

    def initiate_session(self):
        # Perform the initial connection handshake for agreeing on a shared secret 
        self.time_of_last_communication = datetime.datetime.now()
        # Project code here...
        # This can be broken into code run just on the server or just on the client
        if self.server or self.client:
            my_public_key, my_private_key = create_dh_key()
            # Send them our public key
            self.send(bytes(str(my_public_key), "ascii"))
            # Receive their public key
            their_public_key = int(self.recv())
            # Obtain our shared secret
            shared_hash = calculate_dh_secret(their_public_key, my_private_key)
            print("Shared hash: {}".format(shared_hash))

        # Default XOR algorithm can only take a key of length
        # 32 (4 byte) and insecure, hence changed to a block
        # cipher (AES). We are using AES-256 (key is 32 byte string).

        self.iv = shared_hash[:16]  # from week 04 lecture, block size is 128-bits. Using first 16 bytes of shared_hash.
        self.key = shared_hash[32:]  # from week 04 lecture, key length up to 256-bits. Using last 32 bytes of shared_hash.
        self.cipher = AES.new(self.key, AES.MODE_CBC, self.iv) #dlitz.net/software/pycrypto/api/current/Crypto.Cipher.AES-module.html

    def send(self, data):
        if self.cipher:
            hmac = HMAC.new(((self.key).encode("ascii")), digestmod=SHA256)
            data_with_hmac = bytes(hmac.hexdigest() + data.decode("ascii"), "ascii")

            present_time = datetime.datetime.now()
            timestr = datetime.datetime.strftime(present_time, timestamp_format)  # format the timestamp
            data_with_hmac = bytes(timestr, 'ascii') + data_with_hmac  # prepend it to the message
            
            # Need to pad the data to 16 bytes.
            padded_data = crypto_utils.ANSI_X923_pad(data_with_hmac, self.block_size)
            encrypted_data = self.cipher.encrypt(padded_data)

            if self.verbose:
                print("Original data: {}".format(data))
                print("Encrypted data: {}".format(repr(encrypted_data)))
                print("Sending packet of length {}".format(len(encrypted_data)))
        else:
            encrypted_data = data  # not encrypted...

        # Encode the data's length into an unsigned two byte int ('H')
        pkt_len = struct.pack('H', len(encrypted_data))
        self.conn.sendall(pkt_len)
        self.conn.sendall(encrypted_data)

    def recv(self):
        # Decode the data's length from an unsigned two byte int ('H')
        pkt_len_packed = self.conn.recv(struct.calcsize('H'))
        unpacked_contents = struct.unpack('H', pkt_len_packed)
        pkt_len = unpacked_contents[0]

        encrypted_data = self.conn.recv(pkt_len)
        if self.cipher:
            padded_data = self.cipher.decrypt(encrypted_data)
            data = crypto_utils.ANSI_X923_unpad(padded_data, self.block_size)
            secret = (self.key).encode("ascii")

            timestamp = str(data[:timestamp_length], 'ascii')
            data = data[timestamp_length:]

            this_msg_time = datetime.datetime.strptime(timestamp, timestamp_format)
            if this_msg_time <= self.time_of_last_communication:
                print("Replay attack detected!")
            else:
                print("Timestamp is good.")

            self.time_of_last_communication = this_msg_time

            hmac2 = HMAC.new(secret, digestmod=SHA256)
            hmac = data[:hmac2.digest_size * 2]
            data = data[hmac2.digest_size * 2:]

            if hmac2.hexdigest() == str(hmac, "ascii"):
                print ("HMAC matches!")
                print (hmac2.hexdigest())
                print (str(hmac, "ascii"))
            else:
                print ("HMAC doesn't match!")

            if self.verbose:
                print("Receiving packet of length {}".format(pkt_len))
                print("Encrypted data: {}".format(repr(encrypted_data)))
                print("Original data: {}".format(data))
        else:
            data = encrypted_data

        return data

    def close(self):
        self.conn.close()
