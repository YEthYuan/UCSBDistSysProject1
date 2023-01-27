import hashlib
import json
import queue
import socket

import sys
import threading

class Client:
    def __init__(self, pid: int, username: str):
        self.data_queue = None
        self.udp_thread = None
        self.udp_sock = None
        self.pid = pid
        self.username = username

        self.blockchain = []
        self.clock = 0

        self.my_addr = self.get_my_ip_port()
        self.host, self.port = self.my_addr
        self.init_udp_recv_settings()
        self.start_listening()

    def get_my_ip_port(self) -> (str, int):
        """

        :return:
        """
        if len(sys.argv) == 3:
            # Get "IP address" and the "port number" from argument 1 and argument 2
            ip = sys.argv[1]
            port = int(sys.argv[2])
            return ip, port
        else:
            print("Error in getting my ip and port!")
            exit(1)

    def calculate_sum(self, block: dict) -> str:
        cat_str = json.dumps(block).encode()
        ret = hashlib.sha256(cat_str).hexdigest()
        return ret

    def generate_transact(self, sender: str, receiver: str, amount: int) -> dict:
        """
        Generates a transaction dictionary

        :param sender:
        :param receiver:
        :param amount:
        :return:
        """
        ret = {
            "S": sender,
            "R": receiver,
            "amt": amount
        }
        return ret

    def get_transact(self, trans: dict) -> (str, str, int):
        """
        Returns the sender, receiver, and amount from a transaction dictionary

        :param trans:
        :return:
        """
        return trans["S"], trans["R"], trans["amt"]

    def generate_block_to_send(self, transact: dict, prev_hash: str) -> dict:
        """
        Block structure definition:
        block = {
            'timestamp': int,
            'pid': int,
            'transaction': {
                'S': str,
                'R': str,
                'amt': int
            },
            'prev_block': str (sha256 hash),
            'status': ['pending', 'finished']
        }
        :param transact:
        :param prev_hash:
        :return:
        """
        block = {
            'timestamp': self.clock,
            'pid': self.pid,
            'transaction': transact,
            'prev_block': prev_hash,
            'status': 'pending'
        }
        return block

    def update_my_clock(self, new_ts: int):
        self.clock = new_ts

    def compare_clock(self, a: dict, b: dict) -> int:
        """

        :param a:
        :param b:
        :return:
        """
        if a['timestamp'] < b['timestamp']:
            return -1
        elif a['timestamp'] > b['timestamp']:
            return 1
        else:
            if a['pid'] < b['pid']:
                return -1
            elif a['pid'] > b['pid']:
                return 1
            else:
                return 0

    def insert_into_chain(self, new_block: dict):
        i = 0
        for i in range(len(self.blockchain)):
            curr_blk = self.blockchain[i]
            if self.compare_clock(curr_blk, new_block) == 1:
                break

        self.blockchain = self.blockchain[:i] + [new_block] + self.blockchain[i:]

    def send_udp_packet(self, data: str, host: str, port: int):
        """
        Sends a UDP packet to a specified host and port

        Args:
        data: str: the message you want to send
        host: str: the destination IP address
        port: int: the destination port

        Returns:
        None

        """
        # Create a socket object
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            # Send the packet
            sock.sendto(data.encode(), (host, port))
        finally:
            # Close the socket
            sock.close()

    def init_udp_recv_settings(self):
        self.udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp_sock.bind(self.my_addr)
        self.data_queue = queue.Queue()

    def start_listening(self):
        # Start the thread to listen for UDP packets
        self.udp_thread = threading.Thread(target=self.listen_for_udp)
        self.udp_thread.start()

    def listen_for_udp(self):
        while True:
            data, addr = self.udp_sock.recvfrom(1024)
            self.data_queue.put(data)

    def process_recv_data(self):
        while True:
            data = self.data_queue.get()
            # Do something with the received data
            # print(data.decode())
            data = json.load(data)
            self.insert_into_chain(data)
            self.update_my_clock(data['timestamp']+1)


if __name__ == '__main__':
    pass
