import hashlib
import json
import queue
import random
import socket

import sys
import threading
import time

from utils import *


class Client:
    def __init__(self, pid: int, username: str, config: dict, sleep=0):
        self.reply_list = {}
        self.bank_addr = None
        self.broadcast_list = []
        self.data_queue = None
        self.udp_thread = None
        self.udp_sock = None
        self.pid = pid
        self.username = username
        self.sleep = sleep
        self.event = threading.Event()

        self.config = self.config_internet(config)

        self.blockchain = self.init_blockchain()
        self.block_step = 1
        self.clock = 0
        self.balance = 0
        self.set_balance(config)
        self.routes = self.get_routes(config)

        self.stop_udp_thread = False
        self.my_addr = self.get_my_ip_port(config)
        self.host, self.port = self.my_addr
        self.init_udp_recv_settings()
        self.start_listening()

        self.send_balance_inquery(prompt=False)

    def transact(self, amount: int, to: str):
        print("-" * 30)
        print("Transaction Information:")
        print("Amount: ", amount)
        print("To: ", to)
        print("-" * 30)
        while True:
            user_input = input("Do you want to proceed? (Y/N)")
            if user_input.lower() == "y":
                # proceed with the function
                print("You have confirmed your transaction!")
                break
            elif user_input.lower() == "n":
                print("You have gave up your transaction! Nothing will be changed! Don't worry!")
                return
            else:
                print("Invalid input. Please enter Y or N.")

        transact = self.generate_transact(sender=self.username, receiver=to, amount=amount)
        self.update_my_clock(self.clock + 1)
        my_new_block = self.generate_block(transact=transact, prev_hash="")
        self.broadcast_request(my_new_block)
        self.insert_into_chain(my_new_block)

        self.wait_for_all_replies()
        print("[Prerequisite 1 met] All replies have received!")
        self.wait_to_be_queue_head()
        print("[Prerequisite 2 met] At the head of queue now!")
        # self.print_blockchain()

        self.send_transaction_request(transact)

    def wait_for_all_replies(self):
        while not all(self.reply_list.values()):
            pass

    def wait_to_be_queue_head(self):
        while self.blockchain[self.block_step]['pid'] != self.pid:
            pass

    def reset_reply_list(self):
        for k, v in self.reply_list.items():
            self.reply_list[k] = False

    def get_routes(self, config: dict) -> dict:
        ret = {}
        for c in config['clients']:
            ret[c['username']] = (c['ip'], c['port'])

        return ret

    def init_blockchain(self) -> list:
        ret = []
        dummy_head = {
            'timestamp': -1,
            'pid': -1,
            'transaction': {"S": "DummyBlockHead",
                            "R": "",
                            "amt": -1},
            'prev_block': -1
        }
        ret.append(dummy_head)
        head_hash = self.calculate_sum(dummy_head)
        dummy_tail = {
            'timestamp': sys.maxsize,
            'pid': sys.maxsize,
            'transaction': {"S": "DummyBlockTail",
                            "R": "",
                            "amt": -1},
            'prev_block': head_hash
        }
        ret.append(dummy_tail)

        return ret

    def send_fake_request(self):
        transact = self.generate_transact(sender=self.username, receiver="Fake", amount=0)
        self.update_my_clock(self.clock + 1)
        fake_block = self.generate_block(transact, prev_hash=hashlib.sha256("Fake".encode()).hexdigest())
        self.broadcast_request(fake_block)
        self.insert_into_chain(fake_block)
        print("Fake request has been broadcast, REMEMBER TO MANUALLY RELEASE AGAIN!")
        print("!!!NOTE: THIS FUNCTION COULD ONLY BE USED IN THE DEBUG CASE!!!")

    def send_fake_release(self):
        self.update_my_clock(self.clock + 1)
        release_msg = {
            'timestamp': self.clock,
            'pid': self.pid,
            'username': self.username,
            'status': 0
        }
        self.broadcast_release(release_msg)
        print("Fake release has been broadcast.")
        print("!!!NOTE: THIS FUNCTION COULD ONLY BE USED IN THE DEBUG CASE!!!")

    def print_blockchain(self) -> None:
        """
        Prints the input blockchain in a pretty format

        Args:
        blockchain: list: the blockchain to be printed

        Returns:
        None
        """
        for i, block in enumerate(self.blockchain):
            print(f'Block {i + 1}:')
            print(f'Timestamp: {block["timestamp"]}')
            print(f'PID: {block["pid"]}')
            print(f'Sender: {block["transaction"]["S"]}')
            print(f'Receiver: {block["transaction"]["R"]}')
            print(f'Amount: {block["transaction"]["amt"]}')
            print(f'Previous block hash: {block["prev_block"]}')
            print()

    def get_current_clock(self):
        return self.clock

    def get_current_balance(self):
        return self.balance

    def get_current_step(self):
        return self.block_step

    def set_balance(self, config: dict):
        for client in config['clients']:
            if self.username == client['username']:
                self.balance = client['balance']
                print(f"Balance: {self.balance}")

    def manually_modify_clock(self, new_clock: int):
        self.clock = new_clock
        print(f"My Clock successfully updated to {self.clock}")
        print("!!!NOTE: THIS FUNCTION COULD ONLY BE USED IN THE DEBUG CASE!!!")

    def get_my_ip_port(self, pre_config=None) -> (str, int):
        """

        :return:
        """
        if pre_config is None:
            if len(sys.argv) == 3:
                # Get "IP address" and the "port number" from argument 1 and argument 2
                ip = sys.argv[1]
                port = int(sys.argv[2])
                return ip, port
            else:
                print("Error in getting my ip and port!")
                exit(1)

        else:
            for client in pre_config['clients']:
                if self.username == client['username']:
                    ip = client['ip']
                    port = client['port']
                    return ip, port

    def calculate_sum(self, block: dict) -> str:
        cat_str = json.dumps(block).encode()
        ret = hashlib.sha256(cat_str).hexdigest()
        return ret

    def config_internet(self, config: dict) -> dict:
        for client in config['clients']:
            if self.username != client['username']:
                self.broadcast_list.append(client)
                self.reply_list[client['username']] = False

        self.bank_addr = (config['server']['ip'], config['server']['port'])

        return config

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

    def generate_block(self, transact: dict, prev_hash: str) -> dict:
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
        }
        :param transact:
        :param prev_hash:
        :return:
        """
        block = {
            'timestamp': self.clock,
            'pid': self.pid,
            'transaction': transact,
            'prev_block': prev_hash
        }
        return block

    def generate_packet_to_send(self, msg_item: str, msg_type: str) -> dict:
        """
        Packet definition:
        packet = {
            'type': c->c: ['client-request', 'client-reply'， 'client-release']
                    c->s: ['client-balreq', 'client-transact']
                    s->c: ['server-balance', 'server-status']
            'item': str (can be a dumped json string)
        }
        :param msg_item:
        :param msg_type:
        :return:
        """
        packet = {
            'type': msg_type,
            'item': msg_item,
            'from': self.username
        }
        return packet

    def update_block_step(self):
        self.block_step += 1
        print(f"Block step to {self.block_step}")

    def update_my_clock(self, new_ts: int):
        print(f"My clock update to {new_ts}")
        self.clock = new_ts

    def compare_two(self, a_ts: int, a_pid: int, b_ts: int, b_pid: int) -> int:
        """

        :param a_ts:
        :param a_pid:
        :param b_ts:
        :param b_pid:
        :return:
        """
        # print("Compare")
        # print(a_ts, a_pid, b_ts, b_pid)
        if a_ts < b_ts:
            return -1
        elif a_ts > b_ts:
            return 1
        else:
            if a_pid < b_pid:
                return -1
            elif a_pid > b_pid:
                return 1
            else:
                return 0

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

        while i < len(self.blockchain):
            prev_hash = self.calculate_sum(block=self.blockchain[i - 1])
            self.blockchain[i]['prev_block'] = prev_hash

            i += 1

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

    def broadcast_request(self, block: dict):
        self.reset_reply_list()
        payload = json.dumps(block)
        send_data = self.generate_packet_to_send(payload, 'client-request')
        send_data = json.dumps(send_data)
        if self.sleep == -1:
            sleep_time = random.uniform(0, 3)
            time.sleep(sleep_time)
        elif self.sleep:
            time.sleep(self.sleep)
        for c in self.broadcast_list:
            self.send_udp_packet(send_data, c['ip'], c['port'])
            print(f"Request sent to {c['username']}.")

    def process_request(self, payload: dict, sender: str):
        self.insert_into_chain(payload)
        self.update_my_clock(max(payload['timestamp'], self.clock) + 1)
        self.update_my_clock(self.clock+1)
        target_addr = self.routes[sender]
        self.send_reply(target_addr)
        print(f"Reply sent to {sender}.")

    def broadcast_release(self, release_payload: dict):
        self.update_block_step()
        payload = json.dumps(release_payload)
        send_data = self.generate_packet_to_send(payload, 'client-release')
        send_data = json.dumps(send_data)
        if self.sleep == -1:
            sleep_time = random.uniform(0, 3)
            time.sleep(sleep_time)
        elif self.sleep:
            time.sleep(self.sleep)
        for c in self.broadcast_list:
            self.send_udp_packet(send_data, c['ip'], c['port'])
            print(f"Release sent to {c['username']}.")

    def process_release(self, payload: dict):
        username = payload['username']
        status = payload['status']

        if status:  # the other user's transaction succeed
            print(f"{username}'s transaction success!")

        else:  # the other user's transaction failed
            print(f"{username}'s transaction fails!")

        self.update_my_clock(max(payload['timestamp'], self.clock) + 1)
        self.update_block_step()

    def send_reply(self, addr):
        payload = {
            'timestamp': self.clock,
            'pid': self.pid,
            'username': self.username
        }
        payload = json.dumps(payload)
        send_data = self.generate_packet_to_send(payload, 'client-reply')
        send_data = json.dumps(send_data)
        if self.sleep == -1:
            sleep_time = random.uniform(0, 3)
            time.sleep(sleep_time)
        elif self.sleep:
            time.sleep(self.sleep)
        self.send_udp_packet(send_data, *addr)

    def process_reply(self, payload: dict):
        sender = payload['username']
        sender_ts = payload['timestamp']
        sender_pid = payload['pid']
        self.reply_list[sender] = True
        self.update_my_clock(max(sender_ts, self.clock) + 1)

    def send_balance_inquery(self, prompt=True):
        payload = {
            'username': self.username
        }
        payload = json.dumps(payload)
        send_data = self.generate_packet_to_send(payload, 'client-balreq')
        send_data = json.dumps(send_data)
        # if self.sleep == -1:
        #     sleep_time = random.uniform(0, 3)
        #     time.sleep(sleep_time)
        # elif self.sleep:
        #     time.sleep(self.sleep)
        self.send_udp_packet(send_data, *self.bank_addr)
        if prompt:
            print("Balance inquery sent to the bank server!")

    def process_balance_inquery_reply(self, reply: dict):
        username = reply['username']
        balance = reply['balance']
        self.balance = balance
        print(f"*** [Balance Inquery] ***")
        print("The balance of your account:")
        print("Username: ", username)
        print("Balance: ", balance)

    def send_transaction_request(self, transact: dict):
        S, R, amount = self.get_transact(transact)
        payload = json.dumps(transact)
        send_data = self.generate_packet_to_send(payload, 'client-transact')
        send_data = json.dumps(send_data)
        if self.sleep == -1:
            sleep_time = random.uniform(0, 3)
            time.sleep(sleep_time)
        elif self.sleep:
            time.sleep(self.sleep)
        self.send_udp_packet(send_data, *self.bank_addr)
        print("Transaction request sent to the bank server!")
        print(f"  {S} ---------- send {amount} ----------> {R}")

    def process_transact_reply(self, reply: dict):
        username = reply['username']
        status = reply['status']
        balance = reply['balance']

        if status:  # transaction succeed
            print("Transaction successful!")
            print("Username: ", username)
            print(f"Your Balance: {self.balance} -> {balance}")
            self.balance = balance

        else:  # transaction failed
            print("Transaction failed! Maybe you should deposit more money!")
            print("Username: ", username)
            print(f"Your Balance: {balance}")
            self.balance = balance

        self.update_my_clock(self.clock + 1)

        release_msg = {
            'timestamp': self.clock,
            'pid': self.pid,
            'username': username,
            'status': status
        }

        self.broadcast_release(release_msg)

    def init_udp_recv_settings(self):
        self.udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp_sock.bind(self.my_addr)
        self.data_queue = queue.Queue()

    def start_listening(self):
        # Start the thread to listen for UDP packets
        self.udp_thread = threading.Thread(target=self.listen_for_udp)
        self.udp_thread.start()

    def listen_for_udp(self):
        while not self.stop_udp_thread:
            data, addr = self.udp_sock.recvfrom(1024)
            # print("Received data:", data)
            # print("From address:", addr)
            self.process_recv_data(data)

    def stop_udp(self):
        self.stop_udp_thread = True
        self.udp_thread.join()

    def process_recv_data(self, data):
        data = json.loads(data)
        if data['type'] == 'client-request':
            print(f"==>Received request data from another client {data['from']}.")
            payload = data['item']
            payload = json.loads(payload)
            self.process_request(payload, sender=data['from'])
        elif data['type'] == 'client-reply':
            print(f"==>Got reply from another client {data['from']}.")
            payload = data['item']
            payload = json.loads(payload)
            self.process_reply(payload)
        elif data['type'] == 'client-release':
            print(f"==>Client {data['from']} sent you a release.")
            payload = data['item']
            payload = json.loads(payload)
            self.process_release(payload)
        elif data['type'] == 'server-balance':
            print("==>Bank Server replied your balance inquery!")
            payload = data['item']
            payload = json.loads(payload)
            self.process_balance_inquery_reply(payload)
        elif data['type'] == 'server-status':
            print("==>Bank Server processed your transaction, see the detail below!")
            payload = data['item']
            payload = json.loads(payload)
            self.process_transact_reply(payload)


if __name__ == '__main__':
    pass
