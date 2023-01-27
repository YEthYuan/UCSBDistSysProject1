import json
import time
from queue import Queue
import socket
import threading


class Server:
    def __init__(self, config: dict, sleep=False):
        self.data_queue = None
        self.udp_sock = None
        self.udp_thread = None
        self.config = config
        self.sleep = sleep

        self.routes = self.get_routes(config)

        self.balances = self.init_balance_dict(config)

        self.stop_udp_thread = False
        self.my_addr = self.get_my_ip_port(self.config)
        self.host, self.port = self.my_addr
        self.init_udp_recv_settings()
        self.start_listening()

    def reset_balances(self):
        self.balances = self.init_balance_dict(self.config)
        print("Balance table have been reset!")
        self.print_balance()

    def get_routes(self, config: dict) -> dict:
        ret = {}
        for c in config['clients']:
            ret[c['username']] = (c['ip'], c['port'])

        return ret

    def get_my_ip_port(self, pre_config) -> (str, int):
        """

        :return:
        """
        ip = pre_config['server']['ip']
        port = pre_config['server']['port']
        return ip, port

    def init_balance_dict(self, config: dict) -> dict:
        ret = {}
        for item in config['clients']:
            ret[item['username']] = item['balance']

        return ret

    def print_balance(self):
        print(" --- Balance Table --- ")
        for k, v in self.balances.items():
            print(f"{k}:\t\t{v}")
        print(" --------------------- ")

    def generate_packet_to_send(self, msg_item: str, msg_type: str) -> dict:
        """
        Packet definition:
        packet = {
            'type': c->c: ['client-request', 'client-release']
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
            'from': "Bank Server"
        }
        return packet

    def query_balance(self, username: str):
        return self.balances[username]

    def process_balance(self, payload: dict):
        username = payload['username']
        balance = self.query_balance(username)

        reply = {
            'username': username,
            'balance': balance
        }

        send_data = self.generate_packet_to_send(json.dumps(reply), 'server-balance')
        send_data = json.dumps(send_data)
        self.send_udp_packet(send_data, *self.routes[username])
        print(f"Replied the balance inquery to {username}")

    def get_transact(self, trans: dict) -> (str, str, int):
        """
        Returns the sender, receiver, and amount from a transaction dictionary

        :param trans:
        :return:
        """
        return trans["S"], trans["R"], trans["amt"]

    def process_transact(self, payload: dict):
        S, R, amount = self.get_transact(payload)
        S_balance = self.query_balance(S)
        reply = {}
        reply['username'] = S
        if S_balance >= amount:
            s_old = self.balances[S]
            r_old = self.balances[R]
            self.balances[S] -= amount
            self.balances[R] += amount
            print(f"Transact successfully! Balance change:")
            print(f"{S}: {s_old} ---> {self.balances[S]}")
            print(f"{R}: {r_old} ---> {self.balances[R]}")
            reply['status'] = 1
            reply['balance'] = self.balances[S]
        else:
            print(f"Transact failed!")
            print(f"The current balance of {S} is {S_balance}, ")
            print(f"But {S} wants to transfer {amount} to {R}!")
            print("The balance is not enough.")
            reply['status'] = 0
            reply['balance'] = self.balances[S]

        send_data = self.generate_packet_to_send(json.dumps(reply), 'server-status')
        send_data = json.dumps(send_data)

        if self.sleep:
            time.sleep(0.5)

        self.send_udp_packet(send_data, *self.routes[S])
        print(f"Transact replied to {S}")

    def listen_for_udp(self):
        while not self.stop_udp_thread:
            data, addr = self.udp_sock.recvfrom(1024)
            # print("Received data:", data)
            # print("From address:", addr)
            self.process_received_data(data)

    def init_udp_recv_settings(self):
        self.udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp_sock.bind(self.my_addr)

    def process_received_data(self, data):
        """
        Process the message stored in the message queue.
        """
        data = json.loads(data)
        if data['type'] == "client-balreq":
            print(f"==>Received balance query request from {data['from']}.")
            payload = data['item']
            payload = json.loads(payload)
            self.process_balance(payload)
        elif data['type'] == "client-transact":
            print(f"==>Received Transaction request from {data['from']}.")
            payload = data['item']
            payload = json.loads(payload)
            self.process_transact(payload)

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

    def start_listening(self):
        # Start the thread to listen for UDP packets
        self.udp_thread = threading.Thread(target=self.listen_for_udp)
        self.udp_thread.start()

    def stop_udp(self):
        self.stop_udp_thread = True
        self.udp_thread.join()


if __name__ == '__main__':
    pass