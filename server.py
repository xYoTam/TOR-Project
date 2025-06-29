# Author: Yotam Barkan
import argparse
import os
import random
import socket
import sys
import threading
from datetime import datetime

from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA

from aes_functions import aes_encrypt, aes_decrypt
from tcp_by_size import send_with_size, recv_by_size

ip = ""

msg_not_arrive = "An error occurred while sending the message. The message did not arrive to the destination"
args_msg = "add arguments:\nIs main: <T> or <F>"

ERRORS_CODES = {'1': 'Error while trying to handle RSA', '2': 'Error while trying to decrypt the response',
                '3': 'General error in communication', '4': 'Error while trying to create message. cancelling message',
                '5': 'Error: there are no nodes active. cancelling message', '6': 'Error while returning message',
                '7': 'Error while sending a message to next destination', '8': 'Error while handling a message'}

IV_LENGTH = 16
SEPERATOR = '~'
TIMEOUT_SECONDS = 15

# Code messages:
ERROR_CODE = "ERRORR"
ACKNOWLEDGE = "ACKACK"
CODE_LENGTH = 6

NEW_CLIENT = "CLIENT"
NEW_TOR_NODE = "IMNODE"
NODE_INFO = "MYINFO"
NEW_MESSAGE = "LETTER"
PASS_TOR_MESSAGE = "PASTOR"
RETURN_TOR_MESSAGE = "RETTOR"
SEND_TO_DESTINATION = "URLAST"
CLOSING_NODE = "CLOSED"
STOPPED_DELIVERING_MESSAGE = "STOPPD"

START_RSA = "RUNRSA"
PUBLIC_KEY = "PUBLIC"
ENCRYPTION_KEY = "ENCKEY"


# ---------------------------------------------- 1. Encryptions:
class IEncryption:
    """
    an interface to encrypt and decrypt data.
    """
    name = ""

    @staticmethod
    def do_encrypt(data: bytes, key) -> bytes:
        iv = os.urandom(8).hex()
        to_send = iv.encode() + aes_encrypt(bdata=data, key=key, iv=iv)
        return to_send

    @staticmethod
    def do_decrypt(data: bytes, key) -> bytes:
        iv = data[:IV_LENGTH]
        to_decrypt = data[IV_LENGTH:]
        return aes_decrypt(iv=iv, encrypted_bdata=to_decrypt, key=key)


class Rsa:
    def __init__(self):
        cur_key = RSA.generate(2048)
        self.public_key = cur_key.publickey().exportKey()
        self.private_key = cur_key.exportKey()


# ---------------------------------------------- 2. TOR SERVERS:
# -------------------------- Regular node Tor:


class TorServer:
    def __init__(self):
        self.srv_sock = socket.socket()
        self.encryption_handler = IEncryption
        self.port = ""
        self.__sender_by_message_id = {}  # (prev_ip, prev_port, datetime.now())
        self.__key = None
        self.lock = threading.Lock()

    def start_server(self):
        threads = []
        i = 0
        # open a connection to deliver messages, and then connect to server
        try:
            # This is the socket for communicating with the main server
            socket_with_main_srv = socket.socket()
            socket_with_main_srv.connect((ip, 9001))
        except Exception as err:
            print("Error: Can't start a connection with main Tor server- " + str(err) + '\n')
            return

        send_with_size(socket_with_main_srv, NEW_TOR_NODE.encode())
        # Open a connection for delivering message (Tor business logic)
        self.srv_sock.bind(('', 0))
        self.port = str(self.srv_sock.getsockname()[1])
        self.srv_sock.listen()
        try:  # catch Keyboard interrupt
            # Send main server my info
            try:
                my_info = NODE_INFO + SEPERATOR + self.port
                send_with_size(socket_with_main_srv, my_info.encode())
                key = self.__start_rsa(socket_with_main_srv)
                if key[:CODE_LENGTH] == ERROR_CODE:
                    self.__close(socket_with_main_srv)
                    return
                self.__key = key
            except Exception as e:
                print(f"General Error in communication: {e}")
                self.__close(socket_with_main_srv)
                return

            self.srv_sock.settimeout(1)
            while True:  # start receiving messages
                try:
                    sock, addr = self.srv_sock.accept()
                    t = threading.Thread(target=self.handle_new_connection, args=(sock, str(i), addr))
                    t.start()
                    i += 1
                    threads.append(t)
                    if i > 100000000:
                        print('\nMain thread: going down for maintenance')
                        break
                    self.__remove_messages_by_ids()
                except socket.timeout:
                    pass
                except Exception as e:
                    print(f"General Error in communication: {e}")
                    break
        except KeyboardInterrupt:
            send_with_size(socket_with_main_srv, CLOSING_NODE.encode())

        for t in threads:
            t.join()
        print('closing node')
        self.__close(socket_with_main_srv)
        sys.exit()

    def __remove_messages_by_ids(self):
        self.lock.acquire()
        remove = []
        for k, v in self.__sender_by_message_id.items():  # remove timed out messages
            difference = (datetime.now() - v[2]).total_seconds()
            if difference > TIMEOUT_SECONDS:
                remove.append(k)
                print(f"Time out: Removed message number {k} -> {v}")
        for k in remove:
            self.__sender_by_message_id.pop(k)
        self.lock.release()

    def __start_rsa(self, socket_with_main_srv):
        """
        handles the rsa part of connection
        :param socket_with_main_srv: socket with the main tor server
        :return: final aes key if not error
        """
        data = recv_by_size(socket_with_main_srv)
        if data[:CODE_LENGTH].decode() != START_RSA:
            print(ERRORS_CODES['3'])
            return ERROR_CODE
        send_with_size(socket_with_main_srv, ACKNOWLEDGE.encode())
        key = self.do_rsa(socket_with_main_srv)
        if key[:CODE_LENGTH] == ERROR_CODE:
            print(ERRORS_CODES[key.split(SEPERATOR)[1]])
            return ERROR_CODE
        return key

    def __close(self, socket_with_main_srv):
        socket_with_main_srv.close()
        self.srv_sock.close()

    def handle_new_connection(self, sock, tid, addr):
        print(f"New client {tid} connection on {addr}")
        try:
            data = recv_by_size(sock)
            check = None
            if data != b'':
                if data[:CODE_LENGTH].decode() == PASS_TOR_MESSAGE:
                    check = self.tor(data[CODE_LENGTH + 1:], addr)
                if data[:CODE_LENGTH].decode() == RETURN_TOR_MESSAGE:
                    check = self.return_message(data[CODE_LENGTH + 1:])
                if data[:CODE_LENGTH].decode() == STOPPED_DELIVERING_MESSAGE:
                    check = self.tor_didnt_work(data[CODE_LENGTH + 1:].decode())
                if check is not None:
                    if check[:CODE_LENGTH] == ERROR_CODE:
                        print(ERRORS_CODES[check.split(SEPERATOR)[1]])
        except Exception as e:
            print(f"Error : {e}")
        sock.close()
        print(f"Closed connection with client {addr}")

    def tor(self, message, addr):
        """
        decrypt the message it got and passes to next node
        :param message: prev port + encrypted onion from last node: port~encrypted_onion
        :param addr: addr of node who sent the message to know who to return this message to
        :return:
        """
        msg_id = None
        try:
            # Get the previous port and ip to return an answer later (who sent this current message)
            fields = message.split(SEPERATOR.encode(), 1)
            prev_port = fields[0]
            prev_ip = addr[0]

            dec_msg = self.encryption_handler.do_decrypt(fields[1], self.__key)
            is_final = dec_msg[:CODE_LENGTH] == SEND_TO_DESTINATION.encode()  # if this is the final station, send
            if is_final:
                dec_msg = dec_msg[CODE_LENGTH + 1:]
            # the raw message to the final destination
            fields = dec_msg.split(SEPERATOR.encode(), 3)
            if len(fields) != 4:
                return ERROR_CODE + SEPERATOR + '8'
            msg_id = fields[0].decode()
            IP = fields[1].decode()
            port = fields[2].decode()
            msg = fields[3]

            to_send = msg if is_final else (PASS_TOR_MESSAGE + SEPERATOR + str(self.port) + SEPERATOR).encode() + msg
            self.lock.acquire()
            self.__sender_by_message_id[msg_id] = (
                prev_ip, prev_port, datetime.now())  # previous node ip, port by the message id & when message was sent
            self.lock.release()
            data = self.send_to_next(IP, port, to_send)
            if data is not None and isinstance(data, str) and ERROR_CODE in data:
                # if the next server is not active then send back to the main server that the message stopped
                self.tor_didnt_work(msg_id)
            if isinstance(data, bytes) and data != b'' and data is not None:
                return self.__start_return(data,
                                           msg_id)  # send the response back. if an error occurred while sending back the message it will return the error code else it will return None
        except Exception as e:
            print(e)
            if msg_id is not None:
                # if an error occurred while sending the message tell the main server that the delivering of the msg stopped
                self.tor_didnt_work(msg_id)

    def tor_didnt_work(self, msg_id):
        self.lock.acquire()
        if msg_id in self.__sender_by_message_id:
            prev_ip, prev_port, time = self.__sender_by_message_id[msg_id]
            self.__sender_by_message_id.pop(msg_id)
            to_send = STOPPED_DELIVERING_MESSAGE + SEPERATOR + msg_id
            return self.send_to_next(prev_ip, prev_port, to_send.encode())
        self.lock.release()

    def return_message(self, data):
        try:
            fields = data.split(SEPERATOR.encode(), 1)
            ID = fields[0].decode()
            IP, port, time = self.__sender_by_message_id[ID]

            message = fields[1]
            message = self.encryption_handler.do_encrypt(message, self.__key)
            to_send = (RETURN_TOR_MESSAGE + SEPERATOR + ID + SEPERATOR).encode() + message
            self.send_to_next(IP, port, to_send)
        except KeyError:
            print('this message ID is not active')
            return ERROR_CODE + SEPERATOR + '6'
        except Exception as e:
            print(e)
            return ERROR_CODE + SEPERATOR + '6'

    def __start_return(self, response: bytes, ID: str):
        """
        start of returning message process.
        send to the prev node: RETURN_TOR_MESSAGE~ID~first_encryption_msg
        :param response: response from destination
        :param ID: msg_id
        :return:
        """
        try:
            enc_response = self.encryption_handler.do_encrypt(response, self.__key)  # encrypt response
            to_send = (RETURN_TOR_MESSAGE + SEPERATOR + ID + SEPERATOR).encode()
            to_send += enc_response
            IP, port, time = self.__sender_by_message_id[ID]
            self.send_to_next(IP, port, to_send)
            with self.lock:
                self.__sender_by_message_id.pop(ID)
                print(f"Removed {ID} because the message arrived")
        except Exception as e:
            print(e)
            return ERROR_CODE + SEPERATOR + '6'

    def send_to_next(self, IP, port, to_send: bytes):
        """
        send data to next node/ destination. returns response if there's any
        :param IP: next dest ip
        :param port: next dest port
        :param to_send: data to send
        :return: response from dest (if there is any)
        """
        next_node_sock = socket.socket()
        try:
            next_node_sock.connect((IP, int(port)))
            send_with_size(next_node_sock, to_send)
            next_node_sock.settimeout(2)
            data = recv_by_size(next_node_sock)
            next_node_sock.close()
            return data
        except socket.timeout:
            # This means no answer were sent, so 2 options:
            # 1. the answer has arrived to its final destination and the dest didn't respond back
            # 2. it was sent to a normal node Tor which will continue to pass the message
            next_node_sock.close()
        except Exception as e:
            print(e)
            return ERROR_CODE + SEPERATOR + '7'

    def do_rsa(self, sock):
        try:
            public_key = recv_by_size(sock)
            if public_key[:CODE_LENGTH].decode() != PUBLIC_KEY:
                return ERROR_CODE + "~" + "1"
            public_key = public_key[CODE_LENGTH + 1:]
            final_key = os.urandom(32)
            print("---------------------------")
            print(final_key)
            print("---------------------------")
            cipher = PKCS1_OAEP.new(RSA.importKey(public_key))
            encrypted_key = cipher.encrypt(final_key)
            send_with_size(sock, (ENCRYPTION_KEY + '~').encode() + encrypted_key)
            # Get acknowledge from server
            data = recv_by_size(sock)
            data = self.encryption_handler.do_decrypt(data, final_key)
            if data != ACKNOWLEDGE.encode():
                return ERROR_CODE + "~" + "1"
            return final_key
        except Exception as e:
            print(e)
            return ERROR_CODE + "~" + "1"


# ---------------------------------------------------- Main Tor server:
# ---------------------------------------------------- Main Tor server:
# ---------------------------------------------------- Main Tor server:


class MainTorServer(TorServer):
    def __init__(self):
        super().__init__()
        self.handle_rsa = Rsa()
        self.port = 9001
        self.nodes_by_id = {}  # Nodes id points to the nodes info: (node_ip, node_port, final_key)
        self.active_nodes_id = []  # id's of active nodes
        self.active_message_ids = set()  # set for message ids that are in use/ not in use
        self.route_by_id = {}
        self.message_by_id = {}

    def start_server(self):
        threads = []

        self.srv_sock.bind(('0.0.0.0', self.port))
        self.srv_sock.listen()
        # next line release the port
        self.srv_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        i = 1
        while True:
            print('\nMain thread: before accepting ...')
            sock, addr = self.srv_sock.accept()
            t = threading.Thread(target=self.handle_new_connection, args=(sock, str(i), addr))
            t.start()
            i += 1
            threads.append(t)
            if i > 100000000:
                print('\nMain thread: going down for maintenance')
                break

    def handle_new_connection(self, sock, tid, addr):
        try:
            data = recv_by_size(sock)
            if data[:CODE_LENGTH].decode() == NEW_CLIENT:  # handle new client
                self.handle_client(sock, tid, addr)
            elif data[:CODE_LENGTH].decode() == NEW_TOR_NODE:  # handle new tor node
                self.handle_node(sock, tid, addr)
            elif data[:CODE_LENGTH].decode() == RETURN_TOR_MESSAGE:  # handle a response from destination
                self.handle_responses(data[CODE_LENGTH + 1:])
            elif data[:CODE_LENGTH].decode() == STOPPED_DELIVERING_MESSAGE:
                self.tor_didnt_work(data[CODE_LENGTH + 1:])
            else:
                sock.close()
        except Exception as e:
            print(e)
            sock.close()

    def tor_didnt_work(self, msg_id):
        self.message_by_id[msg_id.decode()] = msg_not_arrive

    def handle_responses(self, data):
        """
        decrypt the response by onion. if route is 1, 2, 3 then decrypt with key1, key2, key3
        :param data: msg_id~onion_layers_message
        :return:
        """
        try:
            fields = data.split(SEPERATOR.encode(), 1)
            ID = fields[0].decode()
            enc_msg = fields[1]
            route = self.route_by_id[ID]
            for i in range(len(route)):
                cur_key = self.nodes_by_id[route[i]][2]
                enc_msg = self.encryption_handler.do_decrypt(enc_msg, cur_key)
            self.message_by_id[ID] = enc_msg
        except Exception as e:
            print(e)
            print(ERRORS_CODES['2'])

    def handle_client(self, sock, tid, addr):
        print(f"New client {tid} connection on {addr}")
        my_ids = []  # list of which IDs are of this thread's client, so you can send him the response + the time of the arrival of message
        while True:
            try:
                sock.settimeout(2)
                data = recv_by_size(sock)
                if data == b'':
                    break
                if data[:CODE_LENGTH].decode() == NEW_MESSAGE:
                    msg_id = self.tor(data[CODE_LENGTH + 1:], addr)
                    if isinstance(msg_id, str) and ERROR_CODE in msg_id:
                        print(ERRORS_CODES[msg_id.split(SEPERATOR)[1]])
                        if '5' in msg_id:
                            send_with_size(sock, ERRORS_CODES['5'].encode())
                    elif msg_id is not None:
                        my_ids.append((msg_id, datetime.now()))

            except socket.timeout:
                self.remove_messages(my_ids, sock)
            except Exception as e:
                print(f"Error : {e}")
                break
        sock.close()
        print(f"Closed connection with client {addr}")

    def remove_messages(self, my_ids, sock):
        """
        remove messages - send to client if message arrived / remove if timeout
        :param my_ids: my client's messages ids
        :param sock: client sock
        """
        self.lock.acquire()
        remove = []
        # my_ids = list of tuples: (msg_id, time_of_arrival)
        for msg_info in my_ids:
            message = self.message_by_id.get(msg_info[0])
            if message is not None:
                send_with_size(sock, message)
                self.message_by_id.pop(msg_info[0])
                remove.append(msg_info)
                print(f"Removed message number {msg_info}, answer arrived")
            elif (datetime.now() - msg_info[1]).total_seconds() > TIMEOUT_SECONDS:
                remove.append(msg_info)
                print(f"Time out: Removed message number {msg_info[0]}, time of arrival {msg_info[1]}")
        for k in remove:
            self.release_message_id(k[0])
            my_ids.remove(k)

        self.lock.release()

    def tor(self, full_message, addr):
        try:
            how_many_active = len(self.active_nodes_id)
            if how_many_active == 0:
                return ERROR_CODE + SEPERATOR + '5'
            if how_many_active == 1 or how_many_active == 2 or how_many_active == 3:
                route_length = how_many_active
            else:
                route_length = random.randint(3, how_many_active)
                if route_length > 5:
                    route_length = 5
            route = random.sample(self.active_nodes_id, route_length)
            msg_id = self.get_free_message_id()
            IP, port, message = self.layer_encryption(full_message.decode(), msg_id, route)
            if None in (IP, port, message):
                return ERROR_CODE + SEPERATOR + '4'
            to_send = (PASS_TOR_MESSAGE + SEPERATOR + str(self.port) + SEPERATOR).encode() + message

            self.route_by_id[msg_id] = route
            check = self.send_to_next(IP, port, to_send)
            if check is not None and isinstance(check, str) and ERROR_CODE in check:
                return check
            return msg_id
        except Exception as e:
            print(e)

    def layer_encryption(self, full_message: str, message_id: str, route: list):
        """
        in this function happens the layers encryptions.
        the encryption is by the route of the message where the first layer is
        msg_id~final_dst_ip~final_dst_port~msg

        and then every other layer is
        msg_id~next_node_in_route_ip~next_node_in_route_port~last_layer
        -------------==========================================-------------
        :param full_message: full message from the client (final_dst_ip~final_dst_port~msg)
        :param message_id: id of this message submission
        :param route: list of ID's of the nodes in this route
        :return: The message after all layers encryptions
        """
        try:
            # First part: handle the inner layer of the "onion" where it has the message itself and path to the destination
            fields_of_message = full_message.split(SEPERATOR)  # The message from client is built like : ip~port~msg

            layer_info = SEND_TO_DESTINATION + SEPERATOR  # SEND_TO_DESTINATION means that this is the last station
            layer_info += message_id + SEPERATOR + fields_of_message[0] + SEPERATOR + fields_of_message[1]
            route.reverse()  # first encryption is with the last node in route and so on
            cur_key = self.nodes_by_id[route[0]][2]  # the first key of encryption (inner layer)
            # is the key of the last node in the route. (he delivers it to the destination)
            msg = layer_info + SEPERATOR + fields_of_message[2]
            msg = self.encryption_handler.do_encrypt(msg.encode(),
                                                     cur_key)  # encrypt the path and the msg with last node

            IP = self.nodes_by_id[route[len(route) - 1]][0]
            port = self.nodes_by_id[route[len(route) - 1]][1]

            # Second part: handle all other layers.
            for i in range(0, len(route) - 1):
                layer_info = message_id + SEPERATOR  # msg id
                layer_info += self.nodes_by_id[route[i]][0] + SEPERATOR  # next node ip
                layer_info += self.nodes_by_id[route[i]][1]  # next node port
                msg = (layer_info + SEPERATOR).encode() + msg
                cur_key = self.nodes_by_id[route[i + 1]][2]
                msg = self.encryption_handler.do_encrypt(msg,
                                                         cur_key)  # encrypt the layer info and message with cur node

            route.reverse()  # return route back to normal
            return IP, port, msg
        except Exception as e:
            print(e)
            return None, None, None

    def get_free_message_id(self):
        self.lock.acquire()
        try:
            for i in range(1, 65536):
                if i not in self.active_message_ids:
                    self.active_message_ids.add(i)
                    self.lock.release()
                    return str(i)
        except RuntimeError:
            print("No free message ID available")
        self.lock.release()

    def release_message_id(self, msg_id):
        try:
            self.active_message_ids.remove(int(msg_id))
        except Exception as e:
            print(e)
            return

    def handle_node(self, node_sock, tid, addr):
        try:
            print(f"new tor server number {tid} connection on {addr}")
            node_data = recv_by_size(sock=node_sock)
            if node_data[:CODE_LENGTH].decode() != NODE_INFO:
                node_sock.close()
                print(f"closed connection with {addr}")
                return
            check = self.handle_data(node_data, node_sock, tid, addr)
            if check is not None:
                if check[:CODE_LENGTH] == ERROR_CODE:
                    print(ERRORS_CODES[check.split(SEPERATOR)[1]])
                self.close_connection(node_sock, addr, tid)
                return
        except Exception as e:
            print(e)
        while True:
            try:
                data = recv_by_size(node_sock)
                if data == b'':
                    break
                data = self.handle_data(data, node_sock, tid, addr)
                if isinstance(data, str) and data == CLOSING_NODE:
                    break
            except Exception as e:
                print(e)
                break

        self.close_connection(node_sock, addr, tid)

    def close_connection(self, node_sock, addr, node_id):
        self.remove_node(node_id)
        node_sock.close()
        print(f"closed connection with {addr}")

    def remove_node(self, node_id):
        try:
            self.lock.acquire()
            self.nodes_by_id.pop(node_id)
            self.active_nodes_id.remove(node_id)
            print(f"ONE TIME REMOVED {node_id}")
        except KeyError:
            print("SECOND TIME ERROR")
        self.lock.release()

    def handle_data(self, b_data, node_sock, tid, addr):
        try:
            code = b_data[:CODE_LENGTH].decode()
            fields = b_data[CODE_LENGTH + 1:].decode().split(SEPERATOR)
            check = None
            if code == NODE_INFO:
                check = self.add_new_node(addr[0], fields[0], node_sock, tid)
            elif code == CLOSING_NODE:
                return CLOSING_NODE
            return check
        except Exception as e:
            print(f"Error while handling data: {e}")
            return ERROR_CODE + SEPERATOR + '3'

    def add_new_node(self, node_ip, node_port, sock, node_id):
        final_key = self.do_rsa(sock)
        if final_key[:CODE_LENGTH] == ERROR_CODE.encode():
            return final_key
        self.lock.acquire()
        self.nodes_by_id[node_id] = (node_ip, node_port, final_key)
        self.active_nodes_id.append(node_id)
        self.lock.release()

    def do_rsa(self, sock):
        try:
            send_with_size(sock, START_RSA.encode())
            data = recv_by_size(sock)
            if data.decode() != ACKNOWLEDGE:
                return ERROR_CODE + SEPERATOR + "1"
            send_with_size(sock, (PUBLIC_KEY + SEPERATOR).encode() + self.handle_rsa.public_key)
            enc_key = recv_by_size(sock)
            if enc_key[:CODE_LENGTH].decode() != ENCRYPTION_KEY:
                return ERROR_CODE + SEPERATOR + "1"
            enc_key = enc_key[CODE_LENGTH + 1:]
            cipher = PKCS1_OAEP.new(RSA.importKey(self.handle_rsa.private_key))  # make the object which decrypts
            final_key = cipher.decrypt(enc_key)

            send_enc_ack = self.encryption_handler.do_encrypt(ACKNOWLEDGE.encode(), final_key)
            send_with_size(sock, send_enc_ack)

            print('--------------------------')
            print(final_key)
            print('--------------------------')
            return final_key
        except Exception as e:
            print(f'Error while doing RSA: {e}')
            return ERROR_CODE + SEPERATOR + "1"


# ---------------------------------------------- 3. Main program:


def main():
    global ip
    parser = argparse.ArgumentParser(description="Start a Tor server.")
    parser.add_argument("--main", action="store_true", help="Set this if this is the main server.")
    args = parser.parse_args()

    if args.main:
        tor = MainTorServer()
    else:
        ip = input("Enter main server IP address: ")
        tor = TorServer()

    tor.start_server()


if __name__ == "__main__":
    main()
