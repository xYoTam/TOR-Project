import socket
from tcp_by_size import send_with_size, recv_by_size
from datetime import datetime

sock = socket.socket()
sock.bind(('0.0.0.0', 1234))
sock.listen()
while True:
    try:
        print("waiting")
        cli_sock, addr = sock.accept()

        data = recv_by_size(cli_sock)
        print(data)
        if data == b'TIME':
            x = str(datetime.now())
            send_with_size(cli_sock, x.encode())
    except Exception as e:
        print(e)
        sock.close()

