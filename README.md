# TOR-Project
How to Run:

Start the main server using:
python server.py --main

Launch as many relay nodes as you want by running:
python server.py
and enter the main Tor server IP

Start the client GUI with:
python client.py
and enter the main Tor server IP
and enjoy the secure networking!

💡 You can test the communication using destination_server.py, which returns the current time when you send the message "TIME".
 
An explanation about the programs:

1. server.py: serves as both the main server (when run with --main) and as relay nodes.
Main server is the "entry node", handling client connections, building the route, and layering the AES encryption.
The relay node, handles forwarding encrypted messages. Each relay only knows its previous and next hop to preserve anonymity.

2. client.py: a simple GUI that connects to the main server. It sends a message along with the destination's IP and port.
The main server handles all routing and encryption, so the client stays lightweight.

3. destination_server.py: A server to check the project. It will return the current time after sending 
