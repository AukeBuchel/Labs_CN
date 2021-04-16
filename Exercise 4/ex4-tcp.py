import socket

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
host = ("localhost", 5379)
sock.bind(host)
sock.listen()

(client, address) = sock.accept()
print(client.recv(4096).decode("utf-8"))
