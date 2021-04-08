import socket
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

host_port = ("127.0.0.1", 5378)
sock.connect(host_port)

sock.sendall(input("> ").encode("utf-8"))
data = sock.recv(4096)
print(data.decode("utf-8"))

while True:
    data = sock.recv(4096)
    print(data.decode("utf-8"))
