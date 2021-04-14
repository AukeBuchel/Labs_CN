import socket
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# todo: watch out
host_port = ("127.0.0.1", 5378)
# host_port = ("3.121.226.198", 5378)
sock.connect(host_port)

while True:
    sock.sendall(input("> ").encode("utf-8"))
    data = sock.recv(4096)
    print(data.decode("utf-8"))
