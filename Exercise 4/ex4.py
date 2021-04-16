import socket

# setup the local server (UDP/53)
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
host = ("localhost", 2040)
sock.bind(host)

# data is the received data (dynamic?)
# addr is a tuple that we need to use with .sendto(<newdata>, <addrTuple>)
data, addr = sock.recvfrom(4096)
print(addr)
print(data.encode("utf-8"))
sock.sendto("yoooo".encode("utf-8"), addr)
