import socket

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.sendto("test".encode("utf-8"), ('localhost', 53))
print(sock.recv(1024).decode("utf-8"))
