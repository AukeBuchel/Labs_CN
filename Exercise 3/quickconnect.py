import socket

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
host = ("3.121.226.198", 5382)

sock.connect()

sendstring = "RESET\n"
sock.sendall(sendString.encode("utf-8"))