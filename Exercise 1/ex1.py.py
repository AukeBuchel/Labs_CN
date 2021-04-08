import socket

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
host = ("3.121.226.198", 5378)
sock.connect(host)
