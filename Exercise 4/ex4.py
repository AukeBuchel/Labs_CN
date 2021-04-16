import socket
import struct  # byte ordering

# ============= USED IN PROD =========================
# # setup the local server (UDP/53)
# sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
# host = ("192.168.0.215", 53)
# sock.bind(host)

# # data is the received data (dynamic?)
# # addr is a tuple that we need to use with .sendto(<newdata>, <addrTuple>)
# while True:
#     data, addr = sock.recvfrom(4096)
#     print(addr)
#     print(data)
#     sock.sendto("ELIAS-RESPONSE-DNS".encode("utf-8"), addr)
# #sock.sendto("yoooo".encode("utf-8"), addr)
# =====================================================

# for now, we just use a hardcoded byte string
UDPcontent = b'\x0e\xdb\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01'

# see explanation below
DNSheader = struct.Struct("!6H")

# get all header rows (6 H's of 2 bytes)
id, flagsRaw, qdcount, ancount, nscount, arcount = DNSheader.unpack_from(
    UDPcontent)

# we cannot access individual bits, so we use AND operations. (see also wireshark logs > Flags)
flags = {
    # 1000000000000000 dec = 8000 hex (first bit)
    'QR': flagsRaw & 0x8000,
    'Opcode': flagsRaw & 0x7800,    # 0111100000000000 dec = 7800 hex (4 bits)
    'AA': flagsRaw & 0x400,         # 0000010000000000 dec = 400 hex (1 bit)
}


print(length)

# refer to: https://docs.python.org/2.7/library/struct.html and https://docs.python.org/3/library/struct.html for info about python struct
# we need to use '!' for network (big endian)

# important observations from the RFC (https://tools.ietf.org/html/rfc1035):
# - UDP content (so w/o headers) <= 512 bytes. If more, TC bit is set(?) in the header
# - This is the header format: (each row consists of 16 bits = 2 bytes, so we can use struct(6H) (H is a short int, 2 bytes, 16 bits))
#   0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
# |                      ID                       |
# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
# |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
# |                    QDCOUNT                    |
# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
# |                    ANCOUNT                    |
# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
# |                    NSCOUNT                    |
# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
# |                    ARCOUNT                    |
# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
