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

# for now, we just use a hardcoded byte string (two different byte strings)
# UDPcontent = b"\x0e\xdb\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01"
UDPcontent = b"\x78\xca\x81\x80\x00\x01\x00\x01\x00\x00\x00\x01\x03\x77\x77\x77\x06\x67\x6f\x6f\x67\x6c\x65\x03\x63\x6f\x6d\x00\x00\x01\x00\x01\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x4d\x00\x04\xac\xd9\x11\x44\x00\x00\x29\x04\xd0\x00\x00\x00\x00\x00\x00"

# see explanation in the header section of RFC notes below
DNSheader = struct.Struct("!6H")

# get all header rows (6 H's of 2 bytes)
id, flagsRaw, qdcount, ancount, nscount, arcount = DNSheader.unpack_from(UDPcontent)

# we cannot access individual bits, so we use AND operations. (see also wireshark logs > Flags)
flags = {
    "QR": (flagsRaw & 0x8000) != 0,  # 1000000000000000 dec = 8000 hex (first bit) (boolean bit)
    "Opcode": (flagsRaw & 0x7800) >> 11,  # 0111100000000000 dec = 7800 hex (4 bits) (value bit on position 14-11 so we shift 11 bits to the right)
    "AA": (flagsRaw & 0x400) != 0,  # 0000010000000000 dec = 400 hex (1 bit) (boolean bit)
    "TC": (flagsRaw & 0x200) != 0,  # 0000001000000000 dec = 200 hex (1 bit) (boolean bit)
    "RD": (flagsRaw & 0x100) != 0,  # 0000000100000000 dec = 100 hex (1 bit) (boolean bit)
    "RA": (flagsRaw & 0x80) != 0,  # 00000000010000000 dec = 80 hex (1 bit) (boolean bit)
    "Z": (flagsRaw & 0x70) >> 4,  # 00000000001110000 dec = 70 hex (3 bits) (value bit on position 4-6 so we shift 4 bits to the right)
    "RCODE": (flagsRaw & 0xF) != 0,  # 0000000000001111 dec = F hex (4 bits) (boolean bit)
}

# offset that keeps track of the current byte that we access, DNSheader is 6 * H which is 6 * 16 bits which is 12 * 8 bits so DNSheader.size = 12 (bytes)
currentByte = DNSheader.size
# a list that is filled with the query objects that are decoded (if any)
requests = []
# a list that is filled in with the query answers that are decoded (if any)
answers = []

# for each request in the DNS query (qdcount in header)
for query in range(qdcount):
    # according to the RFC, to get qname, we get a length byte followed by the length amount of character bytes
    domainPartLength, = struct.unpack_from("!B", UDPcontent, currentByte)
    currentByte += 1
    # the URL list we will fill with the requested domain parts (TLD is always last item)
    URL = []

    #0x00 is the delimiter byte, we check for that
    while domainPartLength != 0:
        domainPartString = ''
        for count in range(domainPartLength):
            # the bytes are characters so we can use 'c' from struct
            char, = struct.unpack_from("!c", UDPcontent, currentByte)
            currentByte += 1
            # append the character to the string
            domainPartString += char.decode("utf-8")
        
        # append the string to the list
        URL.append(domainPartString)

        domainPartLength, = struct.unpack_from("!B", UDPcontent, currentByte)
        currentByte += 1

    # to get the qtype and qclass
    DNSrequest = struct.Struct("!2H")
    qtype, qclass = DNSrequest.unpack_from(UDPcontent, currentByte)
    # again, 2H is 4 bytes so DNSrequest.size = 4
    currentByte += DNSrequest.size

    # we build the request object for later access
    requestObject = {
        'URL': URL,
        'qtype': qtype,
        'qclass': qclass
    }

    # we add the request object to the list of request objects
    requests.append(requestObject)

print(f'ancount = {ancount}')

# for each answer in the DNS query (ancount in header)
for answer in range(ancount):
    # NAME is a pointer as described by the RFC
    domainPointer, = struct.unpack_from("!H", UDPcontent, currentByte)
    currentByte += 2
    # according to the RFC, pointer bytes start with 2 1-bits (to distinguish them from labels, see RFC) so we need to remove those
    domainPointer = domainPointer & 0x3f # 00111111 dec = 3f hex 

    # we will access the pointer from now on so we need to store the currentByte position to continue the program later
    originalCurrentByte = currentByte
    # subtract the byte offset from the current byte (subtraction is possible since pointers are only used for earlier occurrences, see RFC)
    currentByte = domainPointer

    # repetition of code, oops
    # according to the RFC, to get qname, we get a length byte followed by the length amount of character bytes
    domainPartLength, = struct.unpack_from("!B", UDPcontent, currentByte)
    currentByte += 1
    # the URL list we will fill with the requested domain parts (TLD is always last item)
    URL = []

    #0x00 is the delimiter byte, we check for that
    while domainPartLength != 0:
        domainPartString = ''
        for count in range(domainPartLength):
            # the bytes are characters so we can use 'c' from struct
            char, = struct.unpack_from("!c", UDPcontent, currentByte)
            currentByte += 1
            # append the character to the string
            domainPartString += char.decode("utf-8")
        
        # append the string to the list
        URL.append(domainPartString)

        domainPartLength, = struct.unpack_from("!B", UDPcontent, currentByte)
        currentByte += 1

    # we are done with the pointed address, restore the original byte position
    currentByte = originalCurrentByte

    # to get the qtype and qclass
    atype, = struct.unpack_from("!H", UDPcontent, currentByte)
    currentByte += 2
    aclass, = struct.unpack_from("!H", UDPcontent, currentByte)
    currentByte += 2
    # TTL is an unsigned 32 bit (4 byte) integer so we can use struct(I)
    attl, = struct.unpack_from("!I", UDPcontent, currentByte)
    currentByte += 4
    ardlength, = struct.unpack_from("!H", UDPcontent, currentByte)
    currentByte += 2


    # this list will be filled with data from the RDATA content (= usually the IP)
    ardata = []

    for count in range(ardlength):
        # each byte is an unsigned integer as specified in the RFC. We can use 'B' from struct
        rdataPiece, = struct.unpack_from("!B", UDPcontent, currentByte)
        currentByte += 1

        # we add the data piece to rdata
        ardata.append(rdataPiece)


    # we build the answer object for later access
    answerObject = {
        'URL': URL,
        'type': atype,
        'class': aclass,
        'ttl': attl,
        'rdlength': ardlength,
        'rdata': ardata
    }

    # we add the answer object to the list of answer objects
    answers.append(answerObject)

print(requests)
print(answers)

# for count in range(length):
#     character, = struct.unpack_from("!c", UDPcontent, 1 + count)
#     print(character)

# see explanation in the query section of RFC notes below
DNSrequest = struct.Struct("!4b")

# bs, bs2, char1, char2 = DNSrequest.unpack_from(UDPcontent, DNSheader.size)

# print(bs, bs2)
# print(char1, char2)

print(flags["TC"])
print(qdcount)

# refer to: https://www.cs.swarthmore.edu/~chaganti/cs43/f19/labs/lab3.html for a general workflow that is needed to implement the DNS server
# refer to: https://www2.cs.duke.edu/courses/fall16/compsci356/DNS/DNS-primer.pdf for explained example queries

# refer to: https://docs.python.org/2.7/library/struct.html and https://docs.python.org/3/library/struct.html for info about python struct
# - We need to use '!' for network (big endian)

# important observations from the RFC (https://tools.ietf.org/html/rfc1035):
# - UDP content (so w/o headers) <= 512 bytes. If more, TC bit is set in the header

# - This is the message format: (for both sender and receiver, some sections may be empty (for example because a query does not contain answers))
# +---------------------+
# |        Header       |
# +---------------------+
# |       Question      | the question for the name server
# +---------------------+
# |        Answer       | RRs answering the question
# +---------------------+
# |      Authority      | RRs pointing toward an authority (those are left out)
# +---------------------+
# |      Additional     | RRs holding additional information (those are left out)
# +---------------------+

# - This is the header format: (each row consists of 16 bits = 2 bytes, so we can use struct(6H) (H is a unsigned short int, 2 bytes, 16 bits))
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

# - This is the question format: (the header QDCOUNT tells how much of these are included, usually 1) (qtype and qclass consist of 16 bits so we can use struct(2H), qname has a dynamic length depending on the domain name string size (but a multiple of 8 bits))
#  0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
# |                                               |
# /                     QNAME                     /
# /                                               /
# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
# |                     QTYPE                     |
# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
# |                     QCLASS                    |
# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

# - This is the answer format:  (the header ANCOUNT tells how much of these are included, usually included if received from another DNS) (NAME is a pointer of 16 bits, other rows are 16 bits so we can use struct(H). RDATA is dynamically sized with RDLENGTH and TTL is 32 bits, 4 bytes)
#   0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
# |                                               |
# /                                               /
# /                      NAME                     /
# |                                               |
# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
# |                      TYPE                     |
# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
# |                     CLASS                     |
# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
# |                      TTL                      |
# |                                               |
# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
# |                   RDLENGTH                    |
# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--|
# /                     RDATA                     /
# /                                               /
# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

# - an octet = 8 bits (a byte)
