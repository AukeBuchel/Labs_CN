import socket
import struct  # byte ordering
import random

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

# use this function ONLY if certain that this is a label, it does NOT detect pointers
def decodeLabel(UDPcontent, offsetByte):
    labelPartLength, = struct.unpack_from("!B", UDPcontent, offsetByte)
    offsetByte += 1

    label = ''
    for count in range(labelPartLength):
        # the bytes are characters so we can use 'c' from struct
        char, = struct.unpack_from("!c", UDPcontent, offsetByte)
        offsetByte += 1
        # append the character to the string
        label += char.decode("utf-8")
    return label, offsetByte

def decodeLabels(UDPcontent, offsetByte):
    # note that we explicitly do not increase the offsetByte, the byte will be read again
    labelPartLength, = struct.unpack_from("!B", UDPcontent, offsetByte)

    labels = []
    # 0x00 is the delimiter byte (but also pointer may occur)
    while labelPartLength != 0 and not pointerFound(labelPartLength, 1):
        label, offsetByte = decodeLabel(UDPcontent, offsetByte)
        labels.append(label)
        # note that we explicitly do not increase the offsetByte, the byte may be be read again
        labelPartLength, = struct.unpack_from("!B", UDPcontent, offsetByte)
    # if the while loop has stopped, the delimiter byte will not be read again so we can increase offsetByte
    offsetByte += 1 

    return labels, offsetByte

# pointers always span two octets, as described in the RFC but we can also detect them with only one byte (python wont let us use isPointer)
def pointerFound(byteContent, byteSize = 2):
    # check if it is really a pointer (starts with two 1-bits) or just a regular domain label
    if byteSize == 2:
        return (byteContent & 0xc000) != 0 # 1100000000000000 bin = c000 hex 
    elif byteSize == 1:
        return (byteContent & 0xc0) != 0 # 11000000 bin = c0 hex 
    else:
        raise("This byte size is not supported.")

# again, pointers are two octets
def decodePointer(byteContent):
    return (byteContent & 0x3ff) # 0011111111111111 bin = 3ff hex 

def getDomainString(domainList):
    domainString = ''
    for domainPart in domainList:
        # we use str() in case we deal with ints (as is the case when we get an IP address)
        domainString += '.' + str(domainPart)
    # we do not need the first period, period.
    return domainString[1:]

def getDomainList(domainString):
    returnList = domainString.split('.')
    if '' in returnList:
        returnList.pop('')
    return returnList

def decodeResourceRecord(UDPcontent, offsetByte):
    # the domain name is stored as a list of subdomains (so separated by a period (.))
    domainName = []

    if pointerFound(struct.unpack_from("!H", UDPcontent, offsetByte)[0]):
        namePointer = decodePointer(struct.unpack_from("!H", UDPcontent, offsetByte)[0])
        offsetByte += 2
        domainNamePart, pointerOffsetByte = decodeLabel(UDPcontent, namePointer)
        domainName.append(domainNamePart)
        # NAME can be a a combination of pointers or labels which is complicated. Note that we use pointerOffsetByte here which is DIFFERENT from offsetByte
        # pointerOffsetByte is used to iterate over the bytes pointed to by the pointer we are working on
        # we stop if a delimiter byte is found (in the pointed-to domain, NAME is not delimited) or if no new pointer is found
        while struct.unpack_from("!B", UDPcontent, pointerOffsetByte)[0] != 0 or pointerFound(struct.unpack_from("!B", UDPcontent, pointerOffsetByte)[0], 1):
            # the domain pointed to, can itself also contain pointers, 
            # this is not included in the rdlength so we do not change bytesInspected (see RFC 4.1.4)
            while pointerFound(struct.unpack_from("!H", UDPcontent, pointerOffsetByte)[0]):
                namePointer = decodePointer(struct.unpack_from("!H", UDPcontent, pointerOffsetByte)[0])
                domainNamePart, pointerOffsetByte = decodeLabel(UDPcontent, namePointer)
                domainName.append(domainNamePart)
            labels, pointerOffsetByte = decodeLabels(UDPcontent, pointerOffsetByte)
            domainName += labels
            pointerOffsetByte -= 1
    else:
        raise TypeError("RR \'Name\' should be a pointer")

    # to get the qtype and qclass (TTL is 32-bit, 4 bytes, which is different)
    atype, aclass, attl, ardlength = struct.unpack_from("!2HIH", UDPcontent, offsetByte)
    offsetByte += 10

    # this list will be filled with data from the RDATA content (= usually the IP)
    ardata = []

    # type A
    if atype == 1:
        for count in range(ardlength):
            # each byte is an unsigned integer as specified in the RFC. We can use 'B' from struct
            rdataPiece, = struct.unpack_from("!B", UDPcontent, offsetByte)
            offsetByte += 1

            # we add the data piece to rdata
            ardata.append(rdataPiece)
    # type NS
    elif atype == 2:
        domainNamePart = ''
        bytesInspected = 0
        while bytesInspected < ardlength:
            if pointerFound(struct.unpack_from("!B", UDPcontent, offsetByte)[0], 1):
                namePointer = decodePointer(struct.unpack_from("!H", UDPcontent, offsetByte)[0])
                offsetByte += 2
                bytesInspected += 2
                domainNamePart, pointerOffsetByte = decodeLabel(UDPcontent, namePointer)
                ardata.append(domainNamePart)
                # the domain pointed to, can itself also contain pointers, 
                # this is not included in the rdlength so we do not change bytesInspected (see RFC 4.1.4)
                while pointerFound(struct.unpack_from("!H", UDPcontent, pointerOffsetByte)[0]):
                    namePointer = decodePointer(struct.unpack_from("!H", UDPcontent, pointerOffsetByte)[0])
                    domainNamePart, pointerOffsetByte = decodeLabel(UDPcontent, namePointer)
                    ardata.append(domainNamePart)
            else:
                oldOffsetByte = offsetByte
                domainNamePart, offsetByte = decodeLabel(UDPcontent, offsetByte)
                bytesInspected += (offsetByte - oldOffsetByte)
                ardata.append(domainNamePart)
    # type AAA:
    elif atype == 28:
        for count in range(ardlength//2):
            # each two bytes is an unsigned integer, IPv6 consists of 8 of these domain parts
            rdataPiece, = struct.unpack_from("!H", UDPcontent, offsetByte)
            offsetByte += 2

            # we add the data piece to rdata
            # hex is used since IPv6 addresses are hexadecimal
            ardata.append(hex(rdataPiece))


    # we build the final resource record object for later access
    resourceRecordObject = {
        'URL': domainName,
        'URLraw': getDomainString(domainName),
        'type': atype,
        'class': aclass,
        'ttl': attl,
        'rdlength': ardlength,
        'rdata': ardata
    }

    return resourceRecordObject, offsetByte


def decodeRequest(UDPcontent):
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

    # for each request in the DNS query (qdcount in header)
    for query in range(qdcount):
        URL, currentByte = decodeLabels(UDPcontent, currentByte)

        # to get the qtype and qclass
        DNSrequest = struct.Struct("!2H")
        qtype, qclass = DNSrequest.unpack_from(UDPcontent, currentByte)
        # again, 2H is 4 bytes so DNSrequest.size = 4
        currentByte += DNSrequest.size

        # we build the request object for later access
        requestObject = {
            'URL': URL,
            'URLraw': getDomainString(URL),
            'qtype': qtype,
            'qclass': qclass
        }

        # we add the request object to the list of request objects
        requests.append(requestObject)

    # a list that is filled in with the query answers that are decoded (if any)
    answers = []

    # for each answer in the DNS query (ancount in header)
    for answer in range(ancount):
        answerObject, currentByte = decodeResourceRecord(UDPcontent, currentByte)
        # we add the answer object to the list of answer objects
        answers.append(answerObject)

    # a list of authorities
    authorities = []

    # for each authority in the DNS query (nscount in header)
    for authority in range(nscount):
        authorityObject, currentByte = decodeResourceRecord(UDPcontent, currentByte)
        # we add the authority object to the list of answer objects
        authorities.append(authorityObject)

    # a list of additional records
    additional = []

    # for each authority in the DNS query (nscount in header)
    for addition in range(arcount):
        additionObject, currentByte = decodeResourceRecord(UDPcontent, currentByte)
        # we add the authority object to the list of answer objects
        additional.append(additionObject)

    return {
        "id": id,
        "flags": flags,
        "qdcount": qdcount,
        "ancount": ancount,
        "nscount": nscount,
        "arcount": arcount,
        "requests": requests,
        "answers": answers,
        "authorities": authorities,
        "additional": additional
    }

def encodeRequest(requestObject):
    # we keep track of the currentByte, again
    currentByte = 0

    # we have no time for this
    requestObject['nscount'] = 0
    requestObject['arcount'] = 0

    # pointers we can reference later
    pointers = {}

    # the byte string we will send one day, we start with the header content
    exportBytes = struct.pack("!H", requestObject['id'])
    currentByte += 2

    # we have to populate the bits, this is the exact opposite of the decoding process so explanation for hex values is left out here
    flagsRaw = 0
    if requestObject['flags']['QR']:
        flagsRaw = (flagsRaw | 0x8000)
    if requestObject['flags']['Opcode']:
        shiftedOpcode = (requestObject['flags']['Opcode'] << 11)
        flagsRaw = (flagsRaw | shiftedOpcode)
    if requestObject['flags']['AA']:
        flagsRaw = (flagsRaw | 0x400)
    if requestObject['flags']['TC']:
        flagsRaw = (flagsRaw | 0x200) 
    if requestObject['flags']['RD']:
        flagsRaw = (flagsRaw | 0x100)  
    if requestObject['flags']['RA']:
        flagsRaw = (flagsRaw | 0x80)  
    if requestObject['flags']['Z']:
        shiftedZ = (requestObject['flags']['Z'] << 4)
        flagsRaw = (flagsRaw | shiftedZ)  
    if requestObject['flags']['RCODE']:
        flagsRaw = (flagsRaw | 0xF) 
    # append the bits converted to a hex byte string to the bytes we want to export
    exportBytes += struct.pack("!H", flagsRaw)
    currentByte += 2

    # append all other header infromation to the hex byte string
    exportBytes += struct.pack("!4H", requestObject['qdcount'], requestObject['ancount'], requestObject['nscount'], requestObject['arcount'])
    currentByte += 8

    # we populate the bytes to export with the requests
    for request in requestObject['requests']:
        # access the pointers by the rawURL as key
        rawURL = ''
        urlPointer = currentByte

        for domainPart in request['URL']:
            # we append to the rawURL
            rawURL += domainPart
            # domainPart is a string, like 'google' in google.com
            exportBytes += struct.pack("!B", len(domainPart))
            currentByte += 1
            for domainPartCharacter in domainPart:
                # domainPartCharacter is a char, like 'g' in google
                exportBytes += struct.pack("!c", domainPartCharacter.encode("utf-8"))
                currentByte += 1
                
        # according to the RFC, we terminate the name with a 0-byte
        exportBytes += struct.pack("!B", 0)
        currentByte += 1

        pointers[rawURL] = urlPointer
        
        # append the other request information to the hex byte string
        exportBytes += struct.pack("!2H", request['qtype'], request['qclass'])
        currentByte += 4

    # we populate the bytes to export with the answers
    for answer in requestObject['answers']:
        rawURL = ''
        for domainPart in answer['URL']:
            rawURL += domainPart

        if rawURL in pointers:
            URLpointer = pointers[rawURL]
            # per RFC defintion, pointers start with two 1-bits at the MSB position (just like in decoding)
            exportBytes += struct.pack("!H", URLpointer | 0xc000)
            currentByte += 2
        else:
            for domainPart in answer['URL']:
                pointers[rawURL] = currentByte
                # domainPart is a string, like 'google' in google.com
                exportBytes += struct.pack("!B", len(domainPart))
                currentByte += 1
                for domainPartCharacter in domainPart:
                    # domainPartCharacter is a char, like 'g' in google
                    exportBytes += struct.pack("!c", domainPartCharacter.encode("utf-8"))
                    currentByte += 1

            # according to the RFC, we terminate the name (not the pointer!) with a 0-byte
            exportBytes += struct.pack("!B", 0)
            currentByte += 1
        
        # append the other request information to the hex byte string
        exportBytes += struct.pack("!2H", answer['type'], answer['class'])
        currentByte += 4
        exportBytes += struct.pack("!I", answer['ttl'])
        currentByte += 4
        exportBytes += struct.pack("!H", answer['rdlength'])
        currentByte += 2

        # append the rdata
        for dataItem in answer['rdata']:
            exportBytes += struct.pack("!B", dataItem)
            currentByte += 1

    return exportBytes

# dummy object to test the request decoding
responseDummy = b"\x78\xca\x81\x80\x00\x01\x00\x01\x00\x00\x00\x01\x03\x77\x77\x77\x06\x67\x6f\x6f\x67\x6c\x65\x03\x63\x6f\x6d\x00\x00\x01\x00\x01\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x4d\x00\x04\xac\xd9\x11\x44\x00\x00\x29\x04\xd0\x00\x00\x00\x00\x00\x00"

# dummy object to test the request encoding
requestDummy = {
    "id": 2,
    "flags": {
        "QR": False,
        "Opcode": 0,
        "AA": False,
        "TC": False,
        "RD": True,
        "RA": False,
        "Z": 0,
        "RCODE": False
    },
    'qdcount': 1, 
    'ancount': 0, 
    'nscount': 0, 
    'arcount': 0, 
    'requests': [
        {
            'URL': ['www', 'storm', 'vu'], 
            'qtype': 1, 
            'qclass': 1
        }
    ],
    'answers': [
        # {
        #     'URL': ['www', 'google', 'com'], 
        #     'type': 1, 
        #     'class': 1, 
        #     'ttl': 77, 
        #     'rdlength': 4, 
        #     'rdata': [172, 217, 17, 68]
        # }
    ]
}

requestDummy2 = {
    "id": 2,
    "flags": {
        "QR": False,
        "Opcode": 0,
        "AA": False,
        "TC": False,
        "RD": True,
        "RA": False,
        "Z": 0,
        "RCODE": False
    },
    'qdcount': 1, 
    'ancount': 0, 
    'nscount': 0, 
    'arcount': 0, 
    'requests': [
        {
            'URL': ['nameserver', 'ml'], 
            'qtype': 1, 
            'qclass': 1
        }
    ],
    'answers': [
        # {
        #     'URL': ['www', 'google', 'com'], 
        #     'type': 1, 
        #     'class': 1, 
        #     'ttl': 77, 
        #     'rdlength': 4, 
        #     'rdata': [172, 217, 17, 68]
        # }
    ]
}

#print(decodeRequest(encodeRequest(requestDummy)))



# program flow:
# 1. request a domain to a root DNS server (from txt file, todo)
#   - if no response (timeout) -> try another root DNS
# 2. decode the answer, it contains the TLD nameservers in additional sec
# 3. request the domain to the TLD DNS server (from step 2)
#   - if no response (timeout) -> try another TLD nameserver
# *. decode the answer, if no answers yet keep repeating this: traverse the tree

# sock.sendto(x, ("198.41.0.4", 53))
# answer = sock.recv(512)
# rootResponse = decodeRequest(answer)
# print("ROOT RESPONSE")
# print(rootResponse)

host = ("192.168.1.202", 53)
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(host)

# map domains to IP addresses
simpleCache = {}

rootDNSip = '198.41.0.4'

# # note that domainName is a list of URL parts
def resolveDomain(domainRequestObject, DNSip):
    print("RESOLVE DOMAIN CALL")
    print(f'Requesting {domainRequestObject} to {DNSip}')
    requestPacket = {
        "id": random.randint(0, 3000),
        "flags": {
            "QR": False,
            "Opcode": 0,
            "AA": False,
            "TC": False,
            "RD": True,
            "RA": False,
            "Z": 0,
            "RCODE": False
        },
        'qdcount': 1, 
        'ancount': 0, 
        'nscount': 0, 
        'arcount': 0, 
        'requests': [
            domainRequestObject
        ],
        'answers': []
    }

    sock.sendto(encodeRequest(requestPacket), (DNSip, 53))
    DNSresponse = decodeRequest(sock.recv(512))

    if DNSresponse['ancount'] > 0:
        print("WE FOUND THE IP!!")
        print(DNSresponse)
        print("ANSWERS:")
        print(DNSresponse['answers'])
        return DNSresponse['answers'][0]['rdata']
    else:
        # this is a list of nameservers, we want the IPs
        possibleAuthorities = []
        for possibleAuthority in DNSresponse['authorities']:
            if '' in possibleAuthority['rdata']:
                possibleAuthority['rdata'].remove('')
            # we check if the TLDs match, so that we can continue in the tree
            if possibleAuthority['type'] == 2 and possibleAuthority['rdata'][-1] == domainRequestObject['URL'][-1]:
                possibleAuthorities.append(possibleAuthority['rdata'])
        # this is a list of IPs
        actualAuthorities = []
        for actualAuthority in DNSresponse['additional']:
            if actualAuthority['type'] == 1 and actualAuthority['URL'] in possibleAuthorities:
                actualAuthorities.append(actualAuthority['rdata'])
        
        if len(actualAuthorities) > 0:
            # for now we only try once
            # todo: try more!
            resolveDomain(domainRequestObject, getDomainString(actualAuthorities[0]))
        elif len(possibleAuthorities) > 0:
            # we do not know which server to go to, so we first ask the IP of the nameserver
            nameserverIP = resolveDomain(possibleAuthorities[0], DNSip)
            resolveDomain(domainRequestObject, getDomainString(nameserverIP))
        else:
            print("I do not know what to do...")
        
requestObject = {
    'URL': ['storm', 'nl'], 
    'qtype': 1, 
    'qclass': 1
}

resolveDomain(requestObject, '198.41.0.4')



# rootRequest = {
#     "id": random.randint(0, 3000),
#     "flags": {
#         "QR": False,
#         "Opcode": 0,
#         "AA": False,
#         "TC": False,
#         "RD": True,
#         "RA": False,
#         "Z": 0,
#         "RCODE": False
#     },
#     'qdcount': 1, 
#     'ancount': 0, 
#     'nscount': 0, 
#     'arcount': 0, 
#     'requests': [
#         {
#             'URL': ['NL'], 
#             'qtype': 1, 
#             'qclass': 1
#         }
#     ],
#     'answers': []
# }

# sock.sendto(encodeRequest(rootRequest), (rootDNSip, 53))
# rootResponse = decodeRequest(sock.recv(512))

# # this is a list of nameservers, we want the IPs
# possibleAuthorities = []
# for possibleAuthority in rootResponse['authorities']:
#     if possibleAuthority['type'] == 2:
#         possibleAuthorities.append(possibleAuthority['rdata'])
# # this is a list of IPs
# actualAuthorities = []
# for actualAuthority in rootResponse['additional']:
#     if actualAuthority['type'] == 1 and actualAuthority['URL'] in possibleAuthorities:
#         actualAuthorities.append(actualAuthority['rdata'])
# print(possibleAuthorities)


# step1DNSip = getDomainString(actualAuthorities[0])

# step1request = {
#     "id": random.randint(0, 3000),
#     "flags": {
#         "QR": False,
#         "Opcode": 0,
#         "AA": False,
#         "TC": False,
#         "RD": True,
#         "RA": False,
#         "Z": 0,
#         "RCODE": False
#     },
#     'qdcount': 1, 
#     'ancount': 0, 
#     'nscount': 0, 
#     'arcount': 0, 
#     'requests': [
#         {
#             'URL': ['storm', 'nl'], 
#             'qtype': 1, 
#             'qclass': 1
#         }
#     ],
#     'answers': []
# }

# sock.sendto(encodeRequest(step1request), (step1DNSip, 53))
# step1response = decodeRequest(sock.recv(512))

# # this is a list of nameservers, we want the IPs
# possibleAuthorities = []
# for possibleAuthority in step1response['authorities']:
#     if '' in possibleAuthority['rdata']:
#         possibleAuthority['rdata'].remove('')
#     if possibleAuthority['type'] == 2 and possibleAuthority['rdata'][-1] == 'nl':
#         possibleAuthorities.append(possibleAuthority['rdata'])
# # this is a list of IPs
# actualAuthorities = []
# for actualAuthority in step1response['additional']:
#     if actualAuthority['type'] == 1 and actualAuthority['URL'] in possibleAuthorities:
#         actualAuthorities.append(actualAuthority['rdata'])
# print(actualAuthorities)


# step2DNSip = getDomainString(actualAuthorities[0])

# step2request = {
#     "id": random.randint(0, 3000),
#     "flags": {
#         "QR": False,
#         "Opcode": 0,
#         "AA": False,
#         "TC": False,
#         "RD": True,
#         "RA": False,
#         "Z": 0,
#         "RCODE": False
#     },
#     'qdcount': 1, 
#     'ancount': 0, 
#     'nscount': 0, 
#     'arcount': 0, 
#     'requests': [
#         {
#             'URL': ['storm', 'nl'], 
#             'qtype': 1, 
#             'qclass': 1
#         }
#     ],
#     'answers': []
# }

# sock.sendto(encodeRequest(step2request), (step2DNSip, 53))
# step2response = decodeRequest(sock.recv(512))

# print(step2response)


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

# - if the AA flag is set, (True) the DNS response does not contain the IP of the requested domain but rather the domain of the nameserver that we must query
