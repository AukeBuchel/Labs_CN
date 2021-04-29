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

class terminalColors:
    blue = '\033[94m'
    green = '\033[92m'
    yellow = '\033[93m'
    red = '\033[91m'
    end = '\033[0m'
    bold = '\033[1m'

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

    # reserve the variable for our scope (MX only)
    preference = 0

    # type A
    if atype == 1:
        for count in range(ardlength):
            # each byte is an unsigned integer as specified in the RFC. We can use 'B' from struct
            rdataPiece, = struct.unpack_from("!B", UDPcontent, offsetByte)
            offsetByte += 1

            # we add the data piece to rdata
            ardata.append(rdataPiece)
    # type NS or type CNAME
    elif atype == 2 or atype == 5:
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
                # todo: same fix as with NAME above
                labels, pointerOffsetByte = decodeLabels(UDPcontent, pointerOffsetByte)
                ardata += labels
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
    # type MX
    elif atype == 15 or atype == 5:
        # preference is MX-only
        preference, = struct.unpack_from("!H", UDPcontent, offsetByte)
        offsetByte += 2
        ardata, offsetByte = decodeLabels(UDPcontent, offsetByte)


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

    if atype == 15:
        resourceRecordObject['preference'] = preference

    return resourceRecordObject, offsetByte


def decodeRequest(UDPcontent, decodeAllSections = True):
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

    if decodeAllSections:
        # for each authority in the DNS query (nscount in header)
        for authority in range(nscount):
            authorityObject, currentByte = decodeResourceRecord(UDPcontent, currentByte)
            # we add the authority object to the list of answer objects
            authorities.append(authorityObject)

    # a list of additional records
    additional = []

    if decodeAllSections:
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
        print(f" encoding answer {answer}")
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

        # we append the MX preference if needed
        if answer['type'] == 15:
            preference = 0
            if 'preference' not in answer:
                print("MX records should have a preference, setting 0 now")
            else:
                preference = answer['preference']
            exportBytes += struct.pack("!H", preference)
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

host = ("192.168.1.202", 53)
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(host)

# map domains to IP addresses
simpleCache = {}

rootDNSip = '198.41.0.4'

rootServers = ['198.41.0.4', '199.9.14.201', '192.33.4.12', '199.7.91.13', '192.203.230.10', '192.5.5.241', '192.112.36.4', '198.97.190.53', '192.36.148.17', '192.58.128.30', '193.0.14.129', '199.7.83.42', '202.12.27.33' ]

# note that domainName is a list of URL parts
def resolveRequest(domainRequestObject, DNSip, indent = ''):
    if '' in domainRequestObject['URL']:
        domainRequestObject['URL'].remove('')
    if DNSip in rootServers:
        print(indent, terminalColors.green, 'Resolve call', terminalColors.end, 'to resolve', getDomainString(domainRequestObject['URL']), 'sent to', DNSip, '(root server)')
    else:
        print(indent, terminalColors.green, 'Resolve call', terminalColors.end, 'to resolve', getDomainString(domainRequestObject['URL']), 'sent to', DNSip)
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
    sock.settimeout(5)
    try:
        DNSresponse = decodeRequest(sock.recv(512))
        while DNSresponse['id'] != requestPacket['id']:
            print("we did not order this")
            DNSresponse = decodeRequest(sock.recv(512))
    except socket.timeout:
        # it is for the calling function to fix this
        print(indent, 'Call', terminalColors.yellow, 'timed out', terminalColors.end)
        return -1

    if DNSresponse['ancount'] > 0:
        print(indent, terminalColors.green, 'Answer(s) found', terminalColors.end, DNSresponse['answers'])
        for answer in DNSresponse['answers']:
            if answer['type'] == 5:
                requestObject = {
                    'URL': answer['rdata'], 
                    'qtype': 1, 
                    'qclass': 1
                }
                return resolveRequest(requestObject, rootServers[0], indent + '  ')
        return DNSresponse['answers']
    else:
        # create a mapping of nameservers (domains) and their IPs
        nameservers = {}
        for authority in DNSresponse['authorities']:
            if authority['type'] == 2:
                if '' in authority['rdata']:
                    authority['rdata'].remove('')
                nameservers[getDomainString(authority['rdata'])] = 'UNSET'
        for addition in DNSresponse['additional']:
            if addition['type'] == 1 and getDomainString(addition['URL']) in nameservers:
                nameservers[getDomainString(addition['URL'])] = getDomainString(addition['rdata'])

        # domain, ip = next(iter(nameservers.items()))
        # we loop, since timeouts can occur so we might need to contact another nameserver
        for domain, ip in nameservers.items():
            # we know the nameserver IP already
            if ip != 'UNSET':
                foundIP = resolveRequest(domainRequestObject, ip, indent + '  ')
                if foundIP == -1 or foundIP == None:
                    # try another IP in the for-loop
                    continue
                else:
                    return foundIP
            # we need to find the nameserver IP still
            else:
                # same TLD, we can traverse the tree
                if getDomainList(domain)[-1] == domainRequestObject['URL'][-1]:
                    requestObject = {
                        'URL': getDomainList(domain), 
                        'qtype': 1, 
                        'qclass': 1
                    }
                    onTreeIP = resolveRequest(requestObject, DNSip, indent + '  ')
                    if onTreeIP == -1 or onTreeIP == None:
                        return -1
                    for IPresponse in onTreeIP:
                        responseObject = resolveRequest(domainRequestObject, getDomainString(IPresponse['rdata']), indent + '  ')
                        if responseObject != -1 and responseObject != None:
                            return  responseObject
                # different TLD, start from root again
                else:
                    requestObject = {
                        'URL': getDomainList(domain), 
                        'qtype': 1, 
                        'qclass': 1
                    }
                    rootSelector = 0
                    offTreeIP = resolveRequest(requestObject, rootServers[rootSelector], indent)
                    while offTreeIP == -1 or offTreeIP == None:
                        # there are 13 root servers to select from
                        rootSelector = rootSelector % 12
                        # we should try another root
                        offTreeIP = resolveRequest(requestObject, rootServers[rootSelector], indent)
                        # increase the root selector
                        rootSelector += 1
                    for IPresponse in offTreeIP:
                        responseObject = resolveRequest(domainRequestObject, getDomainString(IPresponse['rdata']), indent + '  ')
                        if responseObject != -1 and responseObject != None:
                            return responseObject

x = 0
while x < 10:
    # always 512 bytes
    userRequest, userAddress = sock.recvfrom(512)
    userRequest = decodeRequest(userRequest)

    print(terminalColors.blue, "[NEW REQUEST] (->)", terminalColors.end, userRequest['requests'])

    # we do not want responses so we let this slide
    if (userRequest['flags']['QR']):
        print('This request was a', terminalColors.yellow, 'response', terminalColors.end, ', it is dropped.')
        continue

    for request in userRequest['requests']:
        print(terminalColors.blue, 'Resolving', terminalColors.end, getDomainString(request['URL']))
        # we can only resolve type 1 (A) and type 15 (MX) records
        if request['qtype'] == 1 or request['qtype'] == 15:
            supportedType = request['qtype']
            print(terminalColors.green, f'Type {supportedType} is supported', terminalColors.end)
            print(request)
            # try:
            rootSelector = 0
            solvedRequest = resolveRequest(request, rootServers[rootSelector])
            while solvedRequest == -1 or solvedRequest == None:
                print(f"{terminalColors.yellow}Timeout{terminalColors.end} of root server")
                # there are 13 root servers to select from
                rootSelector = rootSelector % 12
                # we should try another root
                solvedRequest = resolveRequest(request, rootServers[rootSelector])
                # increase the root selector
                rootSelector += 1
            print(terminalColors.green, 'Resolved', terminalColors.end, getDomainString(request['URL']), 'to', getDomainString(solvedRequest[0]['rdata']))
            for answer in solvedRequest:
                userRequest['answers'].append(answer)
            # except Exception as e:
            #     print(terminalColors.red, 'Could not resolve', terminalColors.end, getDomainString(request['URL']), 'error:', e)
        else:
            unsupportedType = request['qtype']
            print(terminalColors.yellow, f'Type {unsupportedType} not supported', terminalColors.end)
    
    userRequest['flags']['QR'] = True
    userRequest['ancount'] = len(userRequest['answers'])

    print(terminalColors.blue, "[RETURN RESPONSE] (<-)", terminalColors.end, userRequest)
    serverResponse = encodeRequest(userRequest)

    sock.sendto(serverResponse, userAddress) 

    x += 1


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
# |      Authority      | RRs pointing toward an authority
# +---------------------+
# |      Additional     | RRs holding additional information
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
