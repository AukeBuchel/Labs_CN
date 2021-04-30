import socket
import struct  # byte ordering
import random # packet IDs
import threading # cache maintenance
import time # also for the cache

class terminalColors:
    blue = '\033[94m'
    green = '\033[92m'
    yellow = '\033[93m'
    red = '\033[91m'
    end = '\033[0m'
    bold = '\033[1m'

class debug:
    def info(title, content, indent = '', encaps = True):
        if encaps:
            print(f"{indent}[{terminalColors.blue}{terminalColors.bold}{title}{terminalColors.end}] {content}")
        else:
            print(f"{indent}{terminalColors.blue}{terminalColors.bold}{title}{terminalColors.end} {content}")

    def warning(title, content, indent = '', encaps = True):
        if encaps:
            print(f"{indent}[{terminalColors.yellow}{terminalColors.bold}{title}{terminalColors.end}] {content}")
        else:
            print(f"{indent}{terminalColors.yellow}{terminalColors.bold}{title}{terminalColors.end} {content}")

    def success(title, content, indent = '', encaps = True):
        if encaps:
            print(f"{indent}[{terminalColors.green}{terminalColors.bold}{title}{terminalColors.end}] {content}")
        else:
            print(f"{indent}{terminalColors.green}{terminalColors.bold}{title}{terminalColors.end} {content}")
    
    def error(title, content, indent = '', encaps = True):
        if encaps:
            print(f"{indent}[{terminalColors.red}{terminalColors.bold}{title}{terminalColors.end}] {content}")
        else:
            print(f"{indent}{terminalColors.red}{terminalColors.bold}{title}{terminalColors.end} {content}")

    def neutral(title, content, indent = '', encaps = True):
        if encaps:
            print(f"{indent}[{terminalColors.bold}{title}{terminalColors.end}] {content}")
        else:
            print(f"{indent}{terminalColors.bold}{title}{terminalColors.end} {content}")

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
        domainName, offsetByte = decodeLabels(UDPcontent, offsetByte)

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
    elif atype == 15:
        # preference is MX-only
        preference, = struct.unpack_from("!H", UDPcontent, offsetByte)
        offsetByte += 2
        bytesInspected = 2

        if ardlength - bytesInspected == 1 and struct.unpack_from("!B", UDPcontent, offsetByte)[0] == 0:
            ardata = ['<root>']
        else:
            oldOffsetByte = offsetByte
            ardata, offsetByte = decodeLabels(UDPcontent, offsetByte)
            bytesInspected += (offsetByte - oldOffsetByte)
            offsetByte -= 1

            if bytesInspected < ardlength and pointerFound(struct.unpack_from("!B", UDPcontent, offsetByte)[0], 1):
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
                labels, pointerOffsetByte = decodeLabels(UDPcontent, pointerOffsetByte)
                ardata += labels

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
        "RCODE": (flagsRaw & 0xF),  # 0000000000001111 dec = F hex (4 bits)
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

    if decodeAllSections and flags['RCODE'] != 3:
        # for each authority in the DNS query (nscount in header)
        for authority in range(nscount):
            authorityObject, currentByte = decodeResourceRecord(UDPcontent, currentByte)
            # we add the authority object to the list of answer objects
            authorities.append(authorityObject)

    # a list of additional records
    additional = []

    if decodeAllSections and flags['RCODE'] != 3:
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

        # if type = MX (15), two bytes are added. They supply the 'preference'
        if answer['type'] == 15:
            answer['rdlength'] += 2

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
            # special case where pointed to <root>, this is represented with a 0x0 byte so we represent it with this
            if '<root>' in answer['rdata']:
                answer['rdata'].pop('root')
                answer['rdata'].append(0)

        # append the rdata
        for dataItem in answer['rdata']:
            exportBytes += struct.pack("!B", dataItem)
            currentByte += 1
    return exportBytes

# program flow:
# 1. request a domain to a root DNS server
#   - if no response (timeout) -> try another root DNS
# 2. decode the answer, it contains the TLD nameservers in additional sec
# 3. request the domain to the TLD DNS server (from step 2)
#   - if no response (timeout) -> try another TLD nameserver
# *. decode the answer, if no answers yet keep repeating this: traverse the tree

host = ("192.168.178.207", 53)
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(host)

# map domains to IP addresses
simpleCache = {}

def getCacheItem(requestObject, cacheObject):
    if getDomainString(requestObject['URL']) not in cacheObject:
        return -1
    else:
        cacheItem = cacheObject[getDomainString(requestObject['URL'])]
        if cacheItem['type'] == requestObject['qtype'] and cacheItem['class'] == requestObject['qclass']:
            return cacheItem
        else:
            return -1

# this should run on a separate thread, objects are passed by reference
def maintainCache(cacheObject):
    while True:
        # the list of items to remove because TTL <= 0
        toRemove = []
        for domain, cacheItem in cacheObject.items():
            if cacheItem['ttl'] <= 0:
                toRemove.append(domain)
            else:
                cacheItem['ttl'] -= 1
        for domainToRemove in toRemove:
            cacheObject.pop(domainToRemove)
        
        # ttl is in seconds so we wait one second
        time.sleep(1)


rootServers = ['198.41.0.4', '199.9.14.201', '192.33.4.12', '199.7.91.13', '192.203.230.10', '192.5.5.241', '192.112.36.4', '198.97.190.53', '192.36.148.17', '192.58.128.30', '193.0.14.129', '199.7.83.42', '202.12.27.33' ]

debugOn = True

# note that domainName is a list of URL parts
def resolveRequest(domainRequestObject, DNSip, indent = ''):
    if '' in domainRequestObject['URL']:
        domainRequestObject['URL'].remove('')
    if debugOn:
        if DNSip in rootServers:
            debug.info('Trying to resolve', getDomainString(domainRequestObject['URL']) + ' at server ' + DNSip + ' (root server)', indent = indent, encaps = False)
        else:
            debug.info('Trying to resolve', getDomainString(domainRequestObject['URL']) + ' at server ' + DNSip, indent = indent, encaps = False)
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
    sock.settimeout(1)
    try:
        correctResponse = False
        DNSresponse = {}
        # if IP send to and IP received from are not equal, this packet does not belong here
        while not correctResponse:
            DNSresponseRaw, DNSresponseAddress = sock.recvfrom(512)
            while DNSresponseAddress[0] != DNSip:
                DNSresponseRaw, DNSresponseAddress = sock.recvfrom(512)   
            DNSresponse = decodeRequest(DNSresponseRaw)
            if DNSresponse['id'] == requestPacket['id']:
                correctResponse = True
    except socket.timeout:
        # it is for the calling function to fix this
        if debugOn:
            debug.warning('Timeout', 'DNS response did not return in time', indent=indent, encaps=False)
        return -1

    if DNSresponse['flags']['RCODE'] == 3:
        if debugOn:
            debug.warning('No such name', 'requested domain does not have an IP', indent=indent, encaps=False)
        return -2
    
    cacheResult = getCacheItem(domainRequestObject, simpleCache)
    if cacheResult != -1:
        if debugOn:
            debug.success('Cached answer', getDomainString(cacheResult['rdata']), indent=indent, encaps=False)
        answerList = []
        answerList.append(cacheResult)
        return answerList

    if DNSresponse['ancount'] > 0:
        if debugOn:
            debug.success('Answer found', getDomainString(DNSresponse['answers'][0]['rdata']), indent=indent, encaps=False)
        for answer in DNSresponse['answers']:
            # for testing if cache gets emptied
            # answer['ttl'] = 5
            simpleCache[getDomainString(answer['URL'])] = answer
            if answer['type'] == 5:
                requestObject = {
                    'URL': answer['rdata'], 
                    'qtype': 1, 
                    'qclass': 1
                }
                return resolveRequest(requestObject, rootServers[0], indent + '\t')
            # add the item to the cache
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
                foundIP = resolveRequest(domainRequestObject, ip, indent + '\t')
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
                    onTreeIP = resolveRequest(requestObject, DNSip, indent + '\t')
                    if onTreeIP == -1 or onTreeIP == None:
                        return -1
                    if onTreeIP == -2:
                        return -2
                    for IPresponse in onTreeIP:
                        responseObject = resolveRequest(domainRequestObject, getDomainString(IPresponse['rdata']), indent + '\t')
                        if responseObject != -1 and responseObject != None:
                            return responseObject
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
                    if offTreeIP == -2:
                        return -2
                    for IPresponse in offTreeIP:
                        responseObject = resolveRequest(domainRequestObject, getDomainString(IPresponse['rdata']), indent + '\t')
                        if responseObject != -1 and responseObject != None:
                            return responseObject

def runServer():
    while True:
        try:
            # always 512 bytes
            userRequest, userAddress = sock.recvfrom(512)
            debug.info('Incoming packet', 'from ' + str(userAddress[0]))
            userRequest = decodeRequest(userRequest, False)

            # we do not want responses so we let this slide
            if (userRequest['flags']['QR']):
                debug.warning('No request', 'this packet is dropped since it was a response', encaps=False)
                continue

            for request in userRequest['requests']:
                # we can only resolve type 1 (A) and type 15 (MX) records
                if (request['qtype'] == 1 or request['qtype'] == 15):
                    reqType = 'UNKNOWN'
                    if request['qtype'] == 1:
                        reqType = 'A'
                    elif request['qtype'] == 15:
                        reqType = 'MX'
                    debug.neutral('Resolving query', reqType + ' ' + getDomainString(request['URL']), encaps=False)
                    try:
                        rootSelector = 0
                        solvedRequest = resolveRequest(request, rootServers[rootSelector])
                        while solvedRequest == -1 or solvedRequest == None:
                            # there are 13 root servers to select from
                            rootSelector = rootSelector % 12
                            # we should try another root
                            solvedRequest = resolveRequest(request, rootServers[rootSelector])
                            # increase the root selector
                            rootSelector += 1
                        if solvedRequest == -2:
                            # we set the RCODE flag for the response we send to the user, 3 is NO SUCH NAME
                            userRequest['flags']['RCODE'] = 3
                            debug.success('Resolved query', reqType + ' ' + getDomainString(request['URL']) + ' NO SUCH NAME', encaps=False)
                        else:
                            debug.success('Resolved query', reqType + ' ' + getDomainString(request['URL']) + ' to ' + getDomainString(solvedRequest[0]['rdata']), encaps=False)
                            for answer in solvedRequest:
                                userRequest['answers'].append(answer)
                    except Exception as e:
                        debug.error('Query resolving error', e, encaps=False)
                else:
                    debug.warning('Unsupported query', 'query type ' + str(request['qtype']), encaps=False)
            
            userRequest['flags']['QR'] = True
            userRequest['ancount'] = len(userRequest['answers'])

            debug.info('Outgoing packet', 'to ' + str(userAddress[0]))
            print(userRequest)
            print()
            serverResponse = encodeRequest(userRequest)
            sock.sendto(serverResponse, userAddress) 
        except socket.timeout:
            pass
        except Exception as e:
            debug.error('Server error', e)

def runInterface():
    while True:
        print("Which domain to lookup? (A example.com))")
        inputDomain = input('> ')
        inputDomain = inputDomain.split()
        selectedType = 1
        if inputDomain[0] == 'MX':
            selectedType = 15

        requestObject = {
            #'URL': ['content-signature-2', 'cdn', 'mozilla', 'net'], 
            'URL': getDomainList(inputDomain[1]),
            'qtype': selectedType, 
            'qclass': 1
        }

        reqType = 'UNKNOWN'
        if requestObject['qtype'] == 1:
            reqType = 'A'
        elif requestObject['qtype'] == 15:
            reqType = 'MX'

        rootSelector = 0
        solvedRequest = resolveRequest(requestObject, rootServers[rootSelector])
        while solvedRequest == -1:
            # there are 13 root servers to select from
            rootSelector = rootSelector % 12
            # we should try another root
            solvedRequest = resolveRequest(request, rootServers[rootSelector])
            # increase the root selector
            rootSelector += 1
        if solvedRequest == -2:
            debug.success('Resolved query', reqType + ' ' + getDomainString(requestObject['URL']) + ' NO SUCH NAME', encaps=False)
        else:
            debug.success('Resolved query', reqType + ' ' + getDomainString(requestObject['URL']) + ' to ' + getDomainString(solvedRequest[0]['rdata']), encaps=False)
        print()

cacheThread = threading.Thread(target=maintainCache, args=(simpleCache,))
serverThread = threading.Thread(target=runServer)
interfaceThread = threading.Thread(target=runInterface)

debug.info("Welcome", 'this is the CN-2021 DIY DNS server from Auke Buchel and Elias Groot (lab group 26)\nWhat do you want to do?', encaps=False)
print("\n\t[1] run the DNS server on this machine\n\t[2] interface the DNS server\n")

# of course this is not safe nor error-protected but it is about the DNS, not our interface
startSelection = int(input('> '))

print('\nDo you want to show debug messages? (y/n)')
debugSelection = input('> ')
if debugSelection == 'y':
    debugOn = True
    print('Debug messages shown\n')
else:
    debugOn = False
    print('Debug messages disabled\n')

if startSelection == 1:
    debug.info('Running server', 'on ' + host[0] + ' (over UDP)')
    serverThread.start()
else:
    interfaceThread.start()

# whatever is chosen, cache is always maintained
cacheThread.start()

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
