import struct


def bytesMaker(data):
    # get passed some data, string format, and compute checksum
    byteSet = []
    data = data.encode("utf-8")

    for char in data:
        byte = bin(char)
        # byte = int(byte, 2)
        byteSet.append(byte[2:])
        # byteSet.append(byte)
    # print(byteSet)
    sumCalc(byteSet)

def sumCalc(data):
# get passed a list containing bytes in strings of bits format

# check max length of codewords is 8. If less, append some 0s to make sure we 
    maxLen = 8
    for i in range(len(data)):
        while len(data[i]) < 8:
            data[i] = "0" + data[i]
    print(data)

    # perform binary addition. This can be done multiple ways. One is to simply specify binary addition.
    # the alternative is to add the non-binary 







# some stupid, non-functional attempts using struct. 
# ================================================= 1
    # convert to ascii number
    # a = data.encode('utf-8')
    # nrel = len(a)
    # b = bytes()
    # for i in range (nrel):
    #     # convert to bytes
    #     b += (struct.pack("!b",a[i]))
    # print(b)

# ================================================= 2
    
    # pack all chars one at a time
    # for char in data:
    #     byte = bin(char)
    #     print(len(byte))
        # struct is the worst, please act like normal bytes and bits next time <3

        # byte = bytes()
        # byte = struct.pack('!c', char)
        # # byte = int(byte, 16)

    #     byteSet.append(byte)
    # print(byteSet)


bytesMaker("aä")