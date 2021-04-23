import struct
import ctypes
import binascii

def checkSum(string):
    # we have to generate a bitstring from the passed string. We use this weird looking combination of functions to
    # generate the bitstring.
    string = string.encode("utf-8")
    chars = list(string)
    print(chars)

    packedString = struct.pack('s', string)
    binString = binascii.unhexlify(packedString)
    # convert hex to bin
    print(binString)
    # add all codewords together. Specify some rules of addition\


checkSum("Hello")