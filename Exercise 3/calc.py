import struct

# provided checksum gets passed only the relevant <MESSAGE> SEQ <SEQNR> fields, it will calculate and check the checksum correctly.




def checkSum(sList):
    # pass this function only the message and sequence number part of the message.
    result = 0
    # print(sList)
        # to perform binary addition, we simply add the values from sList, convert to binary, check
        # the length.
        # if length > 8:
        #       cut all MSB until length is 8 (10 with the 0b prefix)
        #       convert result to number
        #       perform addition again (so call with new numbers recursively)
        # else:
        #       invert all bits, return checksum.
    for i in range(len(sList)):
        result += sList[i]
    # print(result)
    result = bin(result)
    # print(result)

    # empty our sList for next call
    sList = []
    num1 = ""
    num2 = ""
    if len(result) > 10:
        num1 += result[2:(len(result) - 8)]
        num1 = int(num1, 2)
        num2 += result[(len(result) - 8):]
        num2 = int(num2, 2)
        sList.append(num1)
        sList.append(num2)
        # print(sList)
        return checkSum(sList)
    else:
        # delete 0b prefix
        result = result[2: : ]
        # add some zeros before to get 8 bits again
        while len(result) < 8:
            result = "0" + result

        # perform one's complement
        # print(result)
        for i in range(len(result)):
            if result[i] == "1":
                result = result[:i] + "0" + result[(i+1):]
            elif result[i] == "0":
                result = result[:i] + "1" + result[(i+1):]
        # result = result[:0] + "0b" + result[1:]
        # result = int(result, 2)
        # print((result))
        # print(type(result))
        return result


def checkCheck(msg, checkBits):
    # pass this a message in encoded string form to check 
    # convert all chars to binary, we get them in utf8 encoded, so making a list out of them should give us the individual byte objects.
    msgList = list(msg)
    intList = []
    MSGindex = -3
    totalSum = 0
    
    # now contains a list of integers, simple byte representations of the chars in the message.
    # compare checksum over DELIVERY <source> <message> SEQ <seqnr> <\n>
    # but this will be different from our original checksum, so we must delete the "DELIVERY <source> part"
    # our incoming message includes " MSG " which starts our message field. We skip all that comes before this in our checksum and
    # in our list, "MSG " will appear as the sequence [77, 83, 71]. If we find this, we know where to start our checksum calculation from. If we do not, we can discard
    # the message by default.
    for i in range(len(msgList)):
        if msgList[i] == 77 and msg[i+1] == 83 and msg[i+2] == 71:
            MSGindex = i
    # now add all binary values of all characters to get the checksum
    # checkBits = int(checkBits, 2)


    # print(checkSum)
    for i in range((MSGindex + 3), len(msgList)):
        totalSum += msgList[i]
    # now we need to again perform carry addition. only if we end up with 11111111 is the message correct and should it be accepted.
    totalSum = bin(totalSum)
    # delete 0b prefix
    totalSum = totalSum[2: : ]

    while len(totalSum) < 8:
        totalSum = "0" + totalSum
    if len(totalSum) > 8:
        num1 = totalSum[0:(len(totalSum) - 8)]
        num1 = int(num1, 2)
        num2 = totalSum[(len(totalSum) -8):]
        num2 = int(num2, 2)
        intList.append(num1)
        intList.append(num2)
        myCheckbits = checkSum(intList)

        print(checkBits)
        print(myCheckbits)

        if checkBits == myCheckbits:
            return True
        else:
            return False
    elif len(totalSum) == 8:
        myCheckBits = totalSum

        print(checkBits)
        print(myCheckbits)

        if checkBits == myCheckbits:
            return True
        else:
            return False




data = "Hello"
data = data.encode("utf-8")
dataList = list(data)
print(dataList)
checkBits = ""
checkBits = checkSum(dataList)
correctRecieved = checkCheck(data, checkBits)
print(correctRecieved)