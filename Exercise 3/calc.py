import struct

def checkSum(sList):

    result = 0
    # print(sList)

    for i in range(len(sList)):
        # to perform binary addition, we simply add the values from sList, convert to binary, check
        # the length.
        # if length > 8:
        #       cut all MSB until length is 8 (10 with the 0b prefix)
        #       convert result to number
        #       perform addition again (so call with new numbers recursively)
        # else:
        #       invert all bits, return checksum.
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

        checkSum(sList)
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
        print(result)
        return result


# def checkCheck(msg, checkSum):
#     # pass this a message in string form to check 


data = "Hello"
data = data.encode("utf-8")
dataList = list(data)
# print(dataList)
checkSum(dataList)
