import socket
import time
import threading
import struct
import copy

# makeup colours
class terminalColors:
        blue = '\033[94m'
        green = '\033[92m'
        yellow = '\033[93m'
        red = '\033[91m'
        end = '\033[0m'
        bold = '\033[1m'


def cleanString(string):
    # string = string.strip()
    string = string.replace("\n", '')
    return string


def findResponseType(data):
    if data.find("HELLO") == 0:
        return "Hello"
    elif data.find("WHO-OK") == 0:
        return "LoggedIn"
    elif data.find("SEND-OK") == 0:
        return "Sent"
    elif data.find("UNKNOWN") == 0:
        return "Unknown"
    elif data.find("DELIVERY") == 0 and data.find("ACK") == -1:
        return "NewMsg"
    elif data.find("IN-USE") == 0:
        return "Used"
    elif data.find("BUSY") == 0:
        return "Busy"
    elif data.find("BAD-RQST-HDR") == 0:
        return "BadHeader"
    elif data.find("BAD-RQST-BODY") == 0:
        return "BadBody"
    elif data.find("VALUE") == 0:
        return "CurrSetting"
    elif data.find("SET-OK") == 0:
        return "Set"
    elif data.find("ACK") != -1:
        return "userACK"
    else:
        raise("Unhandled response type for this protocol.")


# recursive checksum function. Pass this function a list of utf-8 encoded chars and it will blow your mind (only pass message body and seq nr)
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
        # print((result))
        # print(type(result))
        return result


def checkCheck(msg, checkBits):
    # pass this a message in encoded string form to check 
    # convert all chars to binary, we get them in utf8 encoded, so making a list out of them should give us the individual byte objects.
    checkBits = checkBits.decode("utf-8")
    msgList = list(msg)
    intList = []
    totalSum = 0
    
    for num in range(0, len(msgList)):
        totalSum += msgList[num]

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

        if checkBits == myCheckbits:
            return True
        else:
            return False
    elif len(totalSum) == 8:
        myCheckbits = totalSum

        if checkBits == myCheckbits:
            return True
        else:
            return False


def sendAck(data, seqNr):
        seqindex = data.find("SEQ")
        seqNr = data[(seqindex + 4):(seqindex + 5)]
        checkString = "MSG ACK SEQ" + seqNr + " CHECKSUM"
        # print("Sender ack msg: " + checkString)
        checkString = checkString.encode("utf-8")
        checkBits = checkSum(checkString)
        # print("ACK checksum: ")
        # print(checkBits)
        data = data.replace("DELIVERY", "").split()
        sender = data[0]
        ackString = "SEND " + sender + " MSG ACK SEQ" + seqNr + " CHECKSUM " + checkBits + " \n"
        ackString = ackString.encode("utf-8")
        sock.sendto(ackString, host)


def responseHandler(data, respTyp, name):    
    if respTyp == "Hello":
        # check that the server sends us the correct name, indicating that our connection request went through without issue.
        data = data.replace("HELLO", "")
        data = data.split()
        print(data[0])
        if data[0] == name:
            print(terminalColors.green + "[OK] " +
                terminalColors.end + terminalColors.bold + "You are now logged in." + terminalColors.end)
            return True
        else:
            return False
    elif respTyp == "Busy":
        #  We also need the send loop to end if  this occurs
        userActive[1] = True
        print(terminalColors.red +
              "[ERROR] " + terminalColors.end + terminalColors.bold + "Server is busy at the moment." + terminalColors.end)
    elif respTyp == "BadHeader":
        #  We also need the send loop to end if  this occurs
        userActive[1] = True
        print(terminalColors.red +
              "[ERROR] " + terminalColors.end + terminalColors.bold + "A protocol-error occurred (bad header)." + terminalColors.end)
    elif respTyp == "BadBody":
        #  We also need the send loop to end if  this occurs
        userActive[1] = True
        print(terminalColors.red +
              "[ERROR] " + terminalColors.end + terminalColors.bold + "A protocol-error occurred (bad body)." + terminalColors.end)
    elif respTyp == "Used":
        print(terminalColors.yellow +
              "[ERROR] " + terminalColors.end + terminalColors.bold + "This username is already in use." + terminalColors.end)
        return False
    elif respTyp == "LoggedIn":
        data = data.replace("WHO-OK", "")
        names = data.split(",")
        nameList = ""
        for name in names:
            nameList += name + " "
        # !who non-functionality disclaimer due to server implementation (verified by TA)
        print(terminalColors.red + "[DISCLAIMER] " + terminalColors.end + "!who command is non-functional at this time. Please contact a server administrator for details. \n")    
        print(terminalColors.green + "[OK]" +
              terminalColors.end + terminalColors.bold + " These users are logged in:" + terminalColors.end + nameList)
    elif respTyp == "Unknown":
        #  We also need the send loop to end if  this occurs
        userActive[1] = True
        print(terminalColors.yellow +
              "[ERROR] " + terminalColors.end + terminalColors.bold + "The user you tried to reach is currently offline." + terminalColors.end)
    elif respTyp == "Sent":
        #   set "global" bool to true so that sending function knows it can stop making new attempts and wait for next input
        # if userActive[1] == False: 
            # print(terminalColors.green + "[OK] " +
            #   terminalColors.end + terminalColors.bold + "Your message was sent successfully." + terminalColors.end)
        userActive[1] = True
        # print(terminalColors.green + "[OK] " +
        #       terminalColors.end + terminalColors.bold + "Your message was sent successfully." + terminalColors.end)
        
    elif respTyp == "NewMsg":
        # delete SEQ <seqnr> from message body
        seqindex = data.find("SEQ")
        seqNr = data[(seqindex + 4):(seqindex + 5)]
        sendAck(data, seqNr)
        data = data.replace(seqNr, "")
        data = data.replace(" SEQ ", "")

        # delete MSG header
        data = data.replace("MSG ", "")

        # delete checksum header and checksum
        checkSumIndex = data.find("CHECKSUM")
        data = data[:checkSumIndex]

        data = data.replace("DELIVERY", "").split()
        sender = data[0]
        data.pop(0)
        messageBody = ""
        for word in data:
            messageBody = messageBody + " " + word
        print(terminalColors.blue + "[MESSAGE] " +
              terminalColors.end + terminalColors.bold + "@" + sender + ":" + terminalColors.end + messageBody)
        
        
        # # send back acknowledgement message:
        # checkString = "MSG ACK SEQ" + seqNr + " CHECKSUM"
        # # print("Sender ack msg: " + checkString)
        # checkString = checkString.encode("utf-8")
        # checkBits = checkSum(checkString)
        # # print("ACK checksum: ")
        # # print(checkBits)
        # ackString = "SEND " + sender + " MSG ACK SEQ" + seqNr + " CHECKSUM " + checkBits + " \n"
        # ackString = ackString.encode("utf-8")
        # sock.sendto(ackString, host)

    elif respTyp == "CurrSetting":
        data = data.replace("VALUE", "").split()
        setting = "Setting" # server apparently doesnt give back setting name.
        value = data[0]
        if len(data) > 2:
            upper = data[2]
            print(terminalColors.green + "[" + setting + "] " + terminalColors.end + " " + value + upper)
        print(terminalColors.green + "[" + setting + "] " + terminalColors.end + value)
    elif respTyp == "Set":
        print(terminalColors.green + "[SET-OK]" + terminalColors.end)
    elif respTyp == "userACK":
        # print("ack recieved")
        print(terminalColors.green + "[OK] " +
              terminalColors.end + terminalColors.bold + "Your message was sent successfully." + terminalColors.end)
        userActive[2] = True
    else:
        raise("Message could not be handled")


def chatInputLoop(sock, userActive, sequenceNr):
    while userActive[0] == True:
        # just ask for input
        inputData = input("")
        if inputData == "!quit":
            userActive[0] = False
            sock.close()
            quit()
        elif inputData == "!who":
            # who doesn't work properly because of the server side implementation, so we add a disclamer rather than fixing it.
            sendString = "WHO\n".encode("utf-8")
            # we don't catch the responses in this loop
            sock.sendto(sendString, host)
        elif inputData.find("@") == 0:
            inputData = inputData.replace("@", "")
            inputData = inputData.split()  # split by spaces

            # item 0 is the receiver of our message
            sendString = "SEND " + inputData[0]
            inputData.pop(0)
            
            # for our checksum checker, add a start flag for our message field
            sendString += " MSG "
            checkSumString = "MSG "

            # we restore the words in the sentence to a normal string
            for word in inputData:
                sendString += word + " " 
                checkSumString += word + " "

            # checksum should be computed here and appended to the message before \n
            # calculate checksum
            # checksum is calculated over MSG <message> SEQ <seqnr> CHECKSUM 
            # make sure this doesn't happen, only calculate checksum for our message, seqnr. Do this by calling checksum with a string containing only these parts.
            sendString = sendString + "SEQ "+ str(sequenceNr[0]) + " "
            checkSumString = checkSumString + "SEQ " + str(sequenceNr[0]) + "CHECKSUM "
            checkSumString = checkSumString.encode("utf-8")
            checkSumList = list(checkSumString)
            checkBits = ""
            checkBits = checkSum(checkSumList)
            # print("Sender checksum: ")
            # print(checkBits)
            sendString = sendString + "CHECKSUM " + checkBits
            
            sendString += "\n"
            sendString = sendString.encode("utf-8")
            
            # sendString = sendString.encode("utf-8")
            # we do have to reset the acknowledgement bool every time we send or we will never enter our loop again :)
            # this bool tells us if the message was acknowledged or not.
            userActive[1] = False
            userActive[2] = False
            maxAttemptNumber = 20
            currAttemptNumber = 0
            # sock.sendto(sendString.encode("utf-8"), host)
            # now we have to somehow make sure our message is sent properly, otherwise, the client should try again until it gets confirmation.
            # we can do this by checking the second boolean in userActive[]. The response handling thread should change this bool
            # to true when it recieves a message containing SET-OK, prompting a loop in this function to stop sending the packet over and over again.
            # We start a timer here when sending to keep track of our send time.
            while (userActive[1] == False or userActive[2] == False) and currAttemptNumber < maxAttemptNumber:
                # append sequencenr to message
                sock.sendto(sendString, host)
                print(terminalColors.yellow + "[STATUS] " + terminalColors.end + terminalColors.bold+  "Waiting for acknowledgement...\n" + terminalColors.end)
                time.sleep(0.5)
                currAttemptNumber += 1
                if userActive[2] == True:
                    break
            # increment sequence number (global var)
            sequenceNr[0] += 1
            # make sequenceNr wrap around when it exceeds 8 bits. We likely won't need a sequence nr larger than this
            if sequenceNr[0] == 31:
                sequenceNr[0] = 0

        # server settings
        elif inputData.find("SET") == 0:
            inputData = inputData.split()
            if len(inputData) == 3:
                sendString = "SET " + inputData[1] + " " + inputData[2] + "\n"
            elif len(inputData) == 4:
                sendString = "SET " + inputData[1] + " " + inputData[2] + " " + inputData[3] + "\n"
            sendString = sendString.encode("utf-8")
            sock.sendto(sendString, host)
        elif inputData.find("GET") == 0:
            sendString = inputData
            sendString = sendString + "\n"
            sendString = sendString.encode("utf-8")
            sock.sendto(sendString, host)
        elif inputData.find("RESET") == 0:
            sendString = inputData
            sendString = sendString + "\n"
            sendString = sendString.encode("utf-8")
            sock.sendto(sendString, host)


def chatReceiverLoop(sock, userActive):
    recievedNrs = [-1]
    ackedNrs = [-1]

    while userActive[0] == True:
        recievedData = ""
        sock.settimeout(1)
        
        # receivedData = sock.recv(4096).decode("utf-8")
        # not very efficient, scans the whole string over and over again
        # while "\n" not in recievedData and userActive[0] == True:
        try:
            data, addr = sock.recvfrom(65565)
            # deepcopy of data so that we can pass this to our checksum checker later on before it is converted.
            checkSumString = copy.deepcopy(data)
            recievedData += data.decode("utf-8")
            recievedAddr = addr


            # The following code checks the checksum and sequence number. If we were able to recieve this from the server 
            # in the format that we wanted, we could do this cleaner. As it stands, we can only implement such checks in 
            # the user to user messages themselves. Therefore, the checks below will only apply to the messages coming from other 
            # users. This is why we first check what type of message we have. You should note that if the server were to implement 
            # our message format, this check would not be necessary. In that case we would be able to do the checks here, which is 
            # why we didn't move this code to the function that deals with user-user messaging, but put it in this central part instead.

            # this if statement makes sure we only apply our checks to user-user messages.
            tempResCheck = findResponseType(recievedData)
            if tempResCheck == "userACK":
                msgStartIndex = recievedData.find("MSG")
                checkSumIndex = recievedData.find("CHECKSUM")
                seqNrIndex = recievedData.find("SEQ")
                senderSeqNr = recievedData[(seqNrIndex + 3): (seqNrIndex + 4)]
                # print(senderSeqNr)
                senderCheckSum = checkSumString[(checkSumIndex + 9):(checkSumIndex + 17)]
                checkSumString = checkSumString[msgStartIndex:(checkSumIndex + 8)]
                noErrors = checkCheck(checkSumString, senderCheckSum)
                # print(noErrors)
                if noErrors == False:
                    continue
                # deal with duplicate ack numbers (experimental)
                elif senderSeqNr in ackedNrs:
                    continue

                ackedNrs.append(senderSeqNr)
            elif tempResCheck == "NewMsg":
                
                # check checksum here, so that we know that only correct messages pass on to the next check for sequence number.
                # if the message contained errors before, we dont mind recieving it again in hopes of it being correct this time.
                # Only if the message contains no bitflips (that we know of) do we proceed to the next check: sequence numbers, where
                # we try to deal with transfer delay.

                # calculate checksum for the message we recieved
                # find MSG string and only check from there
                msgStartIndex = recievedData.find("MSG")
                checkSumIndex = recievedData.find("CHECKSUM")
                
                # our checksum doesn't cover the sender or the header as sent by the server, as this is part of the protocol on the server
                # side that we cannot alter. Too bad.
                # Checksum was calculated over MSG <message> SEQ <seqnr> CHECKSUM .
                # Make sure we only check over this range as well.
                senderCheckSum = checkSumString[(checkSumIndex + 9):(checkSumIndex + 17)]
                checkSumString = checkSumString[msgStartIndex:(checkSumIndex + 8)]
                # for ACK: "MSG ACK <seqnr> CHECKSUM"
                # print("going to check checksum from string: ")
                # print(checkSumString)
                noErrors = checkCheck(checkSumString, senderCheckSum)
                if noErrors == False:
                    continue

                # Here we check the data for the sequence number. First we look for the sequence "~SEQ~" which we append before
                # the sequence number every time we send. If the sequence number is the same as one we already had, or lower, or more
                # than the current max + 1, we discard the message.
                # This doesnt work when sending to yourself, because the server doesnt give us a sequence number. Only works
                # if you have 2 separate terminals sending to eachother.
                msgSeqNrLoc = recievedData.find("SEQ")
                # get int version of index.
                if msgSeqNrLoc == -1:
                    # seq area got corrupted, the message is therefore useless. Discard.
                    continue
                seqNr = int(recievedData[(msgSeqNrLoc + 4):(msgSeqNrLoc + 5)])

                if seqNr in recievedNrs:
                    # we recieved this message already. Our acknowledgement must have been lost
                    sendAck(recievedData, seqNr)
                    continue
                elif seqNr < max(recievedNrs):
                    # this message is older than the newest one we recieved correctly and we assume was stuck in transmission
                    # for a long time. We discard old messages to ensure we maintain message order.
                    continue
                elif seqNr != (max(recievedNrs) + 1):
                    # this message is not the next one we were expecting. We could make the decision to buffer this message and 
                    # wait for the ones that should come before it, !!!!!ASK TA IF THIS IS NECESSARY!!!!!
                    # for now just discard it.
                    continue


                # only if sequence number is correct do we want to use this message and
                # send back acknowledgement message

                recievedNrs.append(seqNr)

                # instead of our client taking the server sent send-ok message as confirmation, we should make it so that we send
                # our own acknowledgement here. A corrupted message would still be sent correctly according to the server, but we can still
                # find out in this try part that the message got corrupted along the way. Thus, an automatic response should be sent here.
                # something like @<source> ACKNOWLEDGED should do.

        except socket.timeout:
            continue
        except ValueError:
            continue
        except:
            continue

        try:
            if userActive[0] == True:
                # we do not need the delimiter anymore
                recievedData = cleanString(recievedData)
                # print("receivedData: " + receivedData)
                resType = findResponseType(recievedData)
                # null passed as name variable, as we don't need to check name correctness every time. This could be avoided as it is pretty ugly
                # by separating the name check function from responseHandler, but that would add more complexity to our code and python doesn't care anyways.
                responseHandler(recievedData, resType, None)
        except:
            continue


# mind your scope please (so threads can access the sock object)
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
host = ("3.121.226.198", 5382)

nameOk = False
while nameOk == False:
    if nameOk == True:
        break

    # create the socket again since it is not usable after disconnect (on user IN-USE)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    # connect to our server on a port that nobody is listening to currently
    
    # host = ("127.0.0.1", 5379)
    sock.connect(host)

    # enter a name
    name = input("Please enter your name:\n")
    if name == "!quit":
        exit()

    # send first handshake message
    inputData = "HELLO-FROM " + name + "\n"
    sock.sendto(inputData.encode("utf-8"), host)

    # wait for server response, max byte size set to 4096
    recievedData = ""
    
    # print("%s" % receivedData)
    # recievedData = recievedData.decode("utf-8")

    while "\n" not in recievedData:
        data, addr = sock.recvfrom(4096)
        recievedData += data.decode("utf-8")
        recievedAddr = addr

        # todo: maybe check for if not data?
    print(recievedAddr)

    # handshake recieved, check status
    respTyp = findResponseType(recievedData)
    nameOk = responseHandler(recievedData, respTyp , name)

# ugly fix to pass by reference (so we avoid global variables)
userActive = []
# Connection alive bool
userActive.append(True)
# Message acknowledgement from server recieved bool
userActive.append(False)
sequenceNr = []
sequenceNr.append(0)
# message ack from user client bool
userActive.append(False)

# use threading to get into our main chat client functions
sendThread = threading.Thread(target=chatInputLoop, args=(sock, userActive, sequenceNr))
sendThread.daemon = True
receiveThread = threading.Thread(
    target=chatReceiverLoop, args=(sock, userActive))

sendThread.start()
receiveThread.start()
