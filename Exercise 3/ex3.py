import socket
import time
import threading



def cleanString(string):
    string = string.strip()
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
    elif data.find("DELIVERY") == 0:
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
    else:
        raise("Unhandled response type for this protocol.")


def responseHandler(data, respTyp):
    class terminalColors:
        blue = '\033[94m'
        green = '\033[92m'
        yellow = '\033[93m'
        red = '\033[91m'
        end = '\033[0m'
        bold = '\033[1m'

    if respTyp == "Hello":
        print(terminalColors.green + "[OK] " +
              terminalColors.end + terminalColors.bold + "You are now logged in." + terminalColors.end)
        return True
    elif respTyp == "Busy":
        print(terminalColors.red +
              "[ERROR] " + terminalColors.end + terminalColors.bold + "Server is busy at the moment." + terminalColors.end)
    elif respTyp == "BadHeader":
        print(terminalColors.red +
              "[ERROR] " + terminalColors.end + terminalColors.bold + "A protocol-error occurred (bad header)." + terminalColors.end)
    elif respTyp == "BadBody":
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
        print(terminalColors.green + "[OK]" +
              terminalColors.end + terminalColors.bold + " These users are logged in:" + terminalColors.end + nameList)
    elif respTyp == "Unknown":
        print(terminalColors.yellow +
              "[ERROR] " + terminalColors.end + terminalColors.bold + "The user you tried to reach is currently offline." + terminalColors.end)
    elif respTyp == "Sent":
        print(terminalColors.green + "[OK] " +
              terminalColors.end + terminalColors.bold + "Your message was sent successfully." + terminalColors.end)
    elif respTyp == "NewMsg":
        data = data.replace("DELIVERY", "").split()
        sender = data[0]
        data.pop(0)
        messageBody = ""
        for word in data:
            messageBody = messageBody + " " + word
        print(terminalColors.blue + "[MESSAGE] " +
              terminalColors.end + terminalColors.bold + "@" + sender + ":" + terminalColors.end + messageBody)
    elif respTyp == "CurrSetting":
        data = data.replace("VALUE", "").split()

        setting = data[0]
        value = data[1]
        if len(data) > 2:
            upper = data
            print(terminalColors.green + "[" + setting + "]" + terminalColors.end + value + upper)
        print(terminalColors.green + "[" + setting + "]" + terminalColors.end + value)
    elif respTyp == "Set":
        print(terminalColors.green + [SET-OK] + terminalColors.end)

    else:
        raise("Message could not be handled")


def chatInputLoop(sock, userActive):
    while userActive[0] == True:
        # just ask for input
        inputData = input("")
        if inputData == "!quit":
            userActive[0] = False
            quit()
            sock.close()
        elif inputData == "!who":
            # we don't catch the responses in this loop
            sock.sendall("WHO\n".encode("utf-8"))
        elif inputData.find("@") == 0:
            inputData = inputData.replace("@", "")
            inputData = inputData.split()  # split by spaces

            # item 0 is the receiver of our message
            sendString = "SEND " + inputData[0]
            inputData.pop(0)

            # we restore the words in the sentence to a normal string
            for word in inputData:
                sendString += " " + word

            sendString += "\n"
            sock.sendall(sendString.encode("utf-8"))
        elif inputData.find("SET") == 0:
            inputData = inputdata.split()
            if len(inputData) == 3:    
                sendString = "SET" + inputData[1] + inputData[2]
            elif len(inputData) == 4:
                sendString = "SET" + inputData[1] + inputData[2] + inputData[3] + "\n"
                sendString = sendString.encode("utf-8")
                sock.sendall(sendString)
        elif inputData.find("GET") == 0:
            sendString = sendString + "\n"
            sendString = sendString.encode("utf-8")
            sock.sendall(sendString)
        elif inputData.find("RESET") == 0:
            sendString = sendString + "\n"
            sendString = sendString.encode("utf-8")
            sock.sendall(sendString)


def chatReceiverLoop(sock, userActive):
    while userActive[0] == True:
        receivedData = ""
        sock.settimeout(1)

        # receivedData = sock.recv(4096).decode("utf-8")
        # not very efficient, scans the whole string over and over again
        while "\n" not in receivedData and userActive[0] == True:
            try:
                data, addr = sock.recvfrom(10)
                recievedData += data.decode("utf-8")
                recievedAddr = addr

            except socket.timeout:
                continue

        if userActive[0] == True:
            # we do not need the delimiter anymore
            receivedData = cleanString(receivedData)
            # print("receivedData: " + receivedData)
            resType = findResponseType(receivedData)
            responseHandler(receivedData, resType)


# mind your scope please (so threads can access the sock object)
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

nameOk = False
while nameOk == False:
    if nameOk == True:
        break

    # create the socket again since it is not usable after disconnect (on user IN-USE)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    # connect to our server on a port that nobody is listening to currently
    host = ("3.121.226.198", 5382)
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
    recievedData, recievedAddr = sock.recvfrom(4096)
    # print("%s" % receivedData)
    recievedData = recievedData.decode("utf-8")
    print(recievedAddr)

    # while "\n" not in receivedData:
    #     receivedData += sock.recvfrom(10).decode("utf-8")
    #     iterator += 1

        # todo: maybe check for if not data?

    # handshake recieved, check status
    respTyp = findResponseType(recievedData)
    nameOk = responseHandler(recievedData, respTyp)

# ugly fix to pass by reference (so we avoid global variables)
userActive = []
userActive.append(True)

# use threading to get into our main chat client functions
sendThread = threading.Thread(target=chatInputLoop, args=(sock, userActive))
sendThread.daemon = True
receiveThread = threading.Thread(
    target=chatReceiverLoop, args=(sock, userActive))

sendThread.start()
receiveThread.start()
