import socket



# function that checks for response type
def responseType(data):
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

def errorHandler(data, respTyp):
    if respTyp == "Hello":
        print("Login OK")
    elif respTyp == "Busy":
        print("Server is busy at the moment. Please check API documentation.")
    elif respTyp == "BadHeader":
        print("Bad request header. Please try again.")
    elif respTyp == "BadBody":
        print("Bad request body. Please check API documentation.")
    elif respTyp == "Used":
        print("This username is already in use.")
    elif respTyp == "LoggedIn":
        print("These users are logged in: ")
        data = data.replace("WHO-OK", "")
        names = data.split(",")
        nameList = ""
        for name in names: 
            nameList = nameList + name + " "
        print(nameList)
    elif respTyp == "Unknown":
        print("This user is not currently online.")
    elif respTyp == "Sent":
        print("Message sent successfully.")
    elif respTyp == "NewMsg":
        data = data.replace("DELIVERY" , "")
        data = data.split(" ")
        print("Incoming message from " + data[0] + ": ")
        del data[0]
        for word in data:
            print(" " + word + " ")


def chatLoop(sock, respTyp, data):
    quitBool = False
    while quitBool == False:
        # client side input
        x = input()
        if x == "!quit":
            quirBool = True
            exit()
        elif x == "!who":
            sendString = "WHO\n"
            sendString = sendString.encode("utf-8")
            sock.sendall(sendString)
        elif x.find("@") == 0:
            x.replace("@" , "")
            xArray = x.split(" ")
            sendString = "SEND " + xArray[0]
            del xArray[0]
            xlength = len(xArray)
            for i in range(0, xlength):
                sendString = sendString + " " + xArray[i]
            sendString = sendString + "\n"
            sendString = sendString.encode("utf-8")
            sock.sendall(sendString)

        # wait for a server response
        sock.settimeout(2)
        try:
            incoming = sock.recv(4096)
            incoming = incoming.decode("utf-8")
            typeRes = responseType(incoming)
            errorHandler(incoming, typeRes)
        except socket.timeout:
            pass
            
            
        
            
# connect to server
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
host = ("3.121.226.198", 5378)
sock.connect(host)

# enter a name
name = input("Enter name please: ")

# send first handshake message
string_bytes = "HELLO-FROM " + name + "\n"
string_bytes = string_bytes.encode("utf-8")
sock.sendall(string_bytes)

# wait for server response, max byte size set to 4096
data = sock.recv(4096)
if not data:
    # no data found on the socket
    print("Socket closed. Please contact a server administrator.")
else : 
    # handshake recieved, check status
    data = data.decode("utf-8")
    respTyp = responseType(data)
    errorHandler(data, respTyp)
    chatLoop(sock, respTyp, data)


# close the socket like a good programmer ;)
sock.close()