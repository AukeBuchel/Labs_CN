import socket
import threading

# setup the local server
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
host = ("127.0.0.1", 5378)
sock.bind(host)
sock.listen()


class Users:
    def __init__(self):
        self.activeDict = {}
        self.activeList = []

    def userExists(self, username):
        if username in self.activeList:
            return True
        else:
            return False

    def addUser(self, username, userSocket):
        self.activeList.append(username)
        self.activeDict[username] = userSocket

    def removeUser(self, username):
        self.activeList.remove(username)
        self.activeDict.pop(username)

    def getSocket(self, username):
        return self.activeDict[username]

    def getList(self):
        returnString = ""
        for user in self.activeList:
            returnString += ' ' + user
        return returnString.strip()  # remove the first space


def cleanString(string):
    string = string.strip()
    string = string.replace("\n", '')
    return string


# our pretty user management system (just a class that controls a list and a dict)
activeUsers = Users()


def handleUser(client, address):
    userAuthenticated = False
    currentUser = ''
    while not userAuthenticated:
        try:
            receivedData = client.recv(4096)
            if not receivedData:
                # we lost connection :(
                print(
                    f"Connection with {address} was closed (during authentication)")
                # at least we do not need to remove anyone :)
            else:
                receivedData = receivedData.decode("utf-8")
                receivedData = cleanString(receivedData)
                # make a list (array if you will) of this string splitted by spaces
                receivedData = receivedData.split()
                # first item (0) is HELLO-FROM (if everything is well)
                # second item (1) is the username
                print(receivedData)
                if receivedData[0] == 'HELLO-FROM':
                    # if there is no name inserted, this is obviously invalid (0 = header, 1 = username)
                    if len(receivedData) < 2:
                        client.sendall("BAD-RQST-BODY\n".encode("utf-8"))
                    else:
                        if activeUsers.userExists(receivedData[1]):
                            client.sendall("IN-USE\n".encode('utf-8'))
                        else:
                            activeUsers.addUser(receivedData[1], client)
                            client.sendall(
                                f"HELLO {receivedData[1]}\n".encode("utf-8"))
                            currentUser = receivedData[1]
                            userAuthenticated = True
                else:
                    client.sendall("BAD-RQST-HDR\n".encode("utf-8"))
        except OSError as errorMessage:
            client.sendall("BAD-RQST-HDR\n".encode("utf-8"))
            print(errorMessage)

    userStillActive = True
    while userStillActive:
        # just check for all possible commands
        receivedData = client.recv(4096).decode("utf-8")
        # switch statements
        if not receivedData:
            # we lost connection :(
            print(
                f"Connection with {address} was closed (after authentication)")
            userStillActive = False
            # we also need to remnove this user :(
            activeUsers.removeUser(currentUser)
        else:
            receivedData = cleanString(receivedData)
            # make a list (array if you will) of this string splitted by spaces
            # the command will always be at index 0 and arguments at index 1 (or higher)
            receivedData = receivedData.split()
            print(receivedData)

            if receivedData[0] == 'WHO':
                # send a list of logged in users, activeList is already formatted
                activeList = activeUsers.getList()
                client.sendall(f"WHO-OK {activeList}\n".encode("utf-8"))
            elif receivedData[0] == 'SEND':
                # save us the trouble if there is no message (0 = header, 1 = receiver, 2+ = message)
                if len(receivedData) < 3:
                    client.sendall("BAD-RQST-BODY\n".encode("utf-8"))
                else:
                    receivingUser = receivedData[1]
                    # we can only send if the user exists
                    if not activeUsers.userExists(receivingUser):
                        client.sendall("UNKNOWN\n".encode("utf-8"))
                    else:
                        try:
                            # get the receiver socket object we need to send any message to the receiver
                            receiverSocket = activeUsers.getSocket(
                                receivingUser)
                            message = ""
                            # since receivedData is a list, we need to append all words again
                            for wordIndex in range(2, len(receivedData)):
                                if wordIndex == 1:
                                    message += receivedData[wordIndex]
                                else:
                                    message += " " + receivedData[wordIndex]
                            # we send the delivery to using the socket of the receiver
                            receiverSocket.sendall(
                                f"DELIVERY {currentUser} {message}\n".encode("utf-8"))
                            # we send a confirmation to the original sender of the message
                            client.sendall("SEND-OK\n".encode("utf-8"))
                        except OSError as errorMessage:
                            client.sendall("ERROR\n".encode("utf-8"))
                            print(errorMessage)
            else:
                client.sendall("BAD-RQST-HDR\n".encode("utf-8"))


while True:
    # wait for a connection to come in
    (client, address) = sock.accept()
    print(f"New connection from {address}\n")
    # create a new thread to allow multiple connections
    thread = threading.Thread(target=handleUser, args=(client, address))
    thread.start()
