import socket


def startclient(host, port):
    print("Starting client towards host " + str(host) + " and port " + str(port))
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, port))
    s.sendall(b"Hello, world")


if __name__ == "__main__":
    print("Starting pijlwagen application...")
    startclient("127.0.0.1", 5000)
