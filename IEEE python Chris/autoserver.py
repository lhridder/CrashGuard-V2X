import socket


def startserver(host, port):
    print("Starting server on host " + str(host) + " and port " + str(port))
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((host, port))
    s.listen()
    conn, addr = s.accept()
    with conn:
        print("New connection from " + str(addr))
        while True:
            data = conn.recv(1024)
            if not data:
                break
            print("Received message: " + str(data))


if __name__ == "__main__":
    print("Starting car application...")
    startserver("127.0.0.1", 5000)
