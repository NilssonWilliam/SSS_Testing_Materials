import socket
import threading
import sys

HOST = ""

remote = ""

PORT = 11111

def receive_data(conn):
    bytes = conn.recv(4096)
    return bytes

def handle_client(conn, addr):
    share = receive_data(conn)
    conn.close()
    print("Received a packet")
    if share == None:
        print("Share was not properly received")
    else:
        c = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        c.connect((remote, PORT))
        c.send(share)
        c.close()
        

def forward_shares():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((HOST, PORT))
        s.listen() 
        print("Server open")       
        while True:
            try: 
                conn, addr = s.accept() 
            except:
                raise RuntimeError("Something went wrong with connection")
            else:
                threading.Thread(target=handle_client,args=(conn, addr)).start()

def main():
    global remote
    if len(sys.argv) >= 2:
        remote = sys.argv[1]
    forward_shares()

if __name__ == "__main__":
    main()