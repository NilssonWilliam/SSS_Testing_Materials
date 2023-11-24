import random
import functools
import sys
import socket
import pickle
import threading
import aes
import shamirs

"""
Code largely based on the example code found at https://en.wikipedia.org/wiki/Shamir%27s_secret_sharing
"""

PRIME = 4294967311

threshold = 10

shares = 10

HOST = ""

REMOTE = "localhost"

PORT = 11111

shares_acc = []

RINT = functools.partial(random.SystemRandom().randint, 0)

def gcd(a, b):
    x = 0
    lx = 1
    y = 1
    ly = 0
    while b != 0:
        q = a // b
        a, b = b, a % b
        x, lx = lx - q * x, x
        y, ly = ly - q * y, y
    return lx, ly

def fielddiv(num, den):
    inv, _ = gcd(den, PRIME)
    return num * inv

def interpolate(x, xs, ys):
    def arrayproduct(arr):
        acc = 1
        for v in arr:
            acc *= v
        return acc
    k = len(xs)
    nums = []
    dens = []
    for i in range(k):
        others = list(xs)
        cur = others.pop(i)
        nums.append(arrayproduct(x - o for o in others))
        dens.append(arrayproduct(cur - o for o in others))
    den = arrayproduct(dens)
    num = sum([fielddiv(nums[i] * den * ys[i] % PRIME, dens[i]) for i in range(k)])
    return (fielddiv(num, den) + PRIME) % PRIME

def recover_secret(shares):
    xs, ys = zip(*shares)
    return interpolate(0, xs, ys)

def receive_data(conn):
    bytes = conn.recv(4096)
    data = pickle.loads(bytes)
    return data

def handle_client(conn, addr):
    share = receive_data(conn)
    if share == None:
        print("Share was not properly received")
    else:
        shares_acc.append(share)

def test_secretsharing(iters):
    for i in range(iters):
        global shares_acc
        shares_acc = []
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.settimeout(0.1)
            s.bind((HOST, PORT))
            s.listen(1)        
            while True:
                try: 
                    conn, addr = s.accept() 
                except socket.timeout:
                    if len(shares_acc) >= threshold:
                        break
                    pass
                except:
                    raise
                else:
                    threading.Thread(target=handle_client,args=(conn, addr)).start()
            secret = recover_secret(shares_acc)
            c = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            c.connect((REMOTE, PORT+1))
            c.sendall(str(secret).encode("utf-8"))
            c.close()

def test_secretsharing_package(iters):
    for i in range(iters):
        global shares_acc
        shares_acc = []
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.settimeout(0.1)
            s.bind((HOST, PORT))
            s.listen(1)        
            while True:
                try: 
                    conn, addr = s.accept() 
                except socket.timeout:
                    if len(shares_acc) >= threshold:
                        break
                    pass
                except:
                    raise
                else:
                    threading.Thread(target=handle_client,args=(conn, addr)).start()
            secret = shamirs.interpolate(shares_acc, threshold=threshold)
            c = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            c.connect((REMOTE, PORT+1))
            c.sendall(str(secret).encode("utf-8"))
            c.close()

def test_unprotected(iters):
    for i in range(iters):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((HOST, PORT))
            s.listen(1)
            conn, addr = s.accept()
            data = conn.recv(4096).decode("utf-8")        
            c = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            c.connect((REMOTE, PORT+1))
            c.sendall(str(data).encode("utf-8"))
            c.close()

def test_aes(iters):
    for i in range(iters):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((HOST, PORT))
            s.listen(1)
            conn, addr = s.accept()
            key = conn.recv(4096)        
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((HOST, PORT))
            s.listen(1)
            conn, addr = s.accept()
            data = conn.recv(4096)     
            res = aes.decrypt(key, data) 
            c = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            c.connect((REMOTE, PORT+1))
            c.sendall(res)
            c.close()

def main():
    global threshold 
    global shares
    iters = 10
    if len(sys.argv) >= 2:
        threshold = int(sys.argv[1])
        shares = int(sys.argv[1])
    if len(sys.argv) >= 3:
        iters = int(sys.argv[2])
    print("Starting unprotected tests")
    test_unprotected(iters)
    print("Starting secret sharing tests")
    test_secretsharing(iters)
    print("Starting secret sharing tests using package implementation")
    test_secretsharing_package(iters)
    print("Starting AES tests")
    test_aes(iters)
    



if __name__ == "__main__":
    main()