import random
import functools
import socket
import pickle
import threading
import aes
import shamirs
import math
import rsa

"""
Secret sharing code largely based on the example code found at https://en.wikipedia.org/wiki/Shamir%27s_secret_sharing
"""

PRIME = 2 ** 127 - 1

threshold = 10

shares = 10

HOST = ""

REMOTE = "192.168.1.212"

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
        started = False
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.settimeout(0.000001)
            s.bind((HOST, PORT))
            s.listen(threshold)        
            while True:
                try: 
                    conn, addr = s.accept() 
                except socket.timeout:
                    if len(shares_acc) >= threshold and not started:
                        started = True
                        threading.Thread(target=do_response).start()
                    if len(shares_acc) >= shares:
                        break
                    pass
                except:
                    raise
                else:
                    threading.Thread(target=handle_client,args=(conn, addr)).start()

def do_response():
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
            s.settimeout(0.000001)
            s.bind((HOST, PORT))
            s.listen(threshold)        
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
            s.listen()
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
            s.listen()
            conn, addr = s.accept()
            key = conn.recv(4096)        
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((HOST, PORT))
            s.listen()
            conn, addr = s.accept()
            data = conn.recv(4096)     
            res = aes.decrypt(key, data) 
            c = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            c.connect((REMOTE, PORT+1))
            c.sendall(res)
            c.close()

def test_rsa(iters):
    for i in range(iters):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((HOST, PORT))
            s.listen()
            conn, addr = s.accept()
            key = pickle.loads(conn.recv(4096))      
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((HOST, PORT))
            s.listen()
            conn, addr = s.accept()
            data = conn.recv(4096)   
            res = rsa.decrypt(data, key) 
            c = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            c.connect((REMOTE, PORT+1))
            c.sendall(res)
            c.close()

def main():
    global threshold 
    global shares
    iters = 1000
    ns = [3, 5, 7, 11, 15, 30, 50]
    test_unprotected(iters)
    test_aes(iters)
    test_rsa(100)
    for n in ns:
        ks = set([math.ceil(n/2), math.ceil(2*n/3), math.ceil(4*n/6), math.ceil(5*n/6), n])
        for k in ks:
            print(str(n) + " " + str(k))
            shares = n
            threshold = k
            test_secretsharing(iters)
            test_secretsharing_package(iters)
    
    



if __name__ == "__main__":
    main()