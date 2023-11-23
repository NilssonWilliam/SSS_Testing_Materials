import random
import functools
import sys
import socket
import pickle
import time
import aes
import os

"""
Code largely based on the example code found at https://en.wikipedia.org/wiki/Shamir%27s_secret_sharing
"""

PRIME = 4294967311

threshold = 10

shares = 10

HOST = ""

REMOTE = "localhost"

PORT = 11111

RINT = functools.partial(random.SystemRandom().randint, 0)

def eval_poly(poly, x):
    acc = 0
    for c in reversed(poly):
        acc *= x
        acc += c
        acc %= PRIME
    return acc


def generate_secret_shares(data):
    if threshold > shares:
        raise ValueError("Threshold cannot be greater than number of shares")
    poly = [data] + [RINT(PRIME - 1) for i in range(threshold - 1)]
    points = [(i, eval_poly(poly, i)) for i in range(1, shares + 1)]
    return points

def test_secretsharing(iters):
    for i in range(iters):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((HOST, PORT+1))
            s.listen(1)        
            data = RINT(4294967296)
            start = time.time()
            secrets = generate_secret_shares(data)
            for v in secrets:
                c = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                c.connect((REMOTE, PORT))
                c.send(pickle.dumps(v))
                c.close()
            conn, addr = s.accept()
            ans = conn.recv(4096).decode("utf-8")
            end = time.time()
            if(int(ans) != data):
                print(f"Server answered with {ans} but secret was {data}")
            print(f"Time used was {end-start}")

def test_unprotected(iters):
    for i in range(iters):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((HOST, PORT+1))
            s.listen(1)        
            data = RINT(4294967296)
            start = time.time()
            c = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            c.connect((REMOTE, PORT))
            c.send(str(data).encode("utf-8"))
            c.close()
            conn, addr = s.accept()
            ans = conn.recv(4096).decode("utf-8")
            end = time.time()
            if(int(ans) != data):
                print(f"Server answered with {ans} but secret was {data}")
            print(f"Time used was {end-start}")

def test_aes(iters):
    for i in range(iters):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((HOST, PORT+1))
            s.listen(1)        
            data = RINT(4294967296)
            key = os.urandom(16)
            c = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            c.connect((REMOTE, PORT))
            c.send(key)
            c.close()
            start = time.time()
            encrypted = aes.encrypt(key, str(data))
            c = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            c.connect((REMOTE, PORT))
            c.send(encrypted)
            c.close()
            conn, addr = s.accept()
            ans = conn.recv(4096).decode("utf-8")
            end = time.time()
            if(int(ans) != data):
                print(f"Server answered with {ans} but secret was {data}")
            print(f"Time used was {end-start}")

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
    print("Starting AES tests")
    test_aes(iters)
    

if __name__ == "__main__":
    main()