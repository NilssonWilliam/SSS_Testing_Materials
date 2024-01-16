import random
import functools
import socket
import pickle
import time
import aes
import os
import shamirs
import math
import rsa

"""
Secret sharing code largely based on the example code found at https://en.wikipedia.org/wiki/Shamir%27s_secret_sharing
"""

PRIME = 4294967311

threshold = 10

shares = 10

forwarders = 1

HOST = ""

REMOTE = "192.168.5.65"

REMOTES = ["192.168.2.244", "192.168.3.252", "192.168.4.221", "192.168.6.19", "192.168.7.35", "192.168.8.31", "192.168.9.98"]

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
    timeacc = 0
    for i in range(iters):
        time.sleep(0.2)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((HOST, PORT+1))
            s.listen()        
            data = RINT(4294967296)
            start = time.time()
            secrets = generate_secret_shares(data)
            for i, v in enumerate(secrets):
                c = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                c.connect((REMOTES[i % forwarders], PORT))
                c.send(pickle.dumps(v))
                c.close()
            conn, addr = s.accept()
            ans = conn.recv(4096).decode("utf-8")
            end = time.time()
            if(int(ans) != data):
                print(f"Server answered with {ans} but secret was {data}")
            timeacc += end-start
    timeacc = timeacc/iters
    print("In SSS self implemented tests, average was " + str(math.ceil(timeacc*1000)) + "ms for n=" + str(shares) + " and m=" + str(forwarders))


def test_secretsharing_package(iters):
    timeacc = 0
    for i in range(iters):
        time.sleep(0.2)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((HOST, PORT+1))
            s.listen()        
            data = RINT(4294967296)
            start = time.time()
            secrets = shamirs.shares(data, quantity=shares, threshold=threshold)
            for i, v in enumerate(secrets):
                c = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                c.connect((REMOTES[i % forwarders], PORT))
                c.send(pickle.dumps(v))
                c.close()
            conn, addr = s.accept()
            ans = conn.recv(4096).decode("utf-8")
            end = time.time()
            if(int(ans) != data):
                print(f"Server answered with {ans} but secret was {data}")
            timeacc += end-start
    timeacc = timeacc/iters
    print("In SSS package tests, average was " + str(math.ceil(timeacc*1000)) + "ms for n=" + str(shares) + " and m=" + str(forwarders))

def test_unprotected(iters):
    timeacc = 0
    for i in range(iters):
        time.sleep(0.2)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((HOST, PORT+1))
            s.listen()        
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
            timeacc += end-start
    timeacc = timeacc/iters
    print("In unprotected tests, average was " + str(math.ceil(timeacc*1000)) + "ms")

def test_aes(iters):
    timeacc = 0
    for i in range(iters):
        time.sleep(0.2)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((HOST, PORT+1))
            s.listen()        
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
            timeacc += end-start
    timeacc = timeacc/iters
    print("In AES tests, average was " + str(math.ceil(timeacc*1000)) + "ms")

def test_rsa(iters):
    timeacc = 0
    for i in range(iters):
        time.sleep(0.2)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((HOST, PORT+1))
            s.listen()        
            data = str(RINT(PRIME))
            (pub, priv) = rsa.newkeys(3072)
            c = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            c.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            c.connect((REMOTE, PORT))
            c.send(pickle.dumps(priv))
            c.close()
            time.sleep(0.1)
            start = time.time()
            encrypted = rsa.encrypt(data.encode("utf-8"), pub)
            c = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            c.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            c.connect((REMOTE, PORT))
            c.send(encrypted)
            c.close()
            conn, addr = s.accept()
            ans = conn.recv(4096).decode("utf-8")
            end = time.time()
            if(ans != data):
                print(f"Server answered with {ans} but secret was {data}")
            timeacc += end-start
    timeacc = timeacc/iters
    print("In RSA tests, average was " + str(timeacc*1000) + "ms")

def main():
    global threshold 
    global shares
    global forwarders
    iters = 1000
    ns = [7, 15, 30]
    ms = [1, 2, 3, 5, 7]
    test_unprotected(iters)
    test_aes(iters)
    test_rsa(100)
    for n in ns:
        for m in ms:
            shares = n
            threshold = n
            if forwarders <= len(REMOTES):
                forwarders = m
                test_secretsharing(iters)
                test_secretsharing_package(iters)
            else:
                raise AssertionError("Not enough remotes listed")
            
        
    

if __name__ == "__main__":
    main()