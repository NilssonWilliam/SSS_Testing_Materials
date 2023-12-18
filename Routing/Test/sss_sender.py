import random
import functools
import sys
import socket
import pickle
import time
import aes
import os
import shamirs

"""
Code largely based on the example code found at https://en.wikipedia.org/wiki/Shamir%27s_secret_sharing
"""

PRIME = 4294967311

threshold = 10

shares = 10

HOST = ""

REMOTE = "192.168.2.1"

REMOTES = [REMOTE]

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
            s.listen()        
            data = RINT(4294967296)
            start = time.time()
            secrets = generate_secret_shares(data)
            for i, v in enumerate(secrets):
                c = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                c.connect((REMOTES[i % len(REMOTES)], PORT))
                c.send(pickle.dumps(v))
                c.close()
                time.sleep(0.1)
            conn, addr = s.accept()
            ans = conn.recv(4096).decode("utf-8")
            end = time.time()
            if(int(ans) != data):
                print(f"Server answered with {ans} but secret was {data}")

def main():
    global threshold 
    global shares
    iters = 1
    if len(sys.argv) >= 2:
        threshold = int(sys.argv[1])
        shares = int(sys.argv[1])
    print("Starting secret sharing tests")
    test_secretsharing(iters)
    

if __name__ == "__main__":
    main()