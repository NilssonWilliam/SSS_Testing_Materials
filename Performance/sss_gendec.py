import random
import functools
import sys
import cProfile
from pstats import SortKey, Stats

"""
Code largely based on the example code found at https://en.wikipedia.org/wiki/Shamir%27s_secret_sharing
"""

PRIME = 4294967311

THRESHOLD = 10

SHARES = 10

RINT = functools.partial(random.SystemRandom().randint, 0)

def eval_poly(poly, x):
    acc = 0
    for c in reversed(poly):
        acc *= x
        acc += c
        acc %= PRIME
    return acc


def generate_secret_shares(data):
    if THRESHOLD > SHARES:
        raise ValueError("Threshold cannot be greater than number of shares")
    poly = [data] + [RINT(PRIME - 1) for i in range(THRESHOLD - 1)]
    points = [(i, eval_poly(poly, i)) for i in range(1, SHARES + 1)]
    return points

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

def main():
    global THRESHOLD 
    global SHARES
    if len(sys.argv) >= 2:
        THRESHOLD = int(sys.argv[1])
        SHARES = int(sys.argv[1])
    if len(sys.argv) >= 3:
        SHARES = int(sys.argv[2])
    with cProfile.Profile() as profile:
        data = RINT(10000)
        print(data)
        secrets = generate_secret_shares(data)
        print(secrets)
        recovered = recover_secret(secrets)
        print(recovered)
        (
            Stats(profile).strip_dirs().sort_stats(SortKey.CALLS).print_stats()
        )

if __name__ == "__main__":
    main()