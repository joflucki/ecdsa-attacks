import hashlib
from Crypto.Cipher import ChaCha20


# Hashes the message with SHA256 and casts the result into an integer.
def h(m):
    return int(hashlib.sha384(m).hexdigest(), 16)


def sign1(G, m, n, a):
    F = Integers(n)
    n2 = n // 2 ^ 32 # Hack to have small randomness
    k = F(ZZ.random_element(n2))
    (x1, y1) = (k * G).xy()
    r = F(x1)
    return (r, (F(h(m)) + a * r) / F(k))


def sign2(G, m, n, a):
    F = Integers(n)
    key = hashlib.sha256(m).digest()
    nonce = b"\x00" * 24
    cipher = ChaCha20.new(key=key, nonce=nonce)
    size_n = ceil(RR(log(n, 2)) / 8)
    k = int.from_bytes(cipher.encrypt(b"\x00" * size_n))
    (x1, y1) = (k * G).xy()
    r = F(x1)
    return (r, (F(h(m)) + a * r) / F(k))


def sign3(G, m, n, a):
    F = Integers(n)
    key = hashlib.sha256(str(a).encode()).digest()
    nonce = hashlib.sha256(str(a).encode()).digest()[:24]
    cipher = ChaCha20.new(key=key, nonce=nonce)
    size_n = ceil(RR(log(n, 2)) / 8)
    k = int.from_bytes(cipher.encrypt(b"\x00" * size_n))
    (x1, y1) = (k * G).xy()
    r = F(x1)
    return (r, (F(h(m)) + a * r) / F(k))


def sign4(G, m, n, a):
    F = Integers(n)
    k = int(hashlib.sha256(str(a).encode() + str(m).encode()).hexdigest(), 16)
    (x1, y1) = (k * G).xy()
    r = F(x1)
    return (r, (F(h(m)) + a * r) / F(k))


def verif(G, A, m, sig, F):
    u1 = h(m) / F(sig[1])
    u2 = F(sig[0]) / F(sig[1])
    return F((u1 * G + u2 * A)[0]) == sig[0]


# p384 params
def params():
    p = int(
        "0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff",
        16,
    )
    n = int(
        "0xffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973",
        16,
    )
    a = int(
        "0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000fffffffc",
        16,
    )
    b = int(
        "0xb3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef",
        16,
    )
    E = EllipticCurve(GF(p), [a, b])
    Gx, Gy = int(
        "0xaa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7",
        16,
    ), int(
        "0x3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f",
        16,
    )
    G = E(Gx, Gy)
    return (p, E, G, n)


def keyGen(G, n):
    x = Integers(n).random_element().lift()
    A = G * x
    return (x, A)