import numpy as np
from Cryptodome.Hash import SHA256
from Cryptodome.PublicKey import ECC
import struct
from util.crypto import ecchash
# from VerSum.util.crypto import ecchash
from ecdsa import ellipticcurve, SECP256k1

def ecc_point_to_ecdsa_point(ecc_point):
    curve = SECP256k1.curve
    return ellipticcurve.Point(
        curve,
        int(ecc_point.x),
        int(ecc_point.y)
    )

def ecc_key_to_ecdsa_privkey(ecc_key):
    assert ecc_key.has_private(), "Need a private key"
    d = int(ecc_key.d)
    return d


def ecdsa_point_to_ecc_point(ecdsa_point):
    return ECC.EccPoint(ecdsa_point.x(), ecdsa_point.y(), curve='P-256')  # or SECP256k1 if using custom curve

P256_P = ecchash.p

def ecc_point_neg(P):
    return ECC.EccPoint(int(P.x), (-int(P.y)) % P256_P, curve="P-256")

def vector_to_point(vec):
    hash_input = vec.tobytes()
    return ecchash.hash_to_curve(hash_input)

def point_to_vector(point):
    hash_output = SHA256.new(
        int(point.x).to_bytes(32,'big') +
        int(point.y).to_bytes(32,'big')
    ).digest()
    return np.frombuffer(hash_output, dtype=np.float64)

# secp256r1 / P-256
p = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
a = -3
b = int("5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B", 16)

def float_to_point(val):
    bval = struct.pack(">d", val)  # float64 -> bytes
    x = int.from_bytes(bval, 'big')

    while True:
        rhs = (pow(x, 3, p) + a * x + b) % p  # y^2 = x^3 + ax + b mod p
        try:
            y = pow(rhs, (p + 1) // 4, p)  # Tonelli–Shanks for sqrt mod p (p ≡ 3 mod 4)
            point = ECC.EccPoint(x, y, curve='P-256')
            return point
        except ValueError:
            x += 1  # try next x if not quadratic residue

def point_to_float(point):
    x_int = int(point.x)
    b = x_int.to_bytes(8, 'big')  # 8 bytes for float64
    return struct.unpack(">d", b)[0]

def vector_to_points(vec: np.ndarray):
    # point = float_to_point(vec[0])
    # return [point for v in vec]
    return [float_to_point(v) for v in vec]

def points_to_vector(points: list):
    floats = [point_to_float(P) for P in points]
    return np.array(floats, dtype=np.float64)