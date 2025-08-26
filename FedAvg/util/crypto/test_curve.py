from Cryptodome.PublicKey import ECC
from util.crypto import ecchash
import struct
# 用 d=1 构造 ECC 密钥，相当于 pointQ = 1 * G = G
G_point = ECC.construct(curve='P-256', d=1).pointQ

print("Gx =", G_point.x)
print("Gy =", G_point.y)
print(ecchash.Gx)
print(ecchash.Gy)


# secp256r1 / P-256 的参数
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
print(float_to_point(32.104790147))
print(point_to_float(float_to_point(32.10479014701)))
