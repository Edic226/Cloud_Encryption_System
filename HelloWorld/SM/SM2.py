import math
import random
import base64
from gmssl import sm2


# 密钥生成
# key generation

def SM2_Mulyipoint(k, P, a, p):  # 多倍点运算
    k_b = bin(k).replace('0b', '')  # 按2^i分层逐层运算
    i = len(k_b) - 1
    R = P
    if i > 0:
        k = k - 2 ** i
        while i > 0:
            R = SM2_Pluspoint(R, R, a, p)
            i -= 1
        if k > 0:
            R = SM2_Pluspoint(R, SM2_Mulyipoint(k, P, a, p), a, p)
    return R


def SM2_Pluspoint(P, Q, a, p):  # 双倍点运算
    if (math.isinf(P[0]) or math.isinf(P[1])) and (~math.isinf(Q[0]) and ~math.isinf(Q[1])):  # OP = P
        R = Q
    elif (~math.isinf(P[0]) and ~math.isinf(P[1])) and (math.isinf(Q[0]) or math.isinf(Q[1])):  # PO = P
        R = P
    elif (math.isinf(P[0]) or math.isinf(P[1])) and (math.isinf(Q[0]) or math.isinf(Q[1])):  # OO = O
        R = [float('inf'), float('inf')]
    else:
        if P != Q:
            l = SM2__Mod_Decimal(Q[1] - P[1], Q[0] - P[0], p)
        else:
            l = SM2__Mod_Decimal(3 * P[0] ** 2 + a, 2 * P[1], p)
        x = SM2_Mod(l ** 2 - P[0] - Q[0], p)
        y = SM2_Mod(l * (P[0] - x) - P[1], p)
        R = [x, y]
    return R


def SM2_Mod(a, b):  # 摸运算
    if math.isinf(a):
        return float('inf')
    else:
        return a % b


def SM2__Mod_Decimal(n, d, b):  # 小数的模运算
    if d == 0:
        x = float('inf')
    elif n == 0:
        x = 0
    else:
        a = bin(b - 2).replace('0b', '')
        y = 1
        i = 0
        while i < len(a):  # n/d = x mod b => x = n*d^(b-2) mod b
            y = (y ** 2) % b  # 快速指数运算
            if a[i] == '1':
                y = (y * d) % b
            i += 1
        x = (y * n) % b
    return x


def key_gen(a, p, n, G):  # SM2密钥对的生成

    sk = random.randint(1, n - 2)
    pk = SM2_Mulyipoint(sk, G, a, p)
    return sk, pk


def write_key():
    p = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF
    a = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC
    b = 0x28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93
    n = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123
    Gx = 0x32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7
    Gy = 0xBC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0
    G = [Gx, Gy]
    [sk, pk] = key_gen(a, p, n, G)
    sk = hex(sk)[2:]
    pk = hex(pk[0])[2:] + hex(pk[1])[2:]
    return sk, pk


def sm2_getkey():
    sk, pk = write_key()
    return sk, pk


def sm2_encryt(data, pk):
    if type(data) == str:
        data = data.encode()
    sm2_crypt = sm2.CryptSM2(public_key=pk, private_key=0)
    en = base64.b64encode(sm2_crypt.encrypt(data)).decode()
    return en


def sm2_decryt(data, sk):
    if type(data) == str:
        data = base64.b64decode(data.encode())
    sm2_crypt = sm2.CryptSM2(public_key=0, private_key=sk)
    de = sm2_crypt.decrypt(data).decode()
    return de


def sm2_sign(data, id, sk, pk):
    if type(id) == str:
        id = id.encode()
    sm2_crypt = sm2.CryptSM2(public_key=pk, private_key=sk)
    sign = sm2_crypt.sign_with_sm3(id, data)
    return sign


def sm2_verify(sign, id, pk):
    if type(id) == str:
        id = id.encode()
    sm2_crypt = sm2.CryptSM2(public_key=pk, private_key=0)
    verify = sm2_crypt.verify_with_sm3(sign, id)
    return verify
