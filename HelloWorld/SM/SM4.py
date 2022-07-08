from gmssl.sm4 import CryptSM4, SM4_ENCRYPT, SM4_DECRYPT
from SM import SM3
import base64


# ecb
def sm4_encryt(key, data):
    if type(key) == str:
        key = SM3.sm3_hash(key).encode()
    else:
        key = SM3.sm3_hash(key.decode()).encode()
    if type(data) == str:
        data = data.encode()
    crypt_sm4 = CryptSM4()
    crypt_sm4.set_key(key, SM4_ENCRYPT)
    en = base64.b64encode(crypt_sm4.crypt_ecb(data)).decode()
    return en


def sm4_decryt(key, data):
    if type(key) == str:
        key = SM3.sm3_hash(key).encode()
    else:
        key = SM3.sm3_hash(key.decode()).encode()
    if type(data) == str:
        data = base64.b64decode(data)
    crypt_sm4 = CryptSM4()
    crypt_sm4.set_key(key, SM4_DECRYPT)
    de = crypt_sm4.crypt_ecb(data).decode()
    return de


if __name__ == '__main__':
    key = 'abcabcabcabcabc'
    msg = 'ABCDEFG'
    en = sm4_encryt(key, msg)
    print(en)
    de = sm4_decryt(key, en)
    print(de)
