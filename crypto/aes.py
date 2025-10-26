from Crypto.Cipher import AES

ZEROIV = b"\x00" * 16


def removePadding(blocksize, s: bytes) -> bytes:
    'Remove rfc 1423 padding from string.'
    n = s[-1]  # last byte contains number of padding bytes
    if n > blocksize or n > len(s):
        raise Exception('invalid padding')
    return s[:-n]


def AESdecryptCBC(data: bytes, key: bytes, iv: bytes = ZEROIV, padding: bool = False) -> bytes:
    if len(data) % 16:
        print("AESdecryptCBC: data length not /16, truncating")
        data = data[0 : (len(data) // 16) * 16]
    data = AES.new(key, AES.MODE_CBC, iv).decrypt(data)
    if padding:
        return removePadding(16, data)
    return data


def AESencryptCBC(data: bytes, key: bytes, iv: bytes = ZEROIV, padding: bool = False) -> bytes:
    if len(data) % 16:
        print("AESdecryptCBC: data length not /16, truncating")
        data = data[0 : (len(data) // 16) * 16]
    data = AES.new(key, AES.MODE_CBC, iv).encrypt(data)
    return data
