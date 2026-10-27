# aes_manual.py
SBOX = [
0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
]
INV_SBOX = [0] * 256
for i in range(256):
    INV_SBOX[SBOX[i]] = i

RCON = [0x00,0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36]

def xtime(x):
    x <<= 1
    if x & 0x100:
        x ^= 0x11b
    return x & 0xff

def mul(a, b):
    result = 0
    while b:
        if b & 1:
            result ^= a
        a = xtime(a)
        b >>= 1
    return result

def expand_key(key):
    if len(key) != 16:
        raise ValueError("Key AES harus 16 byte (AES-128).")
    w = list(key)
    for i in range(16, 176, 4):
        t = w[i-4:i]
        if i % 16 == 0:
            t = t[1:] + t[:1]
            t = [SBOX[x] for x in t]
            t[0] ^= RCON[i // 16]
        for j in range(4):
            w.append(w[i-16+j] ^ t[j])
    return w

def add_round_key(s, w, rnd):
    for i in range(16):
        s[i] ^= w[rnd*16+i]

def sub_bytes(s):
    for i in range(16):
        s[i] = SBOX[s[i]]

def inv_sub_bytes(s):
    for i in range(16):
        s[i] = INV_SBOX[s[i]]

def shift_rows(s):
    old = s[:]
    for r in range(4):
        for c in range(4):
            s[r+4*c] = old[r+4*((c+r) % 4)]

def inv_shift_rows(s):
    old = s[:]
    for r in range(4):
        for c in range(4):
            s[r+4*c] = old[r+4*((c-r) % 4)]

def mix_columns(s):
    for c in range(4):
        i = 4*c
        a,b,d,e = s[i:i+4]
        s[i]   = mul(a,2) ^ mul(b,3) ^ d ^ e
        s[i+1] = a ^ mul(b,2) ^ mul(d,3) ^ e
        s[i+2] = a ^ b ^ mul(d,2) ^ mul(e,3)
        s[i+3] = mul(a,3) ^ b ^ d ^ mul(e,2)

def inv_mix_columns(s):
    for c in range(4):
        i = 4*c
        a,b,d,e = s[i:i+4]
        s[i]   = mul(a,14)^mul(b,11)^mul(d,13)^mul(e,9)
        s[i+1] = mul(a,9)^mul(b,14)^mul(d,11)^mul(e,13)
        s[i+2] = mul(a,13)^mul(b,9)^mul(d,14)^mul(e,11)
        s[i+3] = mul(a,11)^mul(b,13)^mul(d,9)^mul(e,14)

def encrypt_block(block, key):
    if len(block) != 16:
        raise ValueError("Blok harus 16 byte.")
    w = expand_key(key)
    s = list(block)
    add_round_key(s, w, 0)
    for rnd in range(1, 10):
        sub_bytes(s)
        shift_rows(s)
        mix_columns(s)
        add_round_key(s, w, rnd)
    sub_bytes(s)
    shift_rows(s)
    add_round_key(s, w, 10)
    return bytes(s)

def decrypt_block(block, key):
    w = expand_key(key)
    s = list(block)
    add_round_key(s, w, 10)
    for rnd in range(9, 0, -1):
        inv_shift_rows(s)
        inv_sub_bytes(s)
        add_round_key(s, w, rnd)
        inv_mix_columns(s)
    inv_shift_rows(s)
    inv_sub_bytes(s)
    add_round_key(s, w, 0)
    return bytes(s)

def encrypt_cbc(key, plaintext):
    import secrets
    iv = secrets.token_bytes(16)
    pad = 16 - (len(plaintext) % 16)
    data = plaintext + bytes([pad] * pad)
    out = b""
    prev = iv
    for i in range(0, len(data), 16):
        block = bytes(a ^ b for a,b in zip(data[i:i+16], prev))
        prev = encrypt_block(block, key)
        out += prev
    return iv + out

def decrypt_cbc(key, ciphertext):
    if len(ciphertext) < 32 or len(ciphertext) % 16 != 0:
        raise ValueError("Ciphertext CBC tidak valid.")
    iv = ciphertext[:16]
    data = ciphertext[16:]
    out = b""
    prev = iv
    for i in range(0, len(data), 16):
        block = data[i:i+16]
        dec = decrypt_block(block, key)
        out += bytes(a ^ b for a,b in zip(dec, prev))
        prev = block
    pad = out[-1]
    if pad < 1 or pad > 16 or out[-pad:] != bytes([pad]*pad):
        raise ValueError("Padding tidak valid atau key salah.")
    return out[:-pad]

def encrypt_text_hex(key, text):
    raw = text.encode("ascii")
    return encrypt_cbc(key, raw).hex()

def decrypt_text_hex(key, cipher_hex):
    raw = bytes.fromhex(cipher_hex)
    return decrypt_cbc(key, raw).decode("ascii")

def send_json(sock, obj):
    import json, struct
    data = json.dumps(obj).encode("ascii")
    sock.sendall(struct.pack("!I", len(data)) + data)

def recv_exact(sock, n):
    data = b""
    while len(data) < n:
        part = sock.recv(n-len(data))
        if not part:
            raise ConnectionError("Koneksi terputus.")
        data += part
    return data

def recv_json(sock):
    import json, struct
    size = struct.unpack("!I", recv_exact(sock, 4))[0]
    return json.loads(recv_exact(sock, size).decode("ascii"))

if __name__ == "__main__":
    key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    plain = bytes.fromhex("00112233445566778899aabbccddeeff")
    expected = "69c4e0d86a7b0430d8cdb78070b4c55a"
    result = encrypt_block(plain, key).hex()
    print("Hasil AES :", result)
    print("Sesuai test vector:", result == expected)