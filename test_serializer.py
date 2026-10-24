import json
import struct
import base64
import math
import zlib

def encode_varint(val):
    res = bytearray()
    val = val & 0xFFFFFFFF
    while val >= 128:
        res.append((val & 127) | 128)
        val >>= 7
    res.append(val & 127)
    return res

def is_valid_base64(s):
    if not isinstance(s, str) or len(s) % 4 != 0 or not s:
        return False
    # Check base64 regex
    import re
    if not re.match(r'^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$', s):
        return False
    try:
        decoded = base64.b64decode(s)
        re_encoded = base64.b64encode(decoded).decode('ascii')
        return re_encoded == s
    except Exception:
        return False

def serialize_item(item, out):
    # null / undefined
    if item is None:
        out.append(0)
    elif isinstance(item, bool):
        # 5: False, 6: True
        out.append(6 if item else 5)
    elif isinstance(item, str):
        if is_valid_base64(item):
            # Type 2: Base64 binary
            raw = base64.b64decode(item)
            out.append(2)
            out.extend(encode_varint(len(raw)))
            out.extend(raw)
        elif all(ord(c) <= 255 for c in item):
            # Type 9: ASCII string
            out.append(9)
            out.extend(encode_varint(len(item)))
            out.extend(item.encode('latin1'))
        else:
            # Type 1: UTF-16LE string
            out.append(1)
            out.extend(encode_varint(len(item)))
            for c in item:
                code = ord(c)
                out.append(code & 0xFF)
                out.append((code >> 8) & 0xFF)
    elif isinstance(item, (int, float)):
        # Check if NaN or Infinity
        if math.isnan(item) or math.isinf(item):
            out.append(0)
            return
        
        # Check integer range: -2147483648 <= item <= 2147483647
        if isinstance(item, int) or (isinstance(item, float) and item.is_integer()):
            val = int(item)
            if -2147483648 <= val <= 2147483647:
                # Type 10: Zigzag varint
                out.append(10)
                # Zigzag: (val << 1) ^ (val >> 31)
                # In 32-bit signed:
                if val >= 0:
                    zz = val << 1
                else:
                    zz = ((~(-val)) << 1) ^ -1
                    zz = (~(-val - 1) << 1) # or in python:
                # In JS: (e << 1 ^ e >> 31) >>> 0
                val32 = val & 0xFFFFFFFF
                signed_val = val if val < 0x80000000 else val - 0x100000000
                zz = ((val32 << 1) ^ (signed_val >> 31)) & 0xFFFFFFFF
                out.extend(encode_varint(zz))
            elif 0 <= val <= 0xFFFFFFFF:
                # Type 3: uint32
                out.append(3)
                out.extend(struct.pack('<I', val))
            else:
                # Type 4: Float64 big-endian
                out.append(4)
                out.extend(struct.pack('>d', float(item)))
        else:
            # Type 4: Float64 big-endian
            out.append(4)
            out.extend(struct.pack('>d', float(item)))
    elif isinstance(item, list):
        # Type 7: Array
        out.append(7)
        out.extend(encode_varint(len(item)))
        for x in item:
            serialize_item(x, out)
    else:
        # Object / Dict: JSON stringified -> Type 8
        s = json.dumps(item, separators=(',', ':'))
        out.append(8)
        out.extend(encode_varint(len(s)))
        for c in s:
            code = ord(c)
            out.append(code & 0xFF)
            out.append((code >> 8) & 0xFF)

def serialize_castle_dollar(arr):
    out = bytearray()
    out.extend(encode_varint(len(arr)))
    for item in arr:
        serialize_item(item, out)
    return bytes(out)

with open(r'c:\Users\Administrator\Desktop\Castle Tw Web\castle_captured_dollar.json', 'r') as f:
    dollar = json.load(f)

ser = serialize_castle_dollar(dollar)
print('Serialized length:', len(ser))
print('First 32 bytes hex:', ser[:32].hex())
print('First 10 types:')
for i in range(min(10, len(dollar))):
    print(f'  [{i}] = {repr(dollar[i])[:40]}')

# Compress with raw deflate
compressor = zlib.compressobj(level=9, method=zlib.DEFLATED, wbits=-15)
comp = compressor.compress(ser) + compressor.flush()
print('Compressed length:', len(comp))
print('First 16 bytes compressed hex:', comp[:16].hex())
