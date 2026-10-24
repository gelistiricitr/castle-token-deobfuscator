import json
import struct
import base64
import math
import zlib

def decode_varint(data, offset):
    res = 0
    shift = 0
    while True:
        b = data[offset]
        offset += 1
        res |= (b & 127) << shift
        if (b & 128) == 0:
            break
        shift += 7
    return res, offset

def deserialize_item(data, offset):
    tag = data[offset]
    offset += 1
    
    if tag == 0:
        return None, offset
    elif tag == 1:
        # UTF-16LE string
        length, offset = decode_varint(data, offset)
        chars = []
        for _ in range(length):
            code = data[offset] | (data[offset + 1] << 8)
            offset += 2
            chars.append(chr(code))
        return "".join(chars), offset
    elif tag == 2:
        # Base64 raw binary
        length, offset = decode_varint(data, offset)
        raw = data[offset:offset + length]
        offset += length
        b64 = base64.b64encode(raw).decode('ascii')
        return b64, offset
    elif tag == 3:
        # uint32 LE
        val = struct.unpack('<I', data[offset:offset + 4])[0]
        offset += 4
        return val, offset
    elif tag == 4:
        # Float64 BE
        val = struct.unpack('>d', data[offset:offset + 8])[0]
        offset += 8
        return val, offset
    elif tag == 5:
        return False, offset
    elif tag == 6:
        return True, offset
    elif tag == 7:
        # Array
        length, offset = decode_varint(data, offset)
        arr = []
        for _ in range(length):
            item, offset = deserialize_item(data, offset)
            arr.append(item)
        return arr, offset
    elif tag == 8:
        # JSON string (UTF-16LE)
        length, offset = decode_varint(data, offset)
        chars = []
        for _ in range(length):
            code = data[offset] | (data[offset + 1] << 8)
            offset += 2
            chars.append(chr(code))
        json_str = "".join(chars)
        try:
            val = json.loads(json_str)
            return val, offset
        except Exception:
            return json_str, offset
    elif tag == 9:
        # ASCII string
        length, offset = decode_varint(data, offset)
        raw = data[offset:offset + length]
        offset += length
        return raw.decode('latin1'), offset
    elif tag == 10:
        # Zigzag varint
        zz, offset = decode_varint(data, offset)
        # Invert zigzag: (zz >>> 1) ^ -(zz & 1)
        if zz & 1:
            val = -(zz >> 1) - 1
        else:
            val = zz >> 1
        return val, offset
    else:
        raise ValueError(f"Unknown tag: {tag} at offset {offset-1}")

def deserialize_castle_dollar(data):
    total_len, offset = decode_varint(data, 0)
    arr = []
    for _ in range(total_len):
        item, offset = deserialize_item(data, offset)
        arr.append(item)
    return arr

with open(r'c:\Users\Administrator\Desktop\Castle Tw Web\castle_captured_dollar.json', 'r') as f:
    dollar = json.load(f)

from test_serializer import serialize_castle_dollar
ser = serialize_castle_dollar(dollar)

rec = deserialize_castle_dollar(ser)
print('Original dollar length:', len(dollar))
print('Recovered dollar length:', len(rec))
assert len(rec) == len(dollar)

matches = 0
for i in range(len(dollar)):
    orig_val = dollar[i]
    rec_val = rec[i]
    if orig_val == rec_val:
        matches += 1
    else:
        print(f'Mismatch at index {i}: orig={orig_val} ({type(orig_val)}) vs rec={rec_val} ({type(rec_val)})')

print(f'Total matches: {matches} / {len(dollar)} ({matches/len(dollar)*100:.1f}%)')
