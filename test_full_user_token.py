import json
import base64
import zlib
from playwright.sync_api import sync_playwright
from test_deserializer import deserialize_castle_dollar

with open(r'c:\Users\Administrator\Desktop\Castle Tw Web\original_user_token.txt', 'r', encoding='utf-8') as f:
    full_token = f.read().strip()

print('Full user token length:', len(full_token))

# Parse header
parts = full_token.split('|')
assert parts[0] == 'uq1seNrd'
b64 = parts[1].strip()
b64 += '=' * (-len(b64) % 4)
raw = base64.b64decode(b64)
print('Decoded raw binary length:', len(raw))

keyLen = raw[0] | (raw[1] << 8)
keyBytes = raw[2:2+keyLen]
keyStr = keyBytes.decode('latin1')
print('keyLen:', keyLen)
print('keyStr (base64 encoded timestamp):', keyStr)

authHeader = raw[2+keyLen:2+keyLen+24]
w1 = int.from_bytes(authHeader[0:4], 'big')
w2 = int.from_bytes(authHeader[4:8], 'big')
print(f'Auth header words: w1={w1}, w2={w2}, expected ciphertext length={w1+w2}')

ciphertext = raw[2+keyLen+24:]
print(f'Actual ciphertext length: {len(ciphertext)}')
assert len(ciphertext) == w1 + w2

# Decrypt using Chrome and recovered key '1789745089173'
with sync_playwright() as p:
    b = p.chromium.connect_over_cdp('http://127.0.0.1:9222')
    page = b.contexts[0].new_page()
    page.goto('http://127.0.0.1:8089/index.html')
    page.wait_for_timeout(1000)
    
    raw_dec = page.evaluate('''async ({ tok, key }) => {
        await window.runAnalysis();
        const fn = globalThis.__CIPHER_FUNC;
        const b64 = tok.split('|')[1].trim();
        const rawStr = atob(b64);
        const raw = new Uint8Array(rawStr.length);
        for (let i = 0; i < rawStr.length; i++) raw[i] = rawStr.charCodeAt(i);
        
        const keyLen = raw[0] | (raw[1] << 8);
        const ciphertext = raw.slice(2 + keyLen + 24);
        
        const decWithHeader = fn(ciphertext, key);
        return Array.from(decWithHeader.slice(24));
    }''', {'tok': full_token, 'key': '1789745089173'})
    page.close()

dec_bytes = bytes(raw_dec)
print(f'Decrypted ciphertext bytes: {len(dec_bytes)}')
print(f'First 16 decrypted bytes hex: {dec_bytes[:16].hex()}')

# Decompress with raw deflate
try:
    decomp = zlib.decompress(dec_bytes, -15)
    print(f'*** FULL SUCCESSFUL DECOMPRESSION! ***')
    print(f'Decompressed serialized payload size: {len(decomp)} bytes')
    
    # Deserialize the 749 metrics!
    metrics = deserialize_castle_dollar(decomp)
    print(f'*** FULL SUCCESSFUL DESERIALIZATION! ***')
    print(f'Total metrics recovered: {len(metrics)}')
    
    with open(r'c:\Users\Administrator\Desktop\Castle Tw Web\user_token_metrics.json', 'w', encoding='utf-8') as mf:
        json.dump(metrics, mf, indent=2)
    print('Saved user_token_metrics.json successfully!')
except Exception as e:
    print('Decompression error:', e)
    # Check with decompressobj
    dobj = zlib.decompressobj(-15)
    out = dobj.decompress(dec_bytes)
    print(f'Partial decompressed bytes: {len(out)}')
    print('Error tail:', dobj.unconsumed_tail[:20].hex())
