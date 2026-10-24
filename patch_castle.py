with open(r'c:\Users\Administrator\Desktop\Castle Tw Web\castle.umd-B6QTm2FJ.js', 'r', encoding='utf-8') as f:
    js = f.read()

# 1. Hook Ke cache
t_ke = 'function Ke(){Ke.i||={};'
assert t_ke in js
js = js.replace(t_ke, 'function Ke(){Ke.i||={};globalThis.__KE_CACHE=Ke.i;', 1)

# 2. Hook Pn
t_pn = 'function Pn(e){var t=[];t[kb]=359711713,'
assert t_pn in js
js = js.replace(t_pn, 'function Pn(e){globalThis.__PN=Pn;var t=[];t[kb]=359711713,', 1)

# 3. Hook captured dollar
t_oz = 'oZ(function(e){'
assert t_oz in js
js = js.replace(t_oz, 'globalThis.__CAPTURED_DOLLAR=$;oZ(function(e){', 1)

# 4. Hook uncompressed serialized bytes
t_s = 'return s}($))'
assert t_s in js
js = js.replace(t_s, 'globalThis.__SERIALIZED_BYTES=s;return s}($))', 1)

# 5. Hook t[4]
t_t4 = 't[4]=function(e,t){'
assert t_t4 in js
js = js.replace(t_t4, 't[4]=function __CIPHER_FUNC(e,t){globalThis.__CIPHER_FUNC=__CIPHER_FUNC;', 1)

# 6. Hook deflate bytes in .then
t_then = '[$y](function(e){'
assert t_then in js
js = js.replace(t_then, '[$y](function(e){globalThis.__DEFLATE_BYTES=e;', 1)

with open(r'c:\Users\Administrator\Desktop\Castle Tw Web\castle.modified.js', 'w', encoding='utf-8') as f:
    f.write(js)

print('Successfully restored clean castle.modified.js with original hooks!')
