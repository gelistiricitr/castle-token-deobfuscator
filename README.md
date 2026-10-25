# Castle Token Deobfuscator

**Twitter/X.com Castle Anti-Bot Token Decoder & Analyzer**

[Live Demo / Canli Demo](https://gelistiricitr.github.io/castle-token-deobfuscator/)

---

## TR - Turkce

### Nedir?

Castle, Twitter/X.com'un kullanicilarin tarayici ve cihaz bilgilerini toplayan anti-bot telemetri sistemidir. Bu arac, Castle tokenlarini cozumleyerek icerdikleri **765 metrigi** okunabilir formatta gosterir.

### Ozellikler

- **V1 ve V2 sifreleme destegi** - Her iki Castle protokol versiyonunu da cozer
- **765 metrik analizi** - Tum metrikler etiketli, kategorize edilmis ve formatlanmis
- **11 kategori** - Token/Protokol, Sistem, Tarayici, Ekran, Parmak Izi, Medya, Prob/Test, Ag, Oturum, Olay, Font Testi
- **Tamamen istemci tarafli** - Sunucu yok, veri disari gonderilmez, sadece tarayicinizda calisir
- **Font prob analizi** - 82 font yukluluk durumu (indeks 683-764)
- **IP adresi cozumleme** - Gercek istemci IP'si (indeks 473, lr-decode)
- **GitHub Pages** - Kurulum gerektirmez, dogrudan web uzerinden kullanin

### Kullanim

1. [Canli demo](https://gelistiricitr.github.io/castle-token-deobfuscator/) sayfasini acin
2. Castle tokenini metin alanina yapistirin (ornek: `cNz8rPYH|...`)
3. "Decode Et" butonuna basin
4. Sonuclar: Ozet bilgiler + 765 metrigin tamami tablo halinde

### Teknik Detaylar

**V1 Sifreleme:**
- FNV-1a offset: `0xBC0D78D5`
- Xorshift32: `0x155FACDB / 0x989BDC08 / 0xA4A5C55B`
- Anahtar kodlama: `Pn()` (ROL15 + ROL10 + ADD(6396))

**V2 Sifreleme:**
- FNV-1a offset: `0x751DAC79`
- Xorshift32: `0x7F039DDA / 0x973D8749 / 0x93CF09BD`
- Anahtar kodlama: `lr()` (ROL1 + ADD(0xC481) + ROL2 + base64)

**Binary Protokol:**
- LEB128 varint uzunluk kodlamasi
- 11 veri tipi: null, utf16, binary/base64, uint32LE, float64BE, false, true, array, json, ascii, zigzag

**Token Formati:**
```
[keyLen_lo, keyLen_hi, ...keyBytes, header(8), checksum(16), encrypted_data]
```

### Python CLI

```bash
python decode_token.py
```

Token'i stdin'den veya dosyadan okur, JSON olarak cikti verir.

### Dosya Yapisi

| Dosya | Aciklama |
|-------|----------|
| `index.html` | Web arayuzu (tek sayfa uygulama) |
| `castle_decoder.js` | JavaScript decoder (tarayici icin) |
| `decode_token.py` | Python decoder (CLI icin) |

---

## EN - English

### What is it?

Castle is Twitter/X.com's anti-bot telemetry system that collects browser and device fingerprint data. This tool decodes Castle tokens and displays their **765 metrics** in a human-readable format.

### Features

- **V1 and V2 cipher support** - Decodes both Castle protocol versions
- **765 metric analysis** - All metrics labeled, categorized, and formatted
- **11 categories** - Token/Protocol, System, Browser, Screen, Fingerprint, Media, Probe/Test, Network, Session, Event, Font Test
- **Fully client-side** - No server, no data sent anywhere, runs entirely in your browser
- **Font probe analysis** - 82 font installation states (indices 683-764)
- **IP address decoding** - Real client IP (index 473, lr-decode)
- **GitHub Pages** - No setup required, use directly on the web

### Usage

1. Open the [live demo](https://gelistiricitr.github.io/castle-token-deobfuscator/)
2. Paste a Castle token into the text area (e.g. `cNz8rPYH|...`)
3. Click "Decode Et"
4. Results: Summary info + full table of all 765 metrics

### Technical Details

**V1 Cipher:**
- FNV-1a offset: `0xBC0D78D5`
- Xorshift32: `0x155FACDB / 0x989BDC08 / 0xA4A5C55B`
- Key encoding: `Pn()` (ROL15 + ROL10 + ADD(6396))

**V2 Cipher:**
- FNV-1a offset: `0x751DAC79`
- Xorshift32: `0x7F039DDA / 0x973D8749 / 0x93CF09BD`
- Key encoding: `lr()` (ROL1 + ADD(0xC481) + ROL2 + base64)

**Binary Protocol:**
- LEB128 varint length encoding
- 11 data types: null, utf16, binary/base64, uint32LE, float64BE, false, true, array, json, ascii, zigzag

**Token Format:**
```
[keyLen_lo, keyLen_hi, ...keyBytes, header(8), checksum(16), encrypted_data]
```

### Python CLI

```bash
python decode_token.py
```

Reads token from stdin or file, outputs JSON.

### File Structure

| File | Description |
|------|-------------|
| `index.html` | Web UI (single page app) |
| `castle_decoder.js` | JavaScript decoder (for browser) |
| `decode_token.py` | Python decoder (for CLI) |

---

## License

MIT
