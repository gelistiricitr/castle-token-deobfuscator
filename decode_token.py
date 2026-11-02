#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
=============================================================================
             Castle Anti-Bot Token Deobfuscator & Pure Python Decoder
=============================================================================
 %100 Saf Python (Pure Python) ile çalışan Castle Token Çözücü.
 Harici hiçbir tarayıcı (Chrome, Playwright, Puppeteer), Java veya Node.js
 bağımlılığı YOKTUR. Sadece Python standart kütüphanesi kullanır.

 Geliştirilen Algoritmalar:
  1. Pn(timestamp) Anahtar Ters Çevirici: 16-bit dairesel bit kaydırma ve
     modüler aritmetik tersine mühendisliği (Pure Math Inverse).
  2. Castle Akış Şifreleyicisi (Stream Cipher): 32-bit FNV-1a anahtar türetimi
     ve Xorshift32 PRNG tabanlı simetrik XOR şifre çözücü.
  3. Ham Zlib / Deflate Dekompresyonu.
  4. Castle İkili Protokol Deserializer: LEB128 ve 11 farklı veri tipini
     (UTF-16, Base64, uint32 LE, float64, boolean, array, json, zigzag varint)
     otomatik ayrıştırıcı.
  5. Semantik Deobfuscation & Etiketleme: Kontrol baytlarını temizleme,
     metrik indekslerini anlamlı insan-okunabilir alanlara dönüştürme.
=============================================================================
"""

import sys
import os
import re
import json
import zlib
import base64
import struct
import datetime
from typing import Any, Dict, List, Tuple, Optional, Union

# Windows terminalinde Türkçe karakterlerin bozulmasını engelle
if hasattr(sys.stdout, 'reconfigure'):
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except Exception:
        pass

# ---------------------------------------------------------------------------
# 1. Pn TIMESTAMP ŞİFRESİ TERSİNE ÇEVİRİCİ (PURE MATH INVERSE)
# ---------------------------------------------------------------------------
def invert_pn_word(val: int) -> str:
    """
    Castle'ın Pn fonksiyonundaki 16-bit şifrelenmiş iki baytlık kelimeyi
    orijinal ASCII karakterine geri dönüştürür.
    
    Forward işlem (Castle JS):
      e = (code << 15 | code >> 1) & 0xFFFF
      e = (e << 10 | e >> 6) & 0xFFFF
      e = (e + 6396) & 0xFFFF
    
    Inverse işlem (Tersine Mühendislik):
      e = (val - 6396) & 0xFFFF
      e = (e >> 10 | e << 6) & 0xFFFF
      e = (e >> 15 | e << 1) & 0xFFFF
    """
    e = (val - 6396) & 0xFFFF
    e = ((e >> 10) | ((e << 6) & 0xFFFF)) & 0xFFFF
    e = ((e >> 15) | ((e << 1) & 0xFFFF)) & 0xFFFF
    return chr(e)

def _recover_v1(raw: bytes) -> str:
    chars = []
    for i in range(0, len(raw), 2):
        if i + 1 < len(raw):
            word = (raw[i] << 8) | raw[i + 1]
            chars.append(invert_pn_word(word))
    return "".join(chars)

def _recover_v2(raw: bytes) -> str:
    """lr() inverse: ROR2 -> SUB(0xC481) -> ROR1"""
    chars = []
    for i in range(0, len(raw), 2):
        if i + 1 < len(raw):
            val = (raw[i] << 8) | raw[i + 1]
            val = ((val >> 2) | (val << 14)) & 0xFFFF
            val = (val - 0xC481) & 0xFFFF
            val = ((val >> 1) | (val << 15)) & 0xFFFF
            chars.append(chr(val))
    return "".join(chars)

def _recover_v3(raw: bytes) -> str:
    """Gn() inverse (V3 WcmFKZlD): ROR4 -> XOR(0x72DC) -> ADD(0xB1E6)"""
    chars = []
    for i in range(0, len(raw), 2):
        if i + 1 < len(raw):
            val = (raw[i] << 8) | raw[i + 1]
            val = ((val >> 4) | (val << 12)) & 0xFFFF
            val = (val ^ 0x72DC) & 0xFFFF
            val = (val + 0xB1E6) & 0xFFFF
            chars.append(chr(val))
    return "".join(chars)

def recover_timestamp_key(key_b64: str) -> str:
    padded = key_b64 + "=" * (-len(key_b64) % 4)
    raw = base64.b64decode(padded)
    for fn in (_recover_v3, _recover_v2, _recover_v1):
        res = fn(raw)
        if res.isdigit() and len(res) == 13:
            return res
    return _recover_v1(raw)

# ---------------------------------------------------------------------------
# 2. SAF PYTHON AKIŞ ŞİFRESİ ÇÖZÜCÜ (PURE STREAM CIPHER DECRYPTOR)
# ---------------------------------------------------------------------------
def decrypt_castle_stream(ciphertext: bytes, key_str: str) -> bytes:
    """
    Castle istemcisinin JavaScript içindeki t[4] akış şifreleyicisinin
    birebir saf Python (pure Python) implementasyonu.
    
    Adımlar:
      1. Zaman damgası dizesi üzerinden 32-bit FNV-1a hash hesaplanır.
      2. PRNG durumu FNV-1a çıktısı ve sabit maskelerle başlatılır.
      3. Her 4 baytta bir durum Xorshift32 ve sabit eklemelerle güncellenir.
      4. Çıktı: plaintext[i] = ciphertext[i] ^ keystream_byte[i].
    """
    # 1. 32-bit FNV-1a Hash
    h = 0xBC0D78D5
    FNV_PRIME = 0x01000193  # 16777619

    for ch in key_str:
        h = ((h ^ ord(ch)) * FNV_PRIME) & 0xFFFFFFFF

    if h == 0:
        h = 0x9E3779B9  # Knuth altın oran sabiti

    # 2. Başlangıç PRNG Durumu (n[20])
    state = (h ^ 0x989BDC08) & 0xFFFFFFFF

    CONST1 = 0x155FACDB
    CONST2 = 0x989BDC08
    CONST3 = 0xA4A5C55B

    out = bytearray(len(ciphertext))

    for i in range(len(ciphertext)):
        if (i & 3) == 0:
            # 4 baytta bir PRNG durum güncellemesi (Xorshift32 permütasyonu)
            state = (state + i + CONST1) & 0xFFFFFFFF
            state = (state + CONST2) & 0xFFFFFFFF
            state = (state ^ ((state << 13) & 0xFFFFFFFF)) & 0xFFFFFFFF
            state = (state ^ (state >> 17)) & 0xFFFFFFFF
            state = (state ^ ((state << 5) & 0xFFFFFFFF)) & 0xFFFFFFFF
            state = (state + CONST3) & 0xFFFFFFFF

        keystream_byte = (state >> ((i & 3) * 8)) & 0xFF
        out[i] = ciphertext[i] ^ keystream_byte

    return bytes(out)

def decrypt_castle_stream_v2(ciphertext: bytes, key_str: str) -> bytes:
    """
    V2 Castle akis sifresi: FNV-1a (offset 0x751DAC79) + Xorshift32.
    castle.umd-dATz00yt.js tersine muhendisligi ile elde edilmistir.
    """
    h = 0x751DAC79
    FNV_PRIME = 0x01000193
    for ch in key_str:
        h = ((h ^ ord(ch)) * FNV_PRIME) & 0xFFFFFFFF
    if h == 0:
        h = 0x9E3779B9

    state = (h ^ 0x973D8749) & 0xFFFFFFFF
    out = bytearray(len(ciphertext))

    for i in range(len(ciphertext)):
        if (i & 3) == 0:
            state = (state + i + 0x7F039DDA) & 0xFFFFFFFF
            state = (state + 0x973D8749) & 0xFFFFFFFF
            state = (state ^ ((state << 13) & 0xFFFFFFFF)) & 0xFFFFFFFF
            state = (state ^ (state >> 17)) & 0xFFFFFFFF
            state = (state ^ ((state << 5) & 0xFFFFFFFF)) & 0xFFFFFFFF
            state = (state + 0x93CF09BD) & 0xFFFFFFFF

        out[i] = ciphertext[i] ^ ((state >> ((i & 3) * 8)) & 0xFF)

    return bytes(out)

def decrypt_castle_stream_v3(ciphertext: bytes, key_str: str) -> bytes:
    """
    V3 Castle akis sifresi (WcmFKZlD): FNV-1a (offset 0x4A391620) + Xorshift32.
    castle.umd-CGiQ_kr0.js tersine muhendisligi ile elde edilmistir.
    """
    h = 0x4A391620
    FNV_PRIME = 0x01000193
    for ch in key_str:
        h = ((h ^ ord(ch)) * FNV_PRIME) & 0xFFFFFFFF
    if h == 0:
        h = 0x9E3779B9

    state = (h ^ 0x6F0FB60C) & 0xFFFFFFFF
    out = bytearray(len(ciphertext))

    for i in range(len(ciphertext)):
        if (i & 3) == 0:
            state = (state + i + 0x09007E08) & 0xFFFFFFFF
            state = (state + 0x6F0FB60C) & 0xFFFFFFFF
            state = (state ^ ((state << 13) & 0xFFFFFFFF)) & 0xFFFFFFFF
            state = (state ^ (state >> 17)) & 0xFFFFFFFF
            state = (state ^ ((state << 5) & 0xFFFFFFFF)) & 0xFFFFFFFF
            state = (state + 0x391BF9C5) & 0xFFFFFFFF

        out[i] = ciphertext[i] ^ ((state >> ((i & 3) * 8)) & 0xFF)

    return bytes(out)

# ---------------------------------------------------------------------------
# 3. İKİLİ PROTOKOL AYRIŞTIRICI (BINARY PROTOCOL DESERIALIZER)
# ---------------------------------------------------------------------------
def decode_varint(data: bytes, offset: int) -> Tuple[int, int]:
    """LEB128 işaretsiz tamsayı okur."""
    res = 0
    shift = 0
    while True:
        if offset >= len(data):
            raise IndexError("Varint okunurken beklenmeyen veri sonu (EOF)")
        b = data[offset]
        offset += 1
        res |= (b & 127) << shift
        if (b & 128) == 0:
            break
        shift += 7
    return res, offset

def deserialize_item(data: bytes, offset: int) -> Tuple[Any, int]:
    """Castle ikili akışından tip etiketine göre tek bir elemanı ayrıştırır."""
    if offset >= len(data):
        raise IndexError("Eleman etiketi okunurken beklenmeyen veri sonu (EOF)")

    tag = data[offset]
    offset += 1

    if tag == 0:
        return None, offset
    elif tag == 1:
        # UTF-16LE Dize
        length, offset = decode_varint(data, offset)
        chars = []
        for _ in range(length):
            code = data[offset] | (data[offset + 1] << 8)
            offset += 2
            chars.append(chr(code))
        return "".join(chars), offset
    elif tag == 2:
        # Ham İkili Veri (Base64)
        length, offset = decode_varint(data, offset)
        raw = data[offset:offset + length]
        offset += length
        return base64.b64encode(raw).decode('ascii'), offset
    elif tag == 3:
        # uint32 Little Endian
        val = struct.unpack('<I', data[offset:offset + 4])[0]
        offset += 4
        return val, offset
    elif tag == 4:
        # float64 Big Endian
        val = struct.unpack('>d', data[offset:offset + 8])[0]
        offset += 8
        return val, offset
    elif tag == 5:
        return False, offset
    elif tag == 6:
        return True, offset
    elif tag == 7:
        # Dizi (Array)
        length, offset = decode_varint(data, offset)
        arr = []
        for _ in range(length):
            item, offset = deserialize_item(data, offset)
            arr.append(item)
        return arr, offset
    elif tag == 8:
        # JSON Dizisi (UTF-16LE)
        length, offset = decode_varint(data, offset)
        chars = []
        for _ in range(length):
            code = data[offset] | (data[offset + 1] << 8)
            offset += 2
            chars.append(chr(code))
        json_str = "".join(chars)
        try:
            return json.loads(json_str), offset
        except Exception:
            return json_str, offset
    elif tag == 9:
        # ASCII Dize
        length, offset = decode_varint(data, offset)
        raw = data[offset:offset + length]
        offset += length
        return raw.decode('latin1'), offset
    elif tag == 10:
        # Zigzag Değişken Tamsayı (Zigzag varint)
        zz, offset = decode_varint(data, offset)
        val = -(zz >> 1) - 1 if (zz & 1) else (zz >> 1)
        return val, offset
    else:
        raise ValueError(f"Bilinmeyen Castle protokol etiketi: {tag} (Ofset: {offset - 1})")

def deserialize_castle_payload(data: bytes) -> List[Any]:
    """Sıkıştırması açılmış ikili veriden 749 metriğin tamamını çıkartır."""
    total_len, offset = decode_varint(data, 0)
    arr = []
    for _ in range(total_len):
        item, offset = deserialize_item(data, offset)
        arr.append(item)
    return arr

# ---------------------------------------------------------------------------
# 4. METİN TEMİZLEME & DEOBFUSCATION (HUMAN-READABLE SANITIZATION)
# ---------------------------------------------------------------------------
def clean_string_value(s: Any) -> Any:
    """
    String içindeki görünmez ikili kontrol karakterlerini (\x00-\x1f),
    başlık baytlarını ve escape dizilerini insan tarafından okunabilir
    temiz metne dönüştürür.
    """
    if not isinstance(s, str):
        return s

    if not s:
        return s

    # İşletim sistemi dizesi: '\x03\x07\x03\x00Windowsx86' -> 'Windows (x86_64)'
    if 'Windowsx86' in s:
        return 'Windows (x86_64)'
    if any(ord(ch) < 32 for ch in s) and ('Windows' in s or 'Mac' in s or 'Linux' in s or 'Android' in s or 'iOS' in s):
        m = re.search(r'(Windows|Macintosh|Linux|Android|iOS)[a-zA-Z0-9_\-\s]*', s)
        if m:
            return m.group(0)

    # Donanım parmak izi / GUID:
    if '][' in s or 'iv1ty' in s or 'w3c' in s:
        m = re.search(r'[a-f0-9]{8,}.*', s)
        if m:
            return m.group(0)

    # Başındaki ve sonundaki kontrol karakterlerini temizle
    cleaned = "".join(ch for ch in s if 32 <= ord(ch) <= 126 or ord(ch) >= 160).strip()
    return cleaned if cleaned else s

# Bilinen önemli metrik indeksleri ve Türkçe / İngilizce açıklamaları
METRIC_LABELS = {
    0: ("feature_flags", "Özellik Bayrağı / Mod"),
    1: ("screen_width", "Ekran Genişliği (px)"),
    2: ("screen_height", "Ekran Yüksekliği (px)"),
    6: ("canvas_2d_hash", "Canvas 2D Grafik Parmak İzi"),
    8: ("audio_oscillator_hash", "AudioContext Osilatör İmzası"),
    9: ("color_depth", "Renk Derinliği (bit)"),
    11: ("webgl_vendor_code", "WebGL Donanım Sağlayıcı Kodu"),
    16: ("device_pixel_ratio", "Cihaz Piksel Oranı (DPR)"),
    22: ("webdriver_active", "WebDriver Aktif mi (Bot İmzası)"),
    40: ("screen_color_gamut", "Ekran Renk Gamı İmzası"),
    44: ("automation_detected", "Otomasyon / Bot Tespiti"),
    59: ("operating_system", "İşletim Sistemi (OS)"),
    61: ("interaction_timing", "Kullanıcı Etkileşim Zamanlamaları"),
    86: ("webgl_renderer_hash", "WebGL Grafik İşleyici İmzası"),
    143: ("headless_browser", "Headless (Görünmez) Tarayıcı Tespiti"),
    151: ("devtools_opened", "Geliştirici Araçları (DevTools) Açık mı"),
    163: ("device_hardware_guid", "Cihaz / Donanım Benzersiz Kimliği (GUID)"),
    383: ("cdp_protocol_active", "Chrome DevTools Protokolü (CDP) Tespiti"),
    406: ("client_ip_address", "İstemci Genel IP Adresi (Public IP)"),
    551: ("browser_build_version", "Tarayıcı Derleme Sürümü (Build Version)")
}

FONT_PROBE_START = 683
FONT_PROBE_END = 764
FONT_NOT_INSTALLED_HEX = {"c3c3c3c3", "f7444444"}

CATEGORY_TR = {
    "token": "Token/Protokol",
    "system": "Sistem",
    "browser": "Tarayici",
    "screen": "Ekran",
    "fingerprint": "Parmak Izi",
    "media": "Medya",
    "probe": "Prob/Test",
    "network": "Ag",
    "session": "Oturum",
    "event": "Olay",
    "font": "Font Testi",
}

METRIC_INFO_V2 = {
    0: ("config_flags", "Yapilandirma Bayragi", "token"),
    1: ("token_name", "Token Tanici", "token"),
    2: ("protocol_ver", "Protokol Parametresi", "token"),
    4: ("session_fp", "Oturum Parmak Izi", "fingerprint"),
    5: ("metric_mode", "Metrik Modu", "token"),
    6: ("canvas_2d_hash", "Canvas 2D Hash", "fingerprint"),
    7: ("system_hash", "Sistem Hash", "fingerprint"),
    8: ("os_name", "Isletim Sistemi", "system"),
    9: ("os_hash", "IS Ailesi Hash", "fingerprint"),
    10: ("os_ver_hash", "IS Surum Hash", "fingerprint"),
    11: ("arch_bits", "Mimari Bit Sayisi", "system"),
    12: ("hw_fp", "Donanim Parmak Izi", "fingerprint"),
    13: ("cpu_hash", "Islemci Hash", "fingerprint"),
    14: ("mem_hash", "Bellek Hash", "fingerprint"),
    15: ("depth_hash", "Renk Derinligi Hash", "fingerprint"),
    16: ("resolution_pair", "Cozunurluk Hash Cifti", "screen"),
    17: ("pixel_ratio", "Piksel Orani Hash", "screen"),
    18: ("tz_hash", "Saat Dilimi Hash", "fingerprint"),
    19: ("tz_offset_raw", "Zaman Dilimi Ofseti", "system"),
    20: ("screen_dim", "Ekran Boyutu", "screen"),
    22: ("webgl_hash_1", "WebGL Hash 1", "fingerprint"),
    23: ("webgl_hash_2", "WebGL Hash 2", "fingerprint"),
    24: ("media_cap_1", "Medya Oynatma Yetenegi 1", "media"),
    25: ("castle_pubkey", "Castle Acik Anahtar", "token"),
    26: ("render_engine", "Rendering Motoru", "browser"),
    27: ("engine_hash", "Motor Hash", "fingerprint"),
    28: ("engine_version", "Motor Surumu", "browser"),
    36: ("render_flag", "Rendering Bayragi", "browser"),
    41: ("screen_flag", "Ekran Bayragi", "screen"),
    43: ("timing_val", "Zamanlama Degeri", "event"),
    44: ("env_hash", "Ortam Hash", "fingerprint"),
    52: ("render_mode", "Render Modu", "browser"),
    53: ("screen_val", "Ekran Degeri", "screen"),
    60: ("gpu_renderer", "GPU Isleyici", "browser"),
    61: ("gpu_score", "GPU Skor Degeri", "browser"),
    63: ("user_agent", "User-Agent", "browser"),
    67: ("locale", "Dil / Yerel Ayar", "browser"),
    68: ("cookie_flag", "Cerez Bayragi", "browser"),
    72: ("storage_pair", "Depolama Hash Cifti", "fingerprint"),
    75: ("hw_concurrency", "Donanim Eslestirme", "system"),
    79: ("session_flag", "Oturum Bayragi", "session"),
    80: ("request_id", "Istek Kimligi", "session"),
    83: ("audio_val", "Ses Degeri", "media"),
    88: ("speech_code", "Konusma API Kodu", "media"),
    96: ("touch_points", "Dokunmatik Noktasi", "event"),
    97: ("touch_val", "Dokunmatik Degeri", "event"),
    98: ("event_data", "Olay Verisi", "event"),
    101: ("browser_name", "Tarayici Adi", "browser"),
    103: ("browser_vendor", "Tarayici Ureticisi", "browser"),
    106: ("vis_flag", "Gorunurluk Bayragi", "screen"),
    107: ("visibility", "Sayfa Gorunurlugu", "screen"),
    109: ("shader_hash_str", "WebGL Shader Hash", "fingerprint"),
    111: ("font_metric_hash", "Font Olcum Hash", "fingerprint"),
    116: ("css_selector_fp", "CSS Secici Parmak Izi", "fingerprint"),
    117: ("error_probe_type", "Hata Probu: Tip", "probe"),
    118: ("probe_na", "Prob Sonucu (N/A)", "probe"),
    127: ("perf_val", "Performans Degeri", "event"),
    135: ("canvas_fp", "Canvas Parmak Izi", "fingerprint"),
    137: ("media_cap_2", "Medya Oynatma Yetenegi 2", "media"),
    139: ("webgl_fp", "WebGL Parmak Izi", "fingerprint"),
    140: ("webgl_delta", "WebGL Delta Degeri", "fingerprint"),
    143: ("audio_fp", "Ses Parmak Izi", "fingerprint"),
    145: ("timer_val", "Zamanlayici Degeri", "event"),
    148: ("geo_code", "Cografi Kod", "system"),
    149: ("geo_hash", "Cografi Hash", "fingerprint"),
    152: ("intl_val", "Uluslararasi Deger", "system"),
    154: ("intl_id", "Uluslararasi Kimlik", "system"),
    159: ("date_val", "Tarih Degeri", "system"),
    161: ("language", "Dil Kodu", "system"),
    165: ("main_flag", "Ana Bayrak", "token"),
    166: ("date_probe", "Tarih Probu (TZ Testi)", "probe"),
    178: ("analytics_code", "Analitik Kodu", "token"),
    180: ("proxy_pair", "Proxy Hash Cifti", "fingerprint"),
    182: ("proxy_val", "Proxy Degeri", "fingerprint"),
    189: ("api_code", "API Kodu", "browser"),
    192: ("iterator_val", "Iterator Degeri", "fingerprint"),
    194: ("generator_pair", "Generator Hash Cifti", "fingerprint"),
    196: ("event_flag", "Olay Bayragi", "event"),
    203: ("module_val", "Modul Degeri", "fingerprint"),
    205: ("module_val_2", "Modul Degeri 2", "fingerprint"),
    207: ("probe_flag", "Prob Bayragi", "probe"),
    214: ("api_mode", "API Modu", "browser"),
    215: ("ua_brands", "UA Marka Bilgisi (JSON)", "browser"),
    217: ("ua_subcode", "UA Alt Kodu", "browser"),
    221: ("nav_code", "Navigator Kodu", "browser"),
    224: ("timezone", "Saat Dilimi", "system"),
    226: ("tz_val", "Saat Dilimi Degeri", "system"),
    230: ("short_code", "Kisa Kod", "token"),
    233: ("format_val", "Format Degeri", "fingerprint"),
    235: ("gpu_renderer_dup", "GPU Isleyici (Kopya)", "browser"),
    239: ("fp_hex_1", "Parmak Izi Hex 1", "fingerprint"),
    240: ("webgl_flag", "WebGL Bayragi", "fingerprint"),
    242: ("browser_ver_detail", "Tarayici Surumu (Detay)", "browser"),
    244: ("error_probe_prop", "Hata Probu: Property", "probe"),
    247: ("display_type", "Goruntu Tipi", "screen"),
    248: ("browser_version", "Tarayici Surumu", "browser"),
    252: ("screen_px", "Ekran Piksel Degeri", "screen"),
    253: ("network_flag", "Ag Bayragi", "network"),
    260: ("origin_url", "Kaynak URL", "network"),
    269: ("perf_timing", "Performans Zamanlamasi", "event"),
    272: ("perf_code", "Performans Kodu", "event"),
    280: ("active_flag", "Aktiflik Bayragi", "session"),
    284: ("engine_ver_dup", "Motor Surumu (Kopya)", "browser"),
    293: ("accept_langs", "Kabul Edilen Diller", "browser"),
    303: ("sw_code", "ServiceWorker Kodu", "browser"),
    308: ("page_title", "Sayfa Basligi", "network"),
    311: ("page_code", "Sayfa Kodu", "network"),
    316: ("adv_flag", "Gelismis Bayrak", "probe"),
    324: ("os_arch", "IS + Mimari Birlesik", "system"),
    325: ("timing_val_2", "Zamanlama Degeri 2", "event"),
    327: ("timing_val_3", "Zamanlama Degeri 3", "event"),
    332: ("gpu_vendor", "GPU Ureticisi", "browser"),
    334: ("color_depth", "Renk Derinligi", "screen"),
    341: ("last_event", "Son Olay Tipi", "event"),
    342: ("event_code", "Olay Kodu", "event"),
    343: ("event_timing", "Olay Zamanlamasi", "event"),
    352: ("screen_orient", "Ekran Yonu", "screen"),
    353: ("orient_delta", "Yon Deltasi", "screen"),
    359: ("protocol", "Protokol", "network"),
    363: ("perf_val_2", "Performans Degeri 2", "event"),
    365: ("encoded_val", "Kodlu Deger", "token"),
    366: ("platform", "Platform", "system"),
    367: ("platform_sub", "Platform Alt Kodu", "system"),
    368: ("architecture", "Mimari", "system"),
    373: ("crypto_val", "Kripto Degeri", "fingerprint"),
    374: ("hw_flag", "Donanim Bayragi", "system"),
    380: ("hw_val", "Donanim Degeri", "system"),
    383: ("cdp_flag", "CDP Protokol Bayragi", "probe"),
    391: ("selenium_code", "Selenium Kodu", "probe"),
    395: ("headless_code", "Headless Kodu", "probe"),
    396: ("headless_val", "Headless Degeri", "probe"),
    397: ("resolution_flag", "Cozunurluk Bayragi", "screen"),
    398: ("resolution_pair", "Cozunurluk Hash Cifti", "screen"),
    402: ("short_code_2", "Kisa Kod 2", "token"),
    403: ("net_timing", "Ag Zamanlamasi", "event"),
    406: ("ip_hash", "IP Bolgesi Hash", "fingerprint"),
    416: ("build_id", "Yapi Kimligi (Build ID)", "browser"),
    418: ("build_val", "Yapi Degeri", "browser"),
    419: ("error_probe_inv", "Hata Probu: Invocation", "probe"),
    427: ("misc_flag", "Cesitli Bayrak", "probe"),
    432: ("misc_val", "Cesitli Deger", "event"),
    437: ("fp_hex_2", "Parmak Izi Hex 2", "fingerprint"),
    438: ("feature_flags_bin", "Ozellik Bayrak Dizisi", "probe"),
    444: ("misc_val_2", "Cesitli Deger 2", "event"),
    448: ("behavior_code", "Davranis Kodu", "event"),
    458: ("media_cap_3", "Medya Oynatma Yetenegi 3", "media"),
    463: ("screen_px_2", "Ekran Piksel Degeri 2", "screen"),
    466: ("short_flag", "Kisa Bayrak", "token"),
    469: ("fp_hex_3", "Parmak Izi Hex 3", "fingerprint"),
    471: ("perf_val_3", "Performans Degeri 3", "event"),
    473: ("client_ip", "Istemci IP Adresi", "network"),
    482: ("fp_hex_4", "Parmak Izi Hex 4", "fingerprint"),
    483: ("perf_val_4", "Performans Degeri 4", "event"),
    485: ("misc_val_3", "Cesitli Deger 3", "event"),
    490: ("intl_code", "Intl Kodu", "system"),
    492: ("fp_hex_5", "Parmak Izi Hex 5", "fingerprint"),
    496: ("adv_flag_2", "Gelismis Bayrak 2", "probe"),
    502: ("webrtc_flag", "WebRTC Bayragi", "probe"),
    517: ("api_code_2", "API Kodu 2", "browser"),
    520: ("site_domain", "Site Alan Adi", "network"),
    523: ("site_val", "Site Degeri", "network"),
    529: ("shader_source", "WebGL Shader Kodu", "probe"),
    530: ("shader_val", "Shader Degeri", "probe"),
    533: ("perf_val_5", "Performans Degeri 5", "event"),
    541: ("nav_code_2", "Navigasyon Kodu", "session"),
    542: ("url_path", "URL Yolu", "network"),
    543: ("url_flag", "URL Bayragi", "network"),
    550: ("config_code", "Yapilandirma Kodu", "token"),
    561: ("api_code_3", "API Kodu 3", "browser"),
    567: ("behavior_val", "Davranis Degeri", "event"),
    568: ("behavior_val_2", "Davranis Degeri 2", "event"),
    577: ("short_flag_2", "Kisa Bayrak 2", "token"),
    579: ("proto_probe", "Prototip Dongu Probu", "probe"),
    581: ("behavior_flag", "Davranis Bayragi", "event"),
    588: ("timing_delta", "Zamanlama Deltasi", "event"),
    589: ("timing_val_4", "Zamanlama Degeri 4", "event"),
    590: ("timing_flag", "Zamanlama Bayragi", "event"),
    599: ("fp_hex_6", "Parmak Izi Hex 6", "fingerprint"),
    609: ("secondary_ts", "Ikincil Zaman Damgasi", "session"),
    617: ("session_code", "Oturum Kodu", "session"),
    619: ("stack_probe", "Yigin Derinlik Probu", "probe"),
    622: ("session_id", "Oturum Kimligi", "session"),
    629: ("session_val", "Oturum Degeri", "session"),
    631: ("session_id_dup", "Oturum Kimligi (Kopya)", "session"),
    632: ("session_flag", "Oturum Bayragi", "session"),
    638: ("ua_dup", "User-Agent (Kopya)", "browser"),
    643: ("nav_type", "Navigasyon Tipi", "session"),
    645: ("ua_brands_short", "UA Marka (Kisa JSON)", "browser"),
    647: ("fp_hex_7", "Parmak Izi Hex 7", "fingerprint"),
    655: ("final_val", "Son Zamanlama", "event"),
    658: ("screen_val_2", "Ekran Degeri", "screen"),
    659: ("webrtc_proto", "WebRTC Protokolu", "probe"),
    661: ("webrtc_val", "WebRTC Degeri", "probe"),
    665: ("zero_flags", "Sifir Bayrak Dizisi", "probe"),
    668: ("device_uuid", "Cihaz UUID", "session"),
    670: ("short_hash_1", "Kisa Hash 1", "fingerprint"),
    671: ("final_timing", "Son Zamanlama Degeri", "event"),
    673: ("final_code", "Son Kod Degeri", "token"),
    674: ("final_val_2", "Son Deger 2", "event"),
    677: ("final_timing_2", "Son Zamanlama 2", "event"),
    679: ("short_hash_2", "Kisa Hash 2", "fingerprint"),
    # 683..767: Zamanlama Problari (kd Float32 ms)
    747: ("probe_time_sync_total", "Senkron Problar Toplam Suresi (ms)", "event"),
    748: ("probe_time_total_token", "Toplam Token Uretim Suresi (ms)", "event"),
    749: ("probe_time_async_all", "18 Asenkron Prob Toplam Suresi (ms)", "event"),
    750: ("probe_time_async_0", "Asenkron Prob 0: Ilk baslatma (ms)", "event"),
    751: ("probe_time_async_1", "Asenkron Prob 1: UA HighEntropyValues (ms)", "event"),
    752: ("probe_time_async_2", "Asenkron Prob 2: MediaCapabilities (ms)", "event"),
    753: ("probe_time_async_3", "Asenkron Prob 3: Permissions API (ms)", "event"),
    754: ("probe_time_async_4", "Asenkron Prob 4: Medya Codec/DRM (ms)", "event"),
    755: ("probe_time_async_5", "Asenkron Prob 5: AudioContext Parmak Izi (ms)", "event"),
    756: ("probe_time_async_6", "Asenkron Prob 6: Worker Debugger Tespiti (ms)", "event"),
    757: ("probe_time_async_7", "Asenkron Prob 7: WebRTC SDP Analizi (ms)", "event"),
    758: ("probe_time_async_8", "Asenkron Prob 8: WebRTC ICE/IP Sizintisi (ms)", "event"),
    759: ("probe_time_async_9", "Asenkron Prob 9: Storage Estimate Kota (ms)", "event"),
    760: ("probe_time_async_10", "Asenkron Prob 10: WebGL/GPU Render (ms)", "event"),
    761: ("probe_time_async_11", "Asenkron Prob 11: MediaDevices Cihazlar (ms)", "event"),
    762: ("probe_time_async_12", "Asenkron Prob 12: Battery API Durumu (ms)", "event"),
    763: ("probe_time_async_13", "Asenkron Prob 13: SpeechSynthesis Sesler (ms)", "event"),
    764: ("probe_time_async_14", "Asenkron Prob 14: ServiceWorker Kayit (ms)", "event"),
    765: ("probe_time_async_15", "Asenkron Prob 15: WebGPU Adaptor (ms)", "event"),
    766: ("probe_time_async_16", "Asenkron Prob 16: Canvas/Font Async (ms)", "event"),
    767: ("probe_time_async_17", "Asenkron Prob 17: rAF Zamanlayici (ms)", "event"),
}

# V3 (WcmFKZlD / castle.umd-CGiQ_kr0.js) Metrik Haritasi (772 metrik, 0..771)
METRIC_INFO_V3: Dict[int, Tuple[str, str, str]] = {
    0: ("fp_hex_4", "Parmak Izi Hex 4", "fingerprint"),
    10: ("canvas_fp", "Canvas Parmak Izi Hash", "fingerprint"),
    21: ("architecture", "Islemci Mimarisi (x86/arm)", "system"),
    29: ("browser_ver_detail", "Tarayici Surumu (Detay)", "browser"),
    43: ("webdriver_flag", "WebDriver / Otomasyon Bayragi", "probe"),
    53: ("os_arch", "IS + Mimari Birlesik", "system"),
    57: ("engine_version", "Motor Surumu (Chromium/OS)", "system"),
    60: ("tz_offset_raw", "Saat Dilimi Ofseti (dk)", "system"),
    64: ("locale", "Yerel Ayar (Locale)", "system"),
    68: ("automation_flag_1", "Otomasyon Kontrol Bayragi 1", "probe"),
    77: ("error_probe_type", "Hata Probu: RangeError", "probe"),
    78: ("shader_hash_str", "WebGL Shader Hash + Tip", "fingerprint"),
    84: ("session_id", "Oturum Kimligi (Session ID)", "session"),
    87: ("os_name", "Isletim Sistemi Adi", "system"),
    89: ("timezone", "Saat Dilimi (IANA)", "system"),
    92: ("automation_flag_2", "Otomasyon Kontrol Bayragi 2", "probe"),
    96: ("user_agent", "User-Agent", "browser"),
    98: ("error_probe_inv", "Hata Probu: Illegal Invocation", "probe"),
    100: ("feature_flags_bin", "Ozellik Bayrak Dizisi (Binary)", "probe"),
    108: ("engine_ver_dup", "Motor Surumu (Kopya)", "browser"),
    121: ("display_type", "Goruntu Tipi (screen)", "screen"),
    122: ("accept_langs", "Kabul Edilen Diller", "browser"),
    125: ("platform", "Platform (navigator.platform)", "system"),
    135: ("language", "Birincil Dil Kodu", "system"),
    157: ("origin_url", "Kaynak URL (location.origin)", "network"),
    160: ("device_uuid", "Cihaz UUID", "session"),
    168: ("css_selector_fp", "CSS Selector Destegi", "probe"),
    169: ("castle_pubkey", "Castle Ortam / Public Key", "token"),
    174: ("secondary_ts", "Ikincil Zaman Damgasi (Sayfa Yukleme)", "session"),
    176: ("automation_flag_3", "Otomasyon Kontrol Bayragi 3", "probe"),
    179: ("audio_fp", "AudioContext Parmak Izi Hash", "fingerprint"),
    183: ("date_probe", "Tarih Format Probu (Intl)", "system"),
    209: ("local_ip_fallback", "Yerel IP Fallback", "network"),
    212: ("client_ip", "Istemci IP Adresi (WebRTC)", "network"),
    218: ("chrome_runtime_flag", "Chrome Runtime Spoof Bayragi", "probe"),
    228: ("automation_flag_4", "Otomasyon Kontrol Bayragi 4", "probe"),
    232: ("session_id_dup", "Oturum Kimligi (Kopya)", "session"),
    237: ("gpu_renderer", "GPU Renderer (WebGL)", "browser"),
    244: ("automation_flag_5", "Otomasyon Kontrol Bayragi 5", "probe"),
    265: ("webgl_fp", "WebGL Render Parmak Izi Hash", "fingerprint"),
    296: ("gpu_renderer_dup", "GPU Renderer (Kopya)", "browser"),
    306: ("shader_source", "WebGL Shader Kaynak Kodu", "probe"),
    311: ("gpu_arch", "GPU Mimarisi (WebGPU)", "browser"),
    355: ("headless_flag", "Headless Tarayici Bayragi", "probe"),
    373: ("zero_flags", "Sifir Bayrak Dizisi", "probe"),
    375: ("window_prop_check", "Window Ozellik Dogrulamasi", "probe"),
    398: ("browser_vendor", "Tarayici Ureticisi (navigator.vendor)", "browser"),
    402: ("arch_bits", "Islemci Bit Genisligi (64/32)", "system"),
    412: ("page_title", "Sayfa Basligi (document.title)", "network"),
    414: ("screen_orient", "Ekran Yonu (Orientation)", "screen"),
    416: ("automation_flag_6", "Otomasyon Kontrol Bayragi 6", "probe"),
    431: ("error_probe_prop", "Hata Probu: Property Access", "probe"),
    433: ("webrtc_proto", "WebRTC Aktarim Protokolu", "probe"),
    445: ("cdp_code", "CDP / DevTools Tespit Kodu ('N'=Temiz)", "probe"),
    477: ("chrome_obj_present", "window.chrome Nesnesi Mevcut", "browser"),
    492: ("render_engine", "Render Motoru", "browser"),
    504: ("build_id", "Tarayici Build ID (productSub)", "browser"),
    506: ("selenium_cdc_flag", "Selenium / ChromeDriver ($cdc_) Bayragi", "probe"),
    510: ("perf_memory_present", "Performance Memory Mevcut", "browser"),
    512: ("visibility", "Sayfa Gorunurlugu (visibilityState)", "session"),
    517: ("chrome_csi_present", "Chrome CSI/LoadTimes Dogrulamasi", "browser"),
    522: ("ua_dup", "User-Agent (Kopya)", "browser"),
    523: ("ua_brands", "UA Marka Bilgisi (Tam JSON)", "browser"),
    527: ("automation_flag_7", "Otomasyon Kontrol Bayragi 7", "probe"),
    533: ("protocol", "Protokol (location.protocol)", "network"),
    535: ("automation_flag_8", "Otomasyon Kontrol Bayragi 8", "probe"),
    538: ("nav_type", "Navigasyon Tipi", "session"),
    555: ("last_event", "Son Kullanici Etkilesim Olayi", "event"),
    558: ("proto_probe", "Prototip Dongu Probu (__proto__)", "probe"),
    573: ("gpu_vendor", "GPU Ureticisi", "browser"),
    592: ("browser_name", "Tarayici Adi", "browser"),
    597: ("stack_probe", "Yigin Derinlik Probu (Call Stack)", "probe"),
    598: ("site_domain", "Site Alan Adi (location.hostname)", "network"),
    632: ("ua_brands_short", "UA Marka (Kisa JSON)", "browser"),
    636: ("url_path", "URL Yolu (location.pathname)", "network"),
    650: ("fp_hex_2", "Parmak Izi Hex 2", "fingerprint"),
    655: ("feature_support_flag", "Tarayici Ozellik Destegi Bayragi", "browser"),
    670: ("browser_version", "Tarayici Surumu", "browser"),
    # 687..771: Zamanlama Problari (Qd Float32 ms)
    751: ("probe_time_sync_total", "Senkron Problar Toplam Suresi (ms)", "event"),
    752: ("probe_time_total_token", "Toplam Token Uretim Suresi (ms)", "event"),
    753: ("probe_time_async_all", "18 Asenkron Prob Toplam Suresi (ms)", "event"),
    754: ("probe_time_async_0", "Asenkron Prob 0: Ilk baslatma (ms)", "event"),
    755: ("probe_time_async_1", "Asenkron Prob 1: UA HighEntropyValues (ms)", "event"),
    756: ("probe_time_async_2", "Asenkron Prob 2: MediaCapabilities (ms)", "event"),
    757: ("probe_time_async_3", "Asenkron Prob 3: Permissions API (ms)", "event"),
    758: ("probe_time_async_4", "Asenkron Prob 4: Medya Codec/DRM (ms)", "event"),
    759: ("probe_time_async_5", "Asenkron Prob 5: AudioContext Parmak Izi (ms)", "event"),
    760: ("probe_time_async_6", "Asenkron Prob 6: Worker Debugger Tespiti (ms)", "event"),
    761: ("probe_time_async_7", "Asenkron Prob 7: WebRTC SDP Analizi (ms)", "event"),
    762: ("probe_time_async_8", "Asenkron Prob 8: WebRTC ICE/IP Sizintisi (ms)", "event"),
    763: ("probe_time_async_9", "Asenkron Prob 9: Storage Estimate Kota (ms)", "event"),
    764: ("probe_time_async_10", "Asenkron Prob 10: WebGL/GPU Render (ms)", "event"),
    765: ("probe_time_async_11", "Asenkron Prob 11: MediaDevices Cihazlar (ms)", "event"),
    766: ("probe_time_async_12", "Asenkron Prob 12: Battery API Durumu (ms)", "event"),
    767: ("probe_time_async_13", "Asenkron Prob 13: SpeechSynthesis Sesler (ms)", "event"),
    768: ("probe_time_async_14", "Asenkron Prob 14: ServiceWorker Kayit (ms)", "event"),
    769: ("probe_time_async_15", "Asenkron Prob 15: WebGPU Adaptor (ms)", "event"),
    770: ("probe_time_async_16", "Asenkron Prob 16: Canvas/Font Async (ms)", "event"),
    771: ("probe_time_async_17", "Asenkron Prob 17: rAF Zamanlayici (ms)", "event"),
}

def _is_valid_decoded_text(decoded: str) -> bool:
    if not decoded:
        return False
    for ch in decoded:
        c = ord(ch)
        if not ((32 <= c <= 126) or c in (9, 10, 13) or (0x00A0 <= c <= 0x024F)):
            return False
    return True

def _lr_decode_value(s: Any) -> Any:
    """lr() kodlu base64 stringini cozumler (V2)."""
    if not isinstance(s, str) or len(s) < 4:
        return s
    try:
        padded = s + '=' * (-len(s) % 4)
        raw = base64.b64decode(padded)
    except Exception:
        return s
    if len(raw) < 2 or len(raw) % 2 != 0:
        return s
    chars = []
    for i in range(0, len(raw), 2):
        val = (raw[i] << 8) | raw[i + 1]
        val = ((val >> 2) | (val << 14)) & 0xFFFF
        val = (val - 0xC481) & 0xFFFF
        val = ((val >> 1) | (val << 15)) & 0xFFFF
        chars.append(chr(val))
    decoded = ''.join(chars)
    if _is_valid_decoded_text(decoded):
        return decoded
    return s

def _v3_decode_value(s: Any) -> Any:
    """Gn() veya Kn() kodlu base64 stringini cozumler (V3 WcmFKZlD)."""
    if not isinstance(s, str) or len(s) < 4:
        return s
    try:
        padded = s + '=' * (-len(s) % 4)
        raw = base64.b64decode(padded)
    except Exception:
        return s
    if len(raw) < 2 or len(raw) % 2 != 0:
        return s

    # 1. Gn() inverse: ROR4 -> XOR 0x72DC -> ADD 0xB1E6
    chars_gn = []
    for i in range(0, len(raw), 2):
        val = (raw[i] << 8) | raw[i + 1]
        val = ((val >> 4) | (val << 12)) & 0xFFFF
        val = (val ^ 0x72DC) & 0xFFFF
        val = (val + 0xB1E6) & 0xFFFF
        chars_gn.append(chr(val))
    dec_gn = ''.join(chars_gn)
    if _is_valid_decoded_text(dec_gn):
        return dec_gn

    # 2. Kn() inverse: XOR 0x406F -> SUB 0x3F95
    chars_kn = []
    for i in range(0, len(raw), 2):
        val = (raw[i] << 8) | raw[i + 1]
        val = ((val ^ 0x406F) - 0x3F95) & 0xFFFF
        chars_kn.append(chr(val))
    dec_kn = ''.join(chars_kn)
    if _is_valid_decoded_text(dec_kn):
        return dec_kn

    return s

def _kd_decode_float32(s: Any) -> Optional[float]:
    """V2 kd() 4-bayt sifreli Float32 zamanlama degerini (ms) cozumler."""
    if not isinstance(s, str) or len(s) < 4:
        return None
    try:
        padded = s + '=' * (-len(s) % 4)
        raw = base64.b64decode(padded)
        if len(raw) != 4:
            return None
        out = bytearray(4)
        for i in range(4):
            b = (raw[i] - 0x99) & 0xFF
            b = (b ^ 0x8F) & 0xFF
            b = ((b >> 6) | (b << 2)) & 0xFF
            out[i] = b
        val = struct.unpack('>f', bytes(out))[0]
        if -1e6 < val < 1e9:
            return round(val, 2)
    except Exception:
        pass
    return None

def _qd_decode_float32(s: Any) -> Optional[float]:
    """V3 Qd() 4-bayt sifreli Float32 zamanlama degerini (ms) cozumler."""
    if not isinstance(s, str) or len(s) < 4:
        return None
    try:
        padded = s + '=' * (-len(s) % 4)
        raw = base64.b64decode(padded)
        if len(raw) != 4:
            return None
        out = bytearray(4)
        for i in range(4):
            b = (raw[i] * 15) & 0xFF  # 239 * 15 === 1 (mod 256)
            b = (b ^ 0x6F) & 0xFF
            b = ((b >> 5) | (b << 3)) & 0xFF
            out[i] = b
        val = struct.unpack('>f', bytes(out))[0]
        if -1e6 < val < 1e9:
            return round(val, 2)
    except Exception:
        pass
    return None

def _lr_decode_to_hex(s: Any) -> Optional[str]:
    """lr() decode sonucu ASCII degilse, orijinal base64'u hex olarak dondurur."""
    if not isinstance(s, str) or len(s) < 4:
        return None
    try:
        padded = s + '=' * (-len(s) % 4)
        raw = base64.b64decode(padded)
        return raw.hex()
    except Exception:
        return None

def _m(metrics: list, idx: int, default: Any = None) -> Any:
    return metrics[idx] if idx < len(metrics) and metrics[idx] is not None else default

def _is_bool_true(metrics: list, idx: int) -> bool:
    if idx >= len(metrics):
        return False
    v = metrics[idx]
    return isinstance(v, bool) and v is True

def _format_value(idx: int, value: Any, version: int = 2) -> str:
    """Metrik degerini insan-okunabilir formata donusturur."""
    if value is None:
        return "bos"
    if isinstance(value, bool):
        return "Evet" if value else "Hayir"
    if isinstance(value, int):
        if value == 165:
            return "-- (olculmedi)"
        if value == 161:
            return "-- (mevcut degil)"
        if value == 173:
            return "-- (ayrilmis)"
        if abs(value) > 100_000_000:
            return f"0x{value & 0xFFFFFFFF:08X}"
        return str(value)
    if isinstance(value, float):
        if (version == 3 and 687 <= idx <= 771) or (version == 2 and 683 <= idx <= 767):
            return f"{value} ms"
        return str(value)
    if isinstance(value, str):
        if version == 2 and FONT_PROBE_START <= idx <= FONT_PROBE_END:
            hex_val = _lr_decode_to_hex(value)
            if hex_val and hex_val in FONT_NOT_INSTALLED_HEX:
                return "Yuklu Degil"
            elif hex_val:
                return f"Yuklu (hash: {hex_val})"
        if len(value) > 200:
            return value[:200] + "..."
        return value
    if isinstance(value, list):
        items = []
        for item in value:
            if isinstance(item, int) and abs(item) > 100_000:
                items.append(f"0x{item & 0xFFFFFFFF:08X}")
            else:
                items.append(str(item))
        return "[" + ", ".join(items) + "]"
    return str(value)

def _get_metric_info(idx: int, value: Any, version: Union[int, bool]) -> Tuple[str, str, str]:
    """Metrik icin (etiket, kategori, formatli_deger) dondurur."""
    ver = 2 if version is True else (1 if version is False else int(version))
    formatted = _format_value(idx, value, ver)

    if ver == 3:
        if idx in METRIC_INFO_V3:
            _, label, cat = METRIC_INFO_V3[idx]
            return (label, cat, formatted)
        if 687 <= idx <= 750:
            return (f"Senkron Prob #{idx - 687} Suresi (ms)", "event", formatted)

    if ver == 2:
        if idx in METRIC_INFO_V2:
            _, label, cat = METRIC_INFO_V2[idx]
            return (label, cat, formatted)
        if 683 <= idx <= 746:
            return (f"Senkron Prob #{idx - 683} Suresi (ms)", "event", formatted)
        if FONT_PROBE_START <= idx <= FONT_PROBE_END:
            return (f"Font Testi #{idx - FONT_PROBE_START}", "font", formatted)

    if ver == 1 and idx in METRIC_LABELS:
        _, label = METRIC_LABELS[idx]
        return (label, "system", formatted)

    if value is None:
        return ("Bos Alan", "token", formatted)
    if isinstance(value, bool):
        return ("Bayrak", "probe", formatted)
    if isinstance(value, int):
        if value == 165:
            return ("Olculmedi", "token", formatted)
        if value == 161:
            return ("Mevcut Degil", "token", formatted)
        if value == 173:
            return ("Ayrilmis", "token", formatted)
        if abs(value) > 100_000_000:
            return ("Parmak Izi Bileseni", "fingerprint", formatted)
        if abs(value) > 999:
            return ("Sayisal Deger", "event", formatted)
        return ("Parametre Degeri", "system", formatted)
    if isinstance(value, str):
        return ("Metin Degeri", "browser", formatted)
    if isinstance(value, list):
        return ("Hash Cifti", "fingerprint", formatted)
    if isinstance(value, float):
        return ("Ondalik Deger", "event", formatted)
    return ("Bilinmeyen", "token", formatted)

# ---------------------------------------------------------------------------
# 5. ANA KONTROL VE ÇÖZÜCÜ SINIFI (PURE CASTLE DECODER)
# ---------------------------------------------------------------------------
class PureCastleDecoder:
    """
    Sadece Python standart kütüphanesi kullanan bağımsız Castle Token Çözücü.
    """

    def decode_token(self, token_str: str) -> Dict[str, Any]:
        token_str = token_str.strip()
        if '|' not in token_str:
            raise ValueError("Geçersiz Castle token biçimi: Token 'prefix|payload' formatında olmalıdır.")
        parts = token_str.split('|', 1)

        b64_payload = parts[1].strip()
        b64_padded = b64_payload + '=' * (-len(b64_payload) % 4)
        raw_bytes = base64.b64decode(b64_padded)

        # 1. Anahtar Uzunluğu ve Şifrelenmiş Zaman Damgası
        key_len = raw_bytes[0] | (raw_bytes[1] << 8)
        key_bytes = raw_bytes[2:2 + key_len]
        key_b64 = key_bytes.decode('latin1', errors='ignore')

        # 2. Zaman Damgası Şifresini Çöz (13 haneli Unix epoch ms)
        timestamp_str = recover_timestamp_key(key_b64)
        ts_ms = int(timestamp_str) if timestamp_str.isdigit() else 0
        iso_utc = (
            datetime.datetime.fromtimestamp(ts_ms / 1000.0, datetime.timezone.utc).isoformat()
            if ts_ms else "Bilinmiyor"
        )
        local_date = (
            datetime.datetime.fromtimestamp(ts_ms / 1000.0).strftime('%Y-%m-%d %H:%M:%S')
            if ts_ms else "Bilinmiyor"
        )

        # 3. 24 Baytlık Güvenlik ve Segment Başlığı
        header_offset = 2 + key_len
        auth_header = raw_bytes[header_offset:header_offset + 24]
        seg1_len = int.from_bytes(auth_header[0:4], 'big')
        seg2_len = int.from_bytes(auth_header[4:8], 'big')
        checksum_sig = auth_header[8:24].hex()

        # 4. Şifreli Gövde (Ciphertext)
        ciphertext = raw_bytes[header_offset + 24:]

        # 5. Versiyon tespiti ve sifre cozme (V3 / V2 / V1 otomatik algilama)
        prefix = parts[0]
        if prefix == 'WcmFKZlD':
            cipher_order = [(3, decrypt_castle_stream_v3), (2, decrypt_castle_stream_v2), (1, decrypt_castle_stream)]
        elif prefix == 'uq1seNrd':
            cipher_order = [(1, decrypt_castle_stream), (2, decrypt_castle_stream_v2), (3, decrypt_castle_stream_v3)]
        else:
            cipher_order = [(2, decrypt_castle_stream_v2), (3, decrypt_castle_stream_v3), (1, decrypt_castle_stream)]

        version = None
        decrypted_bytes = b""
        decompressed_bytes = b""
        last_err = None
        for ver_num, decrypt_fn in cipher_order:
            try:
                cand_dec = decrypt_fn(ciphertext, timestamp_str)
                decompressed_bytes = zlib.decompress(cand_dec, -15)
                decrypted_bytes = cand_dec
                version = ver_num
                break
            except zlib.error as err:
                last_err = err

        if version is None:
            raise last_err or ValueError("Castle token akis sifresi cozulemedi (V1/V2/V3 uyumsuz).")

        # 7. İkili Telemetri Protokolü Ayrıştırma (Deserialize)
        raw_metrics = deserialize_castle_payload(decompressed_bytes)

        # 8. Versiyona gore string deobfuscation + prob zamanlama (Float32) cozumu + temizleme
        cleaned_metrics = list(raw_metrics)
        if version == 3:
            for i in range(len(cleaned_metrics)):
                if 687 <= i <= 771 and isinstance(cleaned_metrics[i], str):
                    fval = _qd_decode_float32(cleaned_metrics[i])
                    if fval is not None:
                        cleaned_metrics[i] = fval
                        continue
                cleaned_metrics[i] = _v3_decode_value(cleaned_metrics[i])
                cleaned_metrics[i] = clean_string_value(cleaned_metrics[i])
        elif version == 2:
            for i in range(len(cleaned_metrics)):
                if 683 <= i <= 767 and isinstance(cleaned_metrics[i], str):
                    fval = _kd_decode_float32(cleaned_metrics[i])
                    if fval is not None:
                        cleaned_metrics[i] = fval
                        continue
                cleaned_metrics[i] = _lr_decode_value(cleaned_metrics[i])
                cleaned_metrics[i] = clean_string_value(cleaned_metrics[i])
        else:
            cleaned_metrics = [clean_string_value(v) for v in cleaned_metrics]

        # 9. Versiyona gore alan cikarimi
        labeled_metrics = {}
        for idx, val in enumerate(cleaned_metrics):
            if version == 3 and idx in METRIC_INFO_V3:
                slug, title, cat = METRIC_INFO_V3[idx]
                labeled_metrics[slug] = {"index": idx, "title": title, "category": cat, "value": val}
            elif version == 2 and idx in METRIC_INFO_V2:
                slug, title, cat = METRIC_INFO_V2[idx]
                labeled_metrics[slug] = {"index": idx, "title": title, "category": cat, "value": val}
            elif version == 1 and idx in METRIC_LABELS:
                slug, title = METRIC_LABELS[idx]
                labeled_metrics[slug] = {"index": idx, "title": title, "value": val}

        # formatted_metrics: tum metrikler icin etiket/kategori/formatli deger
        formatted_metrics = []
        for i, v in enumerate(cleaned_metrics):
            label, cat, formatted = _get_metric_info(i, v, version)
            formatted_metrics.append({
                "index": i,
                "label": label,
                "category": CATEGORY_TR.get(cat, cat),
                "type": type(v).__name__ if v is not None else "null",
                "value": formatted,
                "raw": v,
            })

        if version == 3:
            client_os = _m(cleaned_metrics, 87, "Bilinmiyor")
            client_ip = _m(cleaned_metrics, 212, "Bilinmiyor")
            browser_name = _m(cleaned_metrics, 592, "")
            browser_ver = _m(cleaned_metrics, 29, _m(cleaned_metrics, 670, "Bilinmiyor"))
            if browser_name:
                browser_ver = f"{browser_name} {browser_ver}"
            device_guid = _m(cleaned_metrics, 160, "Bilinmiyor")
            user_agent = _m(cleaned_metrics, 96, "Bilinmiyor")
            gpu_renderer = _m(cleaned_metrics, 237, "Bilinmiyor")
            timezone = _m(cleaned_metrics, 89, "Bilinmiyor")
            locale = _m(cleaned_metrics, 64, "Bilinmiyor")
            platform = _m(cleaned_metrics, 125, "Bilinmiyor")
            arch = _m(cleaned_metrics, 21, "")
            page_title = _m(cleaned_metrics, 412, "")
            origin_url = _m(cleaned_metrics, 157, "")
            canvas_hash = _m(cleaned_metrics, 10, None)
            audio_hash = _m(cleaned_metrics, 179, None)
            webgl_gpu_code = _m(cleaned_metrics, 265, None)
            session_id = _m(cleaned_metrics, 84, "Bilinmiyor")
            # V3 Bot & Otomasyon tespiti:
            # 506: Selenium/ChromeDriver ($cdc_), 43: WebDriver/Otomasyon, 355: Headless,
            # 218: Chrome Runtime Spoof, 445: CDP ('N' temiz, 'rFzj' CDP aktif)
            webdriver_active = _is_bool_true(cleaned_metrics, 43) or _is_bool_true(cleaned_metrics, 506)
            headless_browser = _is_bool_true(cleaned_metrics, 355)
            cdp_val = _m(cleaned_metrics, 445, "N")
            cdp_active = (isinstance(cdp_val, str) and cdp_val != "N") or _is_bool_true(cleaned_metrics, 445)
            devtools_open = cdp_active
            bot_detected = (
                webdriver_active
                or headless_browser
                or _is_bool_true(cleaned_metrics, 68)
                or _is_bool_true(cleaned_metrics, 92)
                or _is_bool_true(cleaned_metrics, 176)
                or _is_bool_true(cleaned_metrics, 218)
                or _is_bool_true(cleaned_metrics, 228)
                or _is_bool_true(cleaned_metrics, 244)
                or _is_bool_true(cleaned_metrics, 416)
                or _is_bool_true(cleaned_metrics, 527)
                or _is_bool_true(cleaned_metrics, 535)
            )
            screen_res = f"{platform} {arch}".strip()
            font_signatures = cleaned_metrics[687:751] if len(cleaned_metrics) >= 751 else []
        elif version == 2:
            client_os = _m(cleaned_metrics, 8, "Bilinmiyor")
            client_ip = _m(cleaned_metrics, 473, "Bilinmiyor")
            browser_name = _m(cleaned_metrics, 101, "")
            browser_ver = _m(cleaned_metrics, 248, "Bilinmiyor")
            if browser_name:
                browser_ver = f"{browser_name} {browser_ver}"
            device_guid = _m(cleaned_metrics, 668, "Bilinmiyor")
            user_agent = _m(cleaned_metrics, 63, "Bilinmiyor")
            gpu_renderer = _m(cleaned_metrics, 60, "Bilinmiyor")
            timezone = _m(cleaned_metrics, 224, "Bilinmiyor")
            locale = _m(cleaned_metrics, 67, "Bilinmiyor")
            platform = _m(cleaned_metrics, 366, "Bilinmiyor")
            arch = _m(cleaned_metrics, 368, "")
            page_title = _m(cleaned_metrics, 308, "")
            origin_url = _m(cleaned_metrics, 260, "")
            canvas_hash = _m(cleaned_metrics, 135, None)
            audio_hash = _m(cleaned_metrics, 143, None)
            webgl_gpu_code = _m(cleaned_metrics, 11, None)
            session_id = _m(cleaned_metrics, 622, "Bilinmiyor")
            # Bot tespiti: V2'de sadece gercek boolean degerler gecerli
            bot_detected = _is_bool_true(cleaned_metrics, 44)
            webdriver_active = _is_bool_true(cleaned_metrics, 22)
            headless_browser = _is_bool_true(cleaned_metrics, 143)
            devtools_open = _is_bool_true(cleaned_metrics, 151)
            cdp_active = _is_bool_true(cleaned_metrics, 383)
            screen_res = f"{platform} {arch}".strip()
            font_signatures = cleaned_metrics[668:] if len(cleaned_metrics) > 668 else []
        else:
            client_os = _m(cleaned_metrics, 59, "Windows")
            client_ip = _m(cleaned_metrics, 406, "Bilinmiyor")
            browser_ver = _m(cleaned_metrics, 551, "Bilinmiyor")
            device_guid = _m(cleaned_metrics, 163, "Bilinmiyor")
            user_agent = "Bilinmiyor"
            gpu_renderer = "Bilinmiyor"
            timezone = "Bilinmiyor"
            locale = "Bilinmiyor"
            page_title = ""
            origin_url = ""
            canvas_hash = _m(cleaned_metrics, 6, None)
            audio_hash = _m(cleaned_metrics, 8, None)
            webgl_gpu_code = _m(cleaned_metrics, 11, None)
            session_id = "Bilinmiyor"
            bot_detected = _is_bool_true(cleaned_metrics, 44)
            webdriver_active = _is_bool_true(cleaned_metrics, 22)
            headless_browser = _is_bool_true(cleaned_metrics, 143)
            devtools_open = _is_bool_true(cleaned_metrics, 151)
            cdp_active = _is_bool_true(cleaned_metrics, 383)
            w = _m(cleaned_metrics, 1, 0)
            h = _m(cleaned_metrics, 2, 0)
            screen_res = f"{w}x{h}" if isinstance(w, int) and isinstance(h, int) else "Bilinmiyor"
            font_signatures = cleaned_metrics[668:] if len(cleaned_metrics) > 668 else []

        is_bot = bot_detected or webdriver_active or cdp_active
        security_verdict = "FLAGGED_AS_BOT" if is_bot else "VERIFIED_GENUINE_HUMAN"
        security_text = "SUPHELI / BOT (Tespit Edildi)" if is_bot else "GUVENLI / GERCEK KULLANICI (Temiz)"

        summary = {
            "token_status": "SUCCESSFULLY_DECRYPTED",
            "token_version": parts[0],
            "security_verdict": security_verdict,
            "security_verdict_tr": security_text,
            "session_time": {
                "epoch_ms": ts_ms,
                "utc": iso_utc,
                "local": local_date
            },
            "client_profile": {
                "ip_address": client_ip,
                "operating_system": client_os,
                "browser_version": browser_ver,
                "device_guid": device_guid,
                "user_agent": user_agent,
                "gpu_renderer": gpu_renderer,
                "timezone": timezone,
                "locale": locale,
                "platform": screen_res,
                "page_title": page_title,
                "origin_url": origin_url,
                "session_id": session_id
            },
            "anti_bot_telemetry": {
                "automation_detected": bot_detected,
                "webdriver_active": webdriver_active,
                "headless_detected": headless_browser,
                "devtools_open": devtools_open,
                "cdp_active": cdp_active
            },
            "graphics_and_fingerprints": {
                "canvas_hash": canvas_hash,
                "audio_hash": audio_hash,
                "webgl_gpu_code": webgl_gpu_code,
                "total_font_probes": len(font_signatures),
                "unique_fonts_detected": len(set(str(x) for x in font_signatures))
            },
            "protocol_headers": {
                "segment_1_bytes": seg1_len,
                "segment_2_bytes": seg2_len,
                "total_ciphertext_bytes": len(ciphertext),
                "decompressed_payload_bytes": len(decompressed_bytes),
                "signature_hash": checksum_sig
            },
            "labeled_metrics": labeled_metrics,
            "formatted_metrics": formatted_metrics,
            "total_metrics_count": len(cleaned_metrics),
            "all_metrics_cleaned": cleaned_metrics
        }

        return summary

# ---------------------------------------------------------------------------
# 6. GÖRSEL KONSOL ÇIKTISI VE CLI ARAYÜZÜ
# ---------------------------------------------------------------------------
def print_human_readable_report(res: Dict[str, Any]):
    """Sonuclari konsolda temiz formatta gosterir."""
    p = res["client_profile"]
    b = res["anti_bot_telemetry"]
    s = res["session_time"]
    g = res["graphics_and_fingerprints"]
    h = res["protocol_headers"]

    border = "=" * 74
    sub_border = "-" * 74

    print("\n" + border)
    print("       CASTLE ANTI-BOT TELEMETRI TOKEN RAPORU")
    print(border)
    print(f" [*] Cozum Durumu     : {res['token_status']} (Protokol: {res['token_version']})")
    print(f" [*] Guvenlik Durumu  : {res['security_verdict_tr']}")
    print(f" [*] Toplam Metrik    : {res['total_metrics_count']} adet")
    print(sub_border)
    print(" 1. ZAMAN VE OTURUM BILGILERI:")
    print(f"    Zaman Damgasi   : {s['epoch_ms']} (Unix ms)")
    print(f"    UTC Zamani      : {s['utc']}")
    print(f"    Yerel Zaman     : {s['local']}")
    print(sub_border)
    print(" 2. ISTEMCI VE CIHAZ PROFILI:")
    print(f"    IP Adresi       : {p['ip_address']}")
    print(f"    Isletim Sistemi : {p['operating_system']}")
    print(f"    Tarayici        : {p['browser_version']}")
    print(f"    Platform        : {p['platform']}")
    print(f"    User-Agent      : {p['user_agent']}")
    print(f"    Saat Dilimi     : {p['timezone']}")
    print(f"    Dil / Yerel     : {p['locale']}")
    print(f"    GPU             : {p['gpu_renderer']}")
    print(f"    Cihaz GUID      : {p['device_guid']}")
    print(f"    Oturum ID       : {p['session_id']}")
    if p.get('page_title'):
        print(f"    Sayfa Basligi   : {p['page_title']}")
    if p.get('origin_url'):
        print(f"    Kaynak URL      : {p['origin_url']}")
    print(sub_border)
    print(" 3. BOT & OTOMASYON TESPIT VERILERI:")
    print(f"    Bot / Otomasyon : {'EVET (Riskli!)' if b['automation_detected'] else 'HAYIR (Temiz)'}")
    print(f"    WebDriver Aktif : {'EVET (Riskli!)' if b['webdriver_active'] else 'HAYIR (Temiz)'}")
    print(f"    Headless        : {'EVET' if b['headless_detected'] else 'HAYIR'}")
    print(f"    DevTools Acik   : {'EVET' if b['devtools_open'] else 'HAYIR'}")
    print(f"    CDP Aktif mi    : {'EVET' if b['cdp_active'] else 'HAYIR'}")
    print(sub_border)
    print(" 4. DONANIM VE PARMAK IZI BILGILERI:")
    print(f"    Canvas Hash     : {g['canvas_hash']}")
    print(f"    Ses Hash        : {g['audio_hash']}")
    print(f"    WebGL Kodu      : {g['webgl_gpu_code']}")
    print(f"    Font Imzalari   : {g['total_font_probes']} adet ({g['unique_fonts_detected']} benzersiz)")
    print(sub_border)
    print(" 5. PROTOKOL VE SIFRE DETAYLARI:")
    print(f"    Sifreli Veri    : {h['total_ciphertext_bytes']} bayt (Segmentler: {h['segment_1_bytes']} + {h['segment_2_bytes']})")
    print(f"    Acilmis Veri    : {h['decompressed_payload_bytes']} bayt (Zlib Raw Deflate)")
    print(f"    Butunluk Imzasi : {h['signature_hash']}")
    print(border + "\n")

def main():
    import argparse
    parser = argparse.ArgumentParser(
        description="Castle Anti-Bot Token Deobfuscator & Pure Python Decoder (Twitter/X.com uyumlu)"
    )
    parser.add_argument("token", nargs="?", help="Tam castle_token dizesi (uq1seNrd| veya cNz8rPYH| ile baslar)")
    parser.add_argument("--file", "-f", help="Token iceren metin dosyasinin yolu")
    parser.add_argument("--output", "-o", help="Ciktinin kaydedilecegi JSON dosyasi yolu (opsiyonel)")
    parser.add_argument("--json", "-j", action="store_true", help="Yalnizca saf JSON ciktisi uretir")
    args = parser.parse_args()

    token = None
    if args.file and os.path.exists(args.file):
        with open(args.file, "r", encoding="utf-8") as f:
            token = f.read().strip()
    elif args.token:
        token = args.token.strip()
    elif not sys.stdin.isatty():
        token = sys.stdin.read().strip()

    if not token:
        print("[!] Hata: Token saglanmadi. Tokeni arguman olarak, -f ile veya stdin uzerinden verin.", file=sys.stderr)
        print("    Ornek: python decode_token.py \"uq1seNrd|...\"", file=sys.stderr)
        print("    Ornek: python decode_token.py -f original_user_token.txt -o sonuc.json", file=sys.stderr)
        sys.exit(1)

    decoder = PureCastleDecoder()
    try:
        result = decoder.decode_token(token)
        
        if args.json:
            print(json.dumps(result, indent=2, ensure_ascii=False))
        else:
            print_human_readable_report(result)

        if args.output:
            with open(args.output, "w", encoding="utf-8") as out_f:
                json.dump(result, out_f, indent=2, ensure_ascii=False)
            print(f"[+] Detayli ve okunabilir tum metrikler JSON olarak kaydedildi: {args.output}")

    except Exception as e:
        print(f"[-] Token cozme hatasi: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
