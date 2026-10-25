// Castle Anti-Bot Token Deobfuscator — Client-Side JavaScript Decoder
// decode_token.py'nin %100 tarayıcı tabanlı portu (sunucu gerektirmez)

const METRIC_LABELS = {
    0: ["feature_flags", "Özellik Bayrağı / Mod"],
    1: ["screen_width", "Ekran Genişliği (px)"],
    2: ["screen_height", "Ekran Yüksekliği (px)"],
    6: ["canvas_2d_hash", "Canvas 2D Grafik Parmak İzi"],
    8: ["audio_oscillator_hash", "AudioContext Osilatör İmzası"],
    9: ["color_depth", "Renk Derinliği (bit)"],
    11: ["webgl_vendor_code", "WebGL Donanım Sağlayıcı Kodu"],
    16: ["device_pixel_ratio", "Cihaz Piksel Oranı (DPR)"],
    22: ["webdriver_active", "WebDriver Aktif mi (Bot İmzası)"],
    40: ["screen_color_gamut", "Ekran Renk Gamı İmzası"],
    44: ["automation_detected", "Otomasyon / Bot Tespiti"],
    59: ["operating_system", "İşletim Sistemi (OS)"],
    61: ["interaction_timing", "Kullanıcı Etkileşim Zamanlamaları"],
    86: ["webgl_renderer_hash", "WebGL Grafik İşleyici İmzası"],
    143: ["headless_browser", "Headless (Görünmez) Tarayıcı Tespiti"],
    151: ["devtools_opened", "Geliştirici Araçları (DevTools) Açık mı"],
    163: ["device_hardware_guid", "Cihaz / Donanım Benzersiz Kimliği (GUID)"],
    383: ["cdp_protocol_active", "Chrome DevTools Protokolü (CDP) Tespiti"],
    406: ["client_ip_address", "İstemci Genel IP Adresi (Public IP)"],
    551: ["browser_build_version", "Tarayıcı Derleme Sürümü (Build Version)"]
};

const METRIC_INFO_V2 = {
    0: ["config_flags", "Yapılandırma Bayrağı", "token"],
    1: ["token_name", "Token Tanıcı", "token"],
    2: ["protocol_ver", "Protokol Parametresi", "token"],
    4: ["session_fp", "Oturum Parmak İzi", "fingerprint"],
    5: ["metric_mode", "Metrik Modu", "token"],
    6: ["canvas_2d_hash", "Canvas 2D Hash", "fingerprint"],
    7: ["system_hash", "Sistem Hash", "fingerprint"],
    8: ["os_name", "İşletim Sistemi", "system"],
    9: ["os_hash", "İS Ailesi Hash", "fingerprint"],
    10: ["os_ver_hash", "İS Sürüm Hash", "fingerprint"],
    11: ["arch_bits", "Mimari Bit Sayısı", "system"],
    12: ["hw_fp", "Donanım Parmak İzi", "fingerprint"],
    13: ["cpu_hash", "İşlemci Hash", "fingerprint"],
    14: ["mem_hash", "Bellek Hash", "fingerprint"],
    15: ["depth_hash", "Renk Derinliği Hash", "fingerprint"],
    16: ["resolution_pair", "Çözünürlük Hash Çifti", "screen"],
    17: ["pixel_ratio", "Piksel Oranı Hash", "screen"],
    18: ["tz_hash", "Saat Dilimi Hash", "fingerprint"],
    19: ["tz_offset_raw", "Zaman Dilimi Ofseti", "system"],
    20: ["screen_dim", "Ekran Boyutu", "screen"],
    22: ["webgl_hash_1", "WebGL Hash 1", "fingerprint"],
    23: ["webgl_hash_2", "WebGL Hash 2", "fingerprint"],
    24: ["media_cap_1", "Medya Oynatma Yeteneği 1", "media"],
    25: ["castle_pubkey", "Castle Açık Anahtar", "token"],
    26: ["render_engine", "Rendering Motoru", "browser"],
    27: ["engine_hash", "Motor Hash", "fingerprint"],
    28: ["engine_version", "Motor Sürümü", "browser"],
    36: ["render_flag", "Rendering Bayrağı", "browser"],
    41: ["screen_flag", "Ekran Bayrağı", "screen"],
    43: ["timing_val", "Zamanlama Değeri", "event"],
    44: ["env_hash", "Ortam Hash", "fingerprint"],
    52: ["render_mode", "Render Modu", "browser"],
    53: ["screen_val", "Ekran Değeri", "screen"],
    60: ["gpu_renderer", "GPU İşleyici", "browser"],
    61: ["gpu_score", "GPU Skor Değeri", "browser"],
    63: ["user_agent", "User-Agent", "browser"],
    67: ["locale", "Dil / Yerel Ayar", "browser"],
    68: ["cookie_flag", "Çerez Bayrağı", "browser"],
    72: ["storage_pair", "Depolama Hash Çifti", "fingerprint"],
    75: ["hw_concurrency", "Donanım Eşleştirme", "system"],
    79: ["session_flag", "Oturum Bayrağı", "session"],
    80: ["request_id", "İstek Kimliği", "session"],
    83: ["audio_val", "Ses Değeri", "media"],
    88: ["speech_code", "Konuşma API Kodu", "media"],
    96: ["touch_points", "Dokunmatik Noktası", "event"],
    97: ["touch_val", "Dokunmatik Değeri", "event"],
    98: ["event_data", "Olay Verisi", "event"],
    101: ["browser_name", "Tarayıcı Adı", "browser"],
    103: ["browser_vendor", "Tarayıcı Üreticisi", "browser"],
    106: ["vis_flag", "Görünürlük Bayrağı", "screen"],
    107: ["visibility", "Sayfa Görünürlüğü", "screen"],
    109: ["shader_hash_str", "WebGL Shader Hash", "fingerprint"],
    111: ["font_metric_hash", "Font Ölçüm Hash", "fingerprint"],
    116: ["css_selector_fp", "CSS Seçici Parmak İzi", "fingerprint"],
    117: ["error_probe_type", "Hata Probu: Tip", "probe"],
    118: ["probe_na", "Prob Sonucu (N/A)", "probe"],
    127: ["perf_val", "Performans Değeri", "event"],
    135: ["canvas_fp", "Canvas Parmak İzi", "fingerprint"],
    137: ["media_cap_2", "Medya Oynatma Yeteneği 2", "media"],
    139: ["webgl_fp", "WebGL Parmak İzi", "fingerprint"],
    140: ["webgl_delta", "WebGL Delta Değeri", "fingerprint"],
    143: ["audio_fp", "Ses Parmak İzi", "fingerprint"],
    145: ["timer_val", "Zamanlayıcı Değeri", "event"],
    148: ["geo_code", "Coğrafi Kod", "system"],
    149: ["geo_hash", "Coğrafi Hash", "fingerprint"],
    152: ["intl_val", "Uluslararası Değer", "system"],
    154: ["intl_id", "Uluslararası Kimlik", "system"],
    159: ["date_val", "Tarih Değeri", "system"],
    161: ["language", "Dil Kodu", "system"],
    165: ["main_flag", "Ana Bayrak", "token"],
    166: ["date_probe", "Tarih Probu (TZ Testi)", "probe"],
    178: ["analytics_code", "Analitik Kodu", "token"],
    180: ["proxy_pair", "Proxy Hash Çifti", "fingerprint"],
    182: ["proxy_val", "Proxy Değeri", "fingerprint"],
    189: ["api_code", "API Kodu", "browser"],
    192: ["iterator_val", "Iterator Değeri", "fingerprint"],
    194: ["generator_pair", "Generator Hash Çifti", "fingerprint"],
    196: ["event_flag", "Olay Bayrağı", "event"],
    203: ["module_val", "Modül Değeri", "fingerprint"],
    205: ["module_val_2", "Modül Değeri 2", "fingerprint"],
    207: ["probe_flag", "Prob Bayrağı", "probe"],
    214: ["api_mode", "API Modu", "browser"],
    215: ["ua_brands", "UA Marka Bilgisi (JSON)", "browser"],
    217: ["ua_subcode", "UA Alt Kodu", "browser"],
    221: ["nav_code", "Navigator Kodu", "browser"],
    224: ["timezone", "Saat Dilimi", "system"],
    226: ["tz_val", "Saat Dilimi Değeri", "system"],
    230: ["short_code", "Kısa Kod", "token"],
    233: ["format_val", "Format Değeri", "fingerprint"],
    235: ["gpu_renderer_dup", "GPU İşleyici (Kopya)", "browser"],
    239: ["fp_hex_1", "Parmak İzi Hex 1", "fingerprint"],
    240: ["webgl_flag", "WebGL Bayrağı", "fingerprint"],
    242: ["browser_ver_detail", "Tarayıcı Sürümü (Detay)", "browser"],
    244: ["error_probe_prop", "Hata Probu: Property", "probe"],
    247: ["display_type", "Görüntü Tipi", "screen"],
    248: ["browser_version", "Tarayıcı Sürümü", "browser"],
    252: ["screen_px", "Ekran Piksel Değeri", "screen"],
    253: ["network_flag", "Ağ Bayrağı", "network"],
    260: ["origin_url", "Kaynak URL", "network"],
    269: ["perf_timing", "Performans Zamanlaması", "event"],
    272: ["perf_code", "Performans Kodu", "event"],
    280: ["active_flag", "Aktiflik Bayrağı", "session"],
    284: ["engine_ver_dup", "Motor Sürümü (Kopya)", "browser"],
    293: ["accept_langs", "Kabul Edilen Diller", "browser"],
    303: ["sw_code", "ServiceWorker Kodu", "browser"],
    308: ["page_title", "Sayfa Başlığı", "network"],
    311: ["page_code", "Sayfa Kodu", "network"],
    316: ["adv_flag", "Gelişmiş Bayrak", "probe"],
    324: ["os_arch", "İS + Mimari Birleşik", "system"],
    325: ["timing_val_2", "Zamanlama Değeri 2", "event"],
    327: ["timing_val_3", "Zamanlama Değeri 3", "event"],
    332: ["gpu_vendor", "GPU Üreticisi", "browser"],
    334: ["color_depth", "Renk Derinliği", "screen"],
    341: ["last_event", "Son Olay Tipi", "event"],
    342: ["event_code", "Olay Kodu", "event"],
    343: ["event_timing", "Olay Zamanlaması", "event"],
    352: ["screen_orient", "Ekran Yönü", "screen"],
    353: ["orient_delta", "Yön Deltası", "screen"],
    359: ["protocol", "Protokol", "network"],
    363: ["perf_val_2", "Performans Değeri 2", "event"],
    365: ["encoded_val", "Kodlu Değer", "token"],
    366: ["platform", "Platform", "system"],
    367: ["platform_sub", "Platform Alt Kodu", "system"],
    368: ["architecture", "Mimari", "system"],
    373: ["crypto_val", "Kripto Değeri", "fingerprint"],
    374: ["hw_flag", "Donanım Bayrağı", "system"],
    380: ["hw_val", "Donanım Değeri", "system"],
    383: ["cdp_flag", "CDP Protokol Bayrağı", "probe"],
    391: ["selenium_code", "Selenium Kodu", "probe"],
    395: ["headless_code", "Headless Kodu", "probe"],
    396: ["headless_val", "Headless Değeri", "probe"],
    397: ["resolution_flag", "Çözünürlük Bayrağı", "screen"],
    398: ["resolution_pair", "Çözünürlük Hash Çifti", "screen"],
    402: ["short_code_2", "Kısa Kod 2", "token"],
    403: ["net_timing", "Ağ Zamanlaması", "event"],
    406: ["ip_hash", "IP Bölgesi Hash", "fingerprint"],
    416: ["build_id", "Yapı Kimliği (Build ID)", "browser"],
    418: ["build_val", "Yapı Değeri", "browser"],
    419: ["error_probe_inv", "Hata Probu: Invocation", "probe"],
    427: ["misc_flag", "Çeşitli Bayrak", "probe"],
    432: ["misc_val", "Çeşitli Değer", "event"],
    437: ["fp_hex_2", "Parmak İzi Hex 2", "fingerprint"],
    438: ["feature_flags_bin", "Özellik Bayrak Dizisi", "probe"],
    444: ["misc_val_2", "Çeşitli Değer 2", "event"],
    448: ["behavior_code", "Davranış Kodu", "event"],
    458: ["media_cap_3", "Medya Oynatma Yeteneği 3", "media"],
    463: ["screen_px_2", "Ekran Piksel Değeri 2", "screen"],
    466: ["short_flag", "Kısa Bayrak", "token"],
    469: ["fp_hex_3", "Parmak İzi Hex 3", "fingerprint"],
    471: ["perf_val_3", "Performans Değeri 3", "event"],
    473: ["client_ip", "İstemci IP Adresi", "network"],
    482: ["fp_hex_4", "Parmak İzi Hex 4", "fingerprint"],
    483: ["perf_val_4", "Performans Değeri 4", "event"],
    485: ["misc_val_3", "Çeşitli Değer 3", "event"],
    490: ["intl_code", "Intl Kodu", "system"],
    492: ["fp_hex_5", "Parmak İzi Hex 5", "fingerprint"],
    496: ["adv_flag_2", "Gelişmiş Bayrak 2", "probe"],
    502: ["webrtc_flag", "WebRTC Bayrağı", "probe"],
    517: ["api_code_2", "API Kodu 2", "browser"],
    520: ["site_domain", "Site Alan Adı", "network"],
    523: ["site_val", "Site Değeri", "network"],
    529: ["shader_source", "WebGL Shader Kodu", "probe"],
    530: ["shader_val", "Shader Değeri", "probe"],
    533: ["perf_val_5", "Performans Değeri 5", "event"],
    541: ["nav_code_2", "Navigasyon Kodu", "session"],
    542: ["url_path", "URL Yolu", "network"],
    543: ["url_flag", "URL Bayrağı", "network"],
    550: ["config_code", "Yapılandırma Kodu", "token"],
    561: ["api_code_3", "API Kodu 3", "browser"],
    567: ["behavior_val", "Davranış Değeri", "event"],
    568: ["behavior_val_2", "Davranış Değeri 2", "event"],
    577: ["short_flag_2", "Kısa Bayrak 2", "token"],
    579: ["proto_probe", "Prototip Döngü Probu", "probe"],
    581: ["behavior_flag", "Davranış Bayrağı", "event"],
    588: ["timing_delta", "Zamanlama Deltası", "event"],
    589: ["timing_val_4", "Zamanlama Değeri 4", "event"],
    590: ["timing_flag", "Zamanlama Bayrağı", "event"],
    599: ["fp_hex_6", "Parmak İzi Hex 6", "fingerprint"],
    609: ["secondary_ts", "İkincil Zaman Damgası", "session"],
    617: ["session_code", "Oturum Kodu", "session"],
    619: ["stack_probe", "Yığın Derinlik Probu", "probe"],
    622: ["session_id", "Oturum Kimliği", "session"],
    629: ["session_val", "Oturum Değeri", "session"],
    631: ["session_id_dup", "Oturum Kimliği (Kopya)", "session"],
    632: ["session_flag", "Oturum Bayrağı", "session"],
    638: ["ua_dup", "User-Agent (Kopya)", "browser"],
    643: ["nav_type", "Navigasyon Tipi", "session"],
    645: ["ua_brands_short", "UA Marka (Kısa JSON)", "browser"],
    647: ["fp_hex_7", "Parmak İzi Hex 7", "fingerprint"],
    655: ["final_val", "Son Zamanlama", "event"],
    658: ["screen_val_2", "Ekran Değeri", "screen"],
    659: ["webrtc_proto", "WebRTC Protokolü", "probe"],
    661: ["webrtc_val", "WebRTC Değeri", "probe"],
    665: ["zero_flags", "Sıfır Bayrak Dizisi", "probe"],
    668: ["device_uuid", "Cihaz UUID", "session"],
    670: ["short_hash_1", "Kısa Hash 1", "fingerprint"],
    671: ["final_timing", "Son Zamanlama Değeri", "event"],
    673: ["final_code", "Son Kod Değeri", "token"],
    674: ["final_val_2", "Son Değer 2", "event"],
    677: ["final_timing_2", "Son Zamanlama 2", "event"],
    679: ["short_hash_2", "Kısa Hash 2", "fingerprint"],
};

const FONT_PROBE_START = 683;
const FONT_PROBE_END = 764;

const CATEGORY_TR = {
    token: "Token/Protokol", system: "Sistem", browser: "Tarayıcı", screen: "Ekran",
    fingerprint: "Parmak İzi", media: "Medya", probe: "Prob/Test",
    network: "Ağ", session: "Oturum", event: "Olay", font: "Font Testi"
};

function _formatValue(idx, val, isV2) {
    if (val === null || val === undefined) return "boş";
    if (val === true) return "Evet";
    if (val === false) return "Hayır";
    if (typeof val === 'number') {
        if (val === 165) return "-- (ölçülmedi)";
        if (val === 161) return "-- (mevcut değil)";
        if (val === 173) return "-- (ayrılmış)";
        if (Math.abs(val) > 100000000) return "0x" + (val >>> 0).toString(16).toUpperCase().padStart(8, '0');
        return String(val);
    }
    if (typeof val === 'string') {
        if (val.length > 300) return val.substring(0, 300) + "...";
        return val;
    }
    if (Array.isArray(val)) {
        return "[" + val.map(v => typeof v === 'number' && Math.abs(v) > 100000 ? "0x" + (v >>> 0).toString(16).toUpperCase().padStart(8, '0') : String(v)).join(", ") + "]";
    }
    return String(val);
}

function _getMetricInfo(idx, val, isV2) {
    if (isV2 && METRIC_INFO_V2[idx]) {
        const [slug, label, cat] = METRIC_INFO_V2[idx];
        return { label, category: CATEGORY_TR[cat] || cat, value: _formatValue(idx, val, isV2) };
    }
    if (idx >= FONT_PROBE_START && idx <= FONT_PROBE_END) {
        let fontStatus = "Yüklü Değil";
        if (typeof val === 'string' && val.length >= 4) {
            try {
                let p = val; while (p.length % 4 !== 0) p += '=';
                const b = atob(p);
                const hex = Array.from(b, c => c.charCodeAt(0).toString(16).padStart(2, '0')).join('');
                if (hex !== 'c3c3c3c3' && hex !== 'f7444444') fontStatus = "Yüklü (" + hex + ")";
            } catch (e) {}
        }
        return { label: "Font Testi #" + (idx - FONT_PROBE_START), category: CATEGORY_TR.font, value: fontStatus };
    }
    let label, cat;
    if (val === null || val === undefined) { label = "Boş Alan"; cat = "token"; }
    else if (typeof val === 'boolean') { label = "Bayrak"; cat = "probe"; }
    else if (typeof val === 'number') {
        if (val === 165 || val === 161 || val === 173) { label = "Ölçülmedi/Ayrılmış"; cat = "token"; }
        else if (Math.abs(val) > 100000000) { label = "Parmak İzi Bileşeni"; cat = "fingerprint"; }
        else if (Math.abs(val) > 999) { label = "Sayısal Değer"; cat = "event"; }
        else { label = "Parametre"; cat = "system"; }
    }
    else if (typeof val === 'string') { label = "Metin Değeri"; cat = "browser"; }
    else if (Array.isArray(val)) { label = "Hash Çifti"; cat = "fingerprint"; }
    else { label = "Değer"; cat = "token"; }
    return { label, category: CATEGORY_TR[cat] || cat, value: _formatValue(idx, val, isV2) };
}

// --- Yardımcı Fonksiyonlar ---

function _b64ToBytes(b64) {
    const bin = atob(b64);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
}

function _bytesToB64(bytes) {
    let bin = '';
    for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
    return btoa(bin);
}

// --- 1. Pn Timestamp Şifresi Tersine Çevirici ---

function _invertPnWord(val) {
    let e = (val - 6396) & 0xFFFF;
    e = ((e >>> 10) | ((e << 6) & 0xFFFF)) & 0xFFFF;
    e = ((e >>> 15) | ((e << 1) & 0xFFFF)) & 0xFFFF;
    return String.fromCharCode(e);
}

function _recoverTimestampV1(raw) {
    let result = '';
    for (let i = 0; i + 1 < raw.length; i += 2) {
        result += _invertPnWord((raw[i] << 8) | raw[i + 1]);
    }
    return result;
}

function _recoverTimestampV2(raw) {
    // lr() inverse: ROR2 -> SUB(0xC481) -> ROR1
    let result = '';
    for (let i = 0; i + 1 < raw.length; i += 2) {
        let v = (raw[i] << 8) | raw[i + 1];
        v = ((v >>> 2) | (v << 14)) & 0xFFFF;
        v = (v - 0xC481) & 0xFFFF;
        v = ((v >>> 1) | (v << 15)) & 0xFFFF;
        result += String.fromCharCode(v);
    }
    return result;
}

function _recoverTimestampKey(keyB64) {
    let padded = keyB64;
    while (padded.length % 4 !== 0) padded += '=';
    const raw = _b64ToBytes(padded);
    const v1 = _recoverTimestampV1(raw);
    if (/^\d{13}$/.test(v1)) return v1;
    const v2 = _recoverTimestampV2(raw);
    if (/^\d{13}$/.test(v2)) return v2;
    return v1;
}

// --- 2. Castle Akış Şifresi Çözücü (FNV-1a + Xorshift32) ---

function _decryptStream(ciphertext, keyStr) {
    let h = 0xBC0D78D5;
    for (let i = 0; i < keyStr.length; i++) {
        h = Math.imul(h ^ keyStr.charCodeAt(i), 0x01000193) >>> 0;
    }
    if (h === 0) h = 0x9E3779B9;

    let state = (h ^ 0x989BDC08) >>> 0;
    const out = new Uint8Array(ciphertext.length);

    for (let i = 0; i < ciphertext.length; i++) {
        if ((i & 3) === 0) {
            state = (state + i + 0x155FACDB) >>> 0;
            state = (state + 0x989BDC08) >>> 0;
            state = (state ^ (state << 13)) >>> 0;
            state = (state ^ (state >>> 17)) >>> 0;
            state = (state ^ (state << 5)) >>> 0;
            state = (state + 0xA4A5C55B) >>> 0;
        }
        out[i] = ciphertext[i] ^ ((state >>> ((i & 3) << 3)) & 0xFF);
    }
    return out;
}

// --- 2b. V2 Castle Akış Şifresi (FNV-1a 0x751DAC79 + Xorshift32) ---

function _decryptStreamV2(ciphertext, keyStr) {
    let h = 0x751DAC79;
    for (let i = 0; i < keyStr.length; i++) {
        h = Math.imul(h ^ keyStr.charCodeAt(i), 0x01000193) >>> 0;
    }
    if (h === 0) h = 0x9E3779B9;

    let state = (h ^ 0x973D8749) >>> 0;
    const out = new Uint8Array(ciphertext.length);

    for (let i = 0; i < ciphertext.length; i++) {
        if ((i & 3) === 0) {
            state = (state + i + 0x7F039DDA) >>> 0;
            state = (state + 0x973D8749) >>> 0;
            state = (state ^ (state << 13)) >>> 0;
            state = (state ^ (state >>> 17)) >>> 0;
            state = (state ^ (state << 5)) >>> 0;
            state = (state + 0x93CF09BD) >>> 0;
        }
        out[i] = ciphertext[i] ^ ((state >>> ((i & 3) << 3)) & 0xFF);
    }
    return out;
}

// --- 3. İkili Protokol Ayrıştırıcı (LEB128 Varint + 11 Tip) ---

function _readVarint(data, off) {
    let r = 0, s = 0;
    while (true) {
        if (off >= data.length) throw new Error("Varint okunurken beklenmeyen veri sonu");
        const b = data[off++];
        r = (r | ((b & 0x7F) << s)) >>> 0;
        if (!(b & 0x80)) return [r, off];
        s += 7;
    }
}

function _readItem(data, off) {
    if (off >= data.length) throw new Error("Eleman etiketi okunurken veri sonu");
    const tag = data[off++];

    if (tag === 0) return [null, off];
    if (tag === 5) return [false, off];
    if (tag === 6) return [true, off];

    if (tag === 1 || tag === 8) {
        let len; [len, off] = _readVarint(data, off);
        let s = '';
        for (let i = 0; i < len; i++) {
            s += String.fromCharCode(data[off] | (data[off + 1] << 8));
            off += 2;
        }
        if (tag === 8) { try { return [JSON.parse(s), off]; } catch {} }
        return [s, off];
    }

    if (tag === 2) {
        let len; [len, off] = _readVarint(data, off);
        const slice = data.slice(off, off + len); off += len;
        return [_bytesToB64(slice), off];
    }

    if (tag === 3) {
        const v = (data[off] | (data[off+1] << 8) | (data[off+2] << 16) | (data[off+3] << 24)) >>> 0;
        return [v, off + 4];
    }

    if (tag === 4) {
        const buf = new ArrayBuffer(8);
        const dv = new DataView(buf);
        for (let i = 0; i < 8; i++) dv.setUint8(i, data[off + i]);
        return [dv.getFloat64(0, false), off + 8];
    }

    if (tag === 7) {
        let len; [len, off] = _readVarint(data, off);
        const arr = [];
        for (let i = 0; i < len; i++) {
            let item; [item, off] = _readItem(data, off);
            arr.push(item);
        }
        return [arr, off];
    }

    if (tag === 9) {
        let len; [len, off] = _readVarint(data, off);
        let s = '';
        for (let i = 0; i < len; i++) s += String.fromCharCode(data[off++]);
        return [s, off];
    }

    if (tag === 10) {
        let zz; [zz, off] = _readVarint(data, off);
        return [(zz & 1) ? -((zz >>> 1) + 1) : (zz >>> 1), off];
    }

    throw new Error("Bilinmeyen Castle protokol etiketi: " + tag);
}

function _deserialize(data) {
    let [total, off] = _readVarint(data, 0);
    const arr = [];
    for (let i = 0; i < total; i++) {
        let item; [item, off] = _readItem(data, off);
        arr.push(item);
    }
    return arr;
}

// --- 4. Metin Temizleme & Deobfuscation ---

function _cleanStr(s) {
    if (typeof s !== 'string' || !s) return s;
    if (/Windows|Mac|Linux|Android|iOS/.test(s)) {
        const m = s.match(/(Windows|Macintosh|Linux|Android|iOS)[a-zA-Z0-9_\-\s]*/);
        if (m) return m[0].includes('Windowsx86') ? 'Windows (x86_64)' : m[0];
    }
    if (s.includes('][') || s.includes('iv1ty') || s.includes('w3c')) {
        const m = s.match(/[a-f0-9]{8,}.*/);
        if (m) return m[0];
    }
    let c = '';
    for (const ch of s) {
        const code = ch.charCodeAt(0);
        if ((code >= 32 && code <= 126) || code >= 160) c += ch;
    }
    return c.trim() || s;
}

// --- 4b. V2 lr() Decode & IP Donusturucu ---

function _lrDecodeValue(s) {
    if (typeof s !== 'string' || s.length < 4) return s;
    let bin;
    try {
        let padded = s;
        while (padded.length % 4 !== 0) padded += '=';
        bin = atob(padded);
    } catch (_) { return s; }
    if (bin.length < 2 || bin.length % 2 !== 0) return s;
    let result = '';
    for (let i = 0; i < bin.length; i += 2) {
        let v = (bin.charCodeAt(i) << 8) | bin.charCodeAt(i + 1);
        v = ((v >>> 2) | (v << 14)) & 0xFFFF;
        v = (v - 0xC481) & 0xFFFF;
        v = ((v >>> 1) | (v << 15)) & 0xFFFF;
        result += String.fromCharCode(v);
    }
    for (let i = 0; i < result.length; i++) {
        const c = result.charCodeAt(i);
        if (c < 32 || c > 126) return s;
    }
    return result;
}

function _uint32ToIp(val) {
    if (typeof val !== 'number') return String(val);
    const v = val >>> 0;
    return ((v >>> 24) & 0xFF) + '.' + ((v >>> 16) & 0xFF) + '.' + ((v >>> 8) & 0xFF) + '.' + (v & 0xFF);
}

function _isBoolTrue(arr, idx) {
    return idx < arr.length && arr[idx] === true;
}

// --- 5. Ana Decode Fonksiyonu ---

function decodeCastleToken(tokenStr) {
    tokenStr = tokenStr.trim();
    const pipeIdx = tokenStr.indexOf('|');
    if (pipeIdx < 1 || pipeIdx === tokenStr.length - 1) {
        throw new Error("Geçersiz Castle token biçimi: Token 'prefix|payload' formatında olmalıdır.");
    }
    const parts = [tokenStr.substring(0, pipeIdx), tokenStr.substring(pipeIdx + 1)];

    // Base64 decode
    let b64 = parts[1].trim();
    while (b64.length % 4 !== 0) b64 += '=';
    const raw = _b64ToBytes(b64);

    // 1. Şifrelenmiş zaman damgası anahtarını çıkar
    const keyLen = raw[0] | (raw[1] << 8);
    let keyB64 = '';
    for (let i = 2; i < 2 + keyLen; i++) keyB64 += String.fromCharCode(raw[i]);
    const tsStr = _recoverTimestampKey(keyB64);
    const tsMs = /^\d+$/.test(tsStr) ? parseInt(tsStr) : 0;

    // 2. 24 baytlık güvenlik başlığı
    const hOff = 2 + keyLen;
    const seg1 = ((raw[hOff] << 24) | (raw[hOff+1] << 16) | (raw[hOff+2] << 8) | raw[hOff+3]) >>> 0;
    const seg2 = ((raw[hOff+4] << 24) | (raw[hOff+5] << 16) | (raw[hOff+6] << 8) | raw[hOff+7]) >>> 0;
    let checksum = '';
    for (let i = 8; i < 24; i++) checksum += raw[hOff + i].toString(16).padStart(2, '0');

    // 3. Versiyon tespiti ve sifre cozme (V1/V2 otomatik algilama)
    const ciphertext = raw.slice(hOff + 24);
    const isV2 = parts[0] !== 'uq1seNrd';
    let decrypted, decompressed;
    try {
        decrypted = isV2 ? _decryptStreamV2(ciphertext, tsStr) : _decryptStream(ciphertext, tsStr);
        decompressed = pako.inflateRaw(decrypted);
    } catch (_) {
        decrypted = isV2 ? _decryptStream(ciphertext, tsStr) : _decryptStreamV2(ciphertext, tsStr);
        decompressed = pako.inflateRaw(decrypted);
    }

    // 5. Ikili protokolu ayristir
    const metrics = _deserialize(decompressed);
    const cleaned = metrics.map(_cleanStr);

    // 6. V2: lr() kodlu stringleri coz
    if (isV2) {
        for (let i = 0; i < cleaned.length; i++) {
            cleaned[i] = _lrDecodeValue(cleaned[i]);
        }
    }

    const m = (i, def) => cleaned.length > i && cleaned[i] != null ? cleaned[i] : def;

    // 7. Bot tespiti: sadece gercek boolean True degerleri sayilir
    const botDetected = _isBoolTrue(cleaned, 44);
    const webdriver = _isBoolTrue(cleaned, 22);
    const headless = _isBoolTrue(cleaned, 143);
    const devtools = _isBoolTrue(cleaned, 151);
    const cdp = _isBoolTrue(cleaned, 383);
    const isBot = botDetected || webdriver || cdp;

    const isoUtc = tsMs ? new Date(tsMs).toISOString() : "Bilinmiyor";
    const localTime = tsMs ? new Date(tsMs).toLocaleString('tr-TR') : "Bilinmiyor";

    const fontSigs = cleaned.length > 668 ? cleaned.slice(668) : [];

    // 8. Versiyona gore alan cikarimi ve formatlama
    const formattedMetrics = [];
    for (let i = 0; i < cleaned.length; i++) {
        const info = _getMetricInfo(i, cleaned[i], isV2);
        formattedMetrics.push({
            index: i,
            label: info.label,
            category: info.category,
            type: cleaned[i] === null ? 'null' : Array.isArray(cleaned[i]) ? 'array' : typeof cleaned[i],
            value: info.value,
            raw: cleaned[i]
        });
    }

    let clientOs, clientIp, browserBuild, deviceId, userAgent, gpuRenderer;
    let timezone, locale, pageTitle, originUrl, sessionId, platform;

    if (isV2) {
        clientOs = m(8, "Bilinmiyor");
        clientIp = m(473, "Bilinmiyor");
        const browserName = m(101, "");
        const browserVer = m(248, "Bilinmiyor");
        browserBuild = browserName ? browserName + " " + browserVer : browserVer;
        deviceId = m(668, "Bilinmiyor");
        userAgent = m(63, "Bilinmiyor");
        gpuRenderer = m(60, "Bilinmiyor");
        timezone = m(224, "Bilinmiyor");
        locale = m(67, "Bilinmiyor");
        pageTitle = m(308, "");
        originUrl = m(260, "");
        sessionId = m(622, "Bilinmiyor");
        platform = (m(366, "") + " " + m(368, "")).trim();
    } else {
        clientOs = m(59, "Bilinmiyor");
        clientIp = m(406, "Bilinmiyor");
        browserBuild = m(551, "Bilinmiyor");
        deviceId = m(163, "Bilinmiyor");
        userAgent = "Bilinmiyor";
        gpuRenderer = "Bilinmiyor";
        timezone = "Bilinmiyor";
        locale = "Bilinmiyor";
        pageTitle = "";
        originUrl = "";
        sessionId = "Bilinmiyor";
        platform = m(1, 0) + "x" + m(2, 0);
    }

    return {
        status: "success",
        token_version: parts[0],
        security_verdict: isBot ? "FLAGGED_AS_BOT" : "VERIFIED_GENUINE_HUMAN",
        security_verdict_tr: isBot ? "SUPHELI / BOT (Tespit Edildi)" : "GUVENLI / GERCEK KULLANICI (Temiz)",
        timestamp: {
            raw_timestamp_ms: tsMs,
            timestamp_str: String(tsMs),
            iso_utc: isoUtc,
            local_time: localTime
        },
        security_header: {
            segment_1_length: seg1,
            segment_2_length: seg2,
            total_ciphertext_bytes: ciphertext.length,
            decompressed_payload_bytes: decompressed.length,
            auth_checksum_signature: checksum
        },
        metrics_summary: {
            total_metrics_count: cleaned.length,
            client_ip: clientIp,
            client_os: clientOs,
            browser_build: browserBuild,
            device_id_fingerprint: deviceId,
            user_agent: userAgent,
            gpu_renderer: gpuRenderer,
            timezone: timezone,
            locale: locale,
            page_title: pageTitle,
            origin_url: originUrl,
            session_id: sessionId,
            platform: platform,
            bot_flags: {
                webdriver_active: webdriver,
                automation_detected: botDetected,
                headless_detected: headless,
                devtools_open: devtools,
                cdp_active: cdp,
                consistency_score: isBot ? "Low (Bot Detected)" : "High (Valid Human Environment)"
            }
        },
        categories: {
            network: { ip: clientIp },
            device: {
                os: clientOs,
                browser_version: browserBuild,
                device_fingerprint: deviceId,
                user_agent: userAgent,
                gpu: gpuRenderer,
                timezone: timezone,
                locale: locale,
                platform: platform
            },
            bot_detection: {
                automation_detected: botDetected,
                webdriver_active: webdriver,
                headless_detected: headless,
                devtools_open: devtools,
                cdp_active: cdp
            },
            fingerprints: {
                canvas_hash: isV2 ? m(135, null) : m(6, null),
                audio_hash: isV2 ? m(143, null) : m(8, null),
                webgl_gpu_code: m(11, null),
                total_font_probes: fontSigs.length,
                unique_fonts_detected: new Set(fontSigs.map(String)).size
            }
        },
        formatted_metrics: formattedMetrics,
        raw_metrics_array: cleaned
    };
}
