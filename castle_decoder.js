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

const METRIC_LABELS_V2 = {
    1: ["token_id", "Token Tanici"],
    8: ["operating_system", "Isletim Sistemi"],
    11: ["arch_bits", "Mimari (bit)"],
    26: ["rendering_engine", "Rendering Motoru"],
    60: ["gpu_renderer", "GPU Isleyici (Renderer)"],
    63: ["user_agent", "Kullanici Ajani (User-Agent)"],
    67: ["locale", "Dil / Yerel Ayar"],
    101: ["browser_name", "Tarayici Adi"],
    103: ["browser_vendor", "Tarayici Ureticisi"],
    135: ["canvas_hash", "Canvas Parmak Izi"],
    143: ["audio_hash", "Ses Parmak Izi"],
    161: ["language", "Dil"],
    224: ["timezone", "Saat Dilimi"],
    248: ["browser_version", "Tarayici Surumu"],
    260: ["origin_url", "Kaynak URL"],
    293: ["accept_languages", "Kabul Edilen Diller"],
    308: ["page_title", "Sayfa Basligi"],
    332: ["gpu_vendor", "GPU Ureticisi"],
    352: ["screen_orientation", "Ekran Yonu"],
    366: ["platform", "Platform"],
    368: ["architecture", "Mimari"],
    406: ["client_ip_address", "IP Adresi"],
    520: ["site_domain", "Site Domaini"],
    622: ["session_id", "Oturum Kimligi"],
    643: ["navigation_type", "Navigasyon Tipi"],
    668: ["device_uuid", "Cihaz UUID"],
};

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

    // 6. V2: lr() kodlu stringleri coz, IP donustur
    if (isV2) {
        for (let i = 0; i < cleaned.length; i++) {
            cleaned[i] = _lrDecodeValue(cleaned[i]);
        }
        if (cleaned.length > 406 && typeof cleaned[406] === 'number') {
            cleaned[406] = _uint32ToIp(cleaned[406]);
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

    // 8. Versiyona gore alan cikarimi
    const labels = isV2 ? METRIC_LABELS_V2 : METRIC_LABELS;
    const labeled = {};
    for (const [idx, [slug, title]] of Object.entries(labels)) {
        const i = parseInt(idx);
        if (i < cleaned.length) {
            labeled[slug] = { index: i, title: title, value: cleaned[i] };
        }
    }

    let clientOs, clientIp, browserBuild, deviceId, userAgent, gpuRenderer;
    let timezone, locale, pageTitle, originUrl, sessionId, platform;

    if (isV2) {
        clientOs = m(8, "Bilinmiyor");
        clientIp = m(406, "Bilinmiyor");
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
        labeled_metrics: labeled,
        raw_metrics_array: cleaned
    };
}
