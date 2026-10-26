// Castle Anti-Bot Token Deobfuscator — Client-Side JavaScript Decoder
// decode_token.py'nin %100 tarayici tabanli portu (sunucu gerektirmez)

const METRIC_LABELS = {
    0: ["feature_flags", "Ozellik Bayragi / Mod"],
    1: ["screen_width", "Ekran Genisligi (px)"],
    2: ["screen_height", "Ekran Yuksekligi (px)"],
    6: ["canvas_2d_hash", "Canvas 2D Grafik Parmak Izi"],
    8: ["audio_oscillator_hash", "AudioContext Osilator Imzasi"],
    9: ["color_depth", "Renk Derinligi (bit)"],
    11: ["webgl_vendor_code", "WebGL Donanim Saglayici Kodu"],
    16: ["device_pixel_ratio", "Cihaz Piksel Orani (DPR)"],
    22: ["webdriver_active", "WebDriver Aktif mi (Bot Imzasi)"],
    40: ["screen_color_gamut", "Ekran Renk Gami Imzasi"],
    44: ["automation_detected", "Otomasyon / Bot Tespiti"],
    59: ["operating_system", "Isletim Sistemi (OS)"],
    61: ["interaction_timing", "Kullanici Etkilesim Zamanlamalari"],
    86: ["webgl_renderer_hash", "WebGL Grafik Isleyici Imzasi"],
    143: ["headless_browser", "Headless (Gorunmez) Tarayici Tespiti"],
    151: ["devtools_opened", "Gelistirici Araclari (DevTools) Acik mi"],
    163: ["device_hardware_guid", "Cihaz / Donanim Benzersiz Kimligi (GUID)"],
    383: ["cdp_protocol_active", "Chrome DevTools Protokolu (CDP) Tespiti"],
    406: ["client_ip_address", "Istemci Genel IP Adresi (Public IP)"],
    551: ["browser_build_version", "Tarayici Derleme Surumu (Build Version)"]
};

const METRIC_INFO_V2 = {
    0: ["config_flags", "Yapilandirma Bayragi", "token"],
    1: ["token_name", "Token Tanici", "token"],
    2: ["protocol_ver", "Protokol Parametresi", "token"],
    3: ["init_perf_mark", "Baslangic Performans Izi", "event"],
    4: ["session_fp", "Oturum Parmak Izi", "fingerprint"],
    5: ["metric_mode", "Metrik Modu", "token"],
    6: ["canvas_2d_hash", "Canvas 2D Hash", "fingerprint"],
    7: ["system_hash", "Sistem Hash", "fingerprint"],
    8: ["os_name", "Isletim Sistemi", "system"],
    9: ["os_hash", "IS Ailesi Hash", "fingerprint"],
    10: ["os_ver_hash", "IS Surum Hash", "fingerprint"],
    11: ["arch_bits", "Mimari Bit Sayisi", "system"],
    12: ["hw_fp", "Donanim Parmak Izi", "fingerprint"],
    13: ["cpu_hash", "Islemci Hash", "fingerprint"],
    14: ["mem_hash", "Bellek Hash", "fingerprint"],
    15: ["depth_hash", "Renk Derinligi Hash", "fingerprint"],
    16: ["resolution_pair", "Cozunurluk Hash Cifti", "screen"],
    17: ["pixel_ratio", "Piksel Orani Hash", "screen"],
    18: ["tz_hash", "Saat Dilimi Hash", "fingerprint"],
    19: ["tz_offset_raw", "Zaman Dilimi Ofseti", "system"],
    20: ["screen_dim", "Ekran Boyutu", "screen"],
    21: ["screen_avail_top", "Ekran Kullanilabilir Ust Ofset", "screen"],
    22: ["webgl_hash_1", "WebGL Hash 1", "fingerprint"],
    23: ["webgl_hash_2", "WebGL Hash 2", "fingerprint"],
    24: ["media_cap_1", "Medya Oynatma Yetenegi 1", "media"],
    25: ["castle_pubkey", "Castle Acik Anahtar", "token"],
    26: ["render_engine", "Rendering Motoru", "browser"],
    27: ["engine_hash", "Motor Hash", "fingerprint"],
    28: ["engine_version", "Motor Surumu", "browser"],
    29: ["window_keys_pair", "Window Ozellik Listesi Hash Cifti", "fingerprint"],
    30: ["navigator_proto_pair", "Navigator Prototip Hash Cifti", "fingerprint"],
    31: ["document_proto_pair", "Document Prototip Hash Cifti", "fingerprint"],
    32: ["screen_proto_pair", "Screen Prototip Hash Cifti", "fingerprint"],
    33: ["history_proto_pair", "History Prototip Hash Cifti", "fingerprint"],
    34: ["location_hash_val", "Location Yapi Hash Degeri", "fingerprint"],
    35: ["dom_ready_state", "DOM Hazirlik Durumu", "browser"],
    36: ["render_flag", "Rendering Bayragi", "browser"],
    38: ["drm_widevine_probe", "DRM Widevine / EME Destegi", "media"],
    39: ["window_outer_delta", "Pencere Dis/Ic Boyut Farki", "screen"],
    40: ["perm_geolocation", "Izin: Konum (geolocation)", "probe"],
    41: ["screen_flag", "Ekran Bayragi", "screen"],
    42: ["perm_notifications", "Izin: Bildirimler (notifications)", "probe"],
    43: ["timing_val", "Zamanlama Degeri", "event"],
    44: ["env_hash", "Ortam Hash", "fingerprint"],
    45: ["math_constants_pair", "Math Sabitleri Hassasiyet Hash Cifti", "fingerprint"],
    46: ["worker_debugger_probe", "WebWorker Debugger Zamanlama Probu", "probe"],
    47: ["math_trig_pair", "Math Trigonometri Hash Cifti", "fingerprint"],
    48: ["error_stack_fmt", "Error Stack Bicim Kodu", "probe"],
    49: ["math_exp_log_pair", "Math Ustel/Logaritmik Hash Cifti", "fingerprint"],
    50: ["math_hyperbolic_pair", "Math Hiperbolik Fonksiyon Hash Cifti", "fingerprint"],
    51: ["intl_collator_pair", "Intl.Collator Yerel Hash Cifti", "fingerprint"],
    52: ["render_mode", "Render Modu", "browser"],
    53: ["screen_val", "Ekran Degeri", "screen"],
    54: ["intl_numfmt_pair", "Intl.NumberFormat Hash Cifti", "fingerprint"],
    55: ["intl_datefmt_pair", "Intl.DateTimeFormat Hash Cifti", "fingerprint"],
    56: ["intl_plural_pair", "Intl.PluralRules Hash Cifti", "fingerprint"],
    57: ["intl_reltime_pair", "Intl.RelativeTimeFormat Hash Cifti", "fingerprint"],
    58: ["intl_listfmt_pair", "Intl.ListFormat Hash Cifti", "fingerprint"],
    60: ["gpu_renderer", "GPU Isleyici", "browser"],
    61: ["gpu_score", "GPU Skor Degeri", "browser"],
    63: ["user_agent", "User-Agent", "browser"],
    66: ["webgl_params_pair", "WebGL Parametreler Hash Cifti", "fingerprint"],
    67: ["locale", "Dil / Yerel Ayar", "browser"],
    68: ["cookie_flag", "Cerez Bayragi", "browser"],
    69: ["perm_push", "Izin: Push Bildirimleri", "probe"],
    70: ["canvas_winding_probe", "Canvas Winding / Blending Kodu", "fingerprint"],
    71: ["canvas_text_pair", "Canvas measureText Hash Cifti", "fingerprint"],
    72: ["storage_pair", "Depolama Hash Cifti", "fingerprint"],
    73: ["canvas_emoji_pair", "Canvas Emoji Render Hash Cifti", "fingerprint"],
    74: ["canvas_gradient_pair", "Canvas Gradient Render Hash Cifti", "fingerprint"],
    75: ["hw_concurrency", "Donanim Eslestirme", "system"],
    76: ["svg_rect_pair", "SVG getClientRects Hash Cifti", "fingerprint"],
    77: ["dom_rect_pair", "DOM Element Boyut Hash Cifti", "fingerprint"],
    79: ["session_flag", "Oturum Bayragi", "session"],
    80: ["request_id", "Istek Kimligi", "session"],
    82: ["css_computed_pair", "getComputedStyle Ozellik Hash Cifti", "fingerprint"],
    83: ["audio_val", "Ses Degeri", "media"],
    84: ["css_system_colors_pair", "CSS Sistem Renkleri Hash Cifti", "fingerprint"],
    85: ["css_supports_pair", "CSS.supports Ozellik Hash Cifti", "fingerprint"],
    86: ["webgl_renderer_hash", "WebGL Grafik Isleyici Imzasi", "fingerprint"],
    87: ["font_unicode_pair", "Unicode Glif Genislik Hash Cifti", "font"],
    88: ["speech_code", "Konusma API Kodu", "media"],
    89: ["font_serif_pair", "Serif Font Ailesi Olcum Cifti", "font"],
    93: ["font_sans_pair", "Sans-Serif Font Ailesi Olcum Cifti", "font"],
    94: ["font_mono_pair", "Monospace Font Ailesi Olcum Cifti", "font"],
    95: ["font_system_ui_pair", "System-UI Font Olcum Cifti", "font"],
    96: ["touch_points", "Dokunmatik Noktasi", "event"],
    97: ["touch_val", "Dokunmatik Degeri", "event"],
    98: ["event_data", "Olay Verisi", "event"],
    101: ["browser_name", "Tarayici Adi", "browser"],
    103: ["browser_vendor", "Tarayici Ureticisi", "browser"],
    106: ["vis_flag", "Gorunurluk Bayragi", "screen"],
    107: ["visibility", "Sayfa Gorunurlugu", "screen"],
    109: ["shader_hash_str", "WebGL Shader Hash", "fingerprint"],
    111: ["font_metric_hash", "Font Olcum Hash", "fingerprint"],
    113: ["perm_midi", "Izin: MIDI Cihazlari", "probe"],
    114: ["storage_quota_est", "Depolama Kotasi Tahmini (StorageManager)", "system"],
    116: ["css_selector_fp", "CSS Secici Parmak Izi", "fingerprint"],
    117: ["error_probe_type", "Hata Probu: Tip", "probe"],
    118: ["probe_na", "Prob Sonucu (N/A)", "probe"],
    127: ["perf_val", "Performans Degeri", "event"],
    133: ["video_codec_h264", "Video Codec: H.264 Destegi", "media"],
    135: ["canvas_fp", "Canvas Parmak Izi", "fingerprint"],
    137: ["media_cap_2", "Medya Oynatma Yetenegi 2", "media"],
    139: ["webgl_fp", "WebGL Parmak Izi", "fingerprint"],
    140: ["webgl_delta", "WebGL Delta Degeri", "fingerprint"],
    143: ["audio_fp", "Ses Parmak Izi", "fingerprint"],
    144: ["media_devices_cnt", "Medya Aygitlari Sayisi (enumerateDevices)", "media"],
    145: ["timer_val", "Zamanlayici Degeri", "event"],
    148: ["geo_code", "Cografi Kod", "system"],
    149: ["geo_hash", "Cografi Hash", "fingerprint"],
    152: ["intl_val", "Uluslararasi Deger", "system"],
    154: ["intl_id", "Uluslararasi Kimlik", "system"],
    158: ["perm_camera", "Izin: Kamera (camera)", "probe"],
    159: ["date_val", "Tarih Degeri", "system"],
    161: ["language", "Dil Kodu", "system"],
    164: ["video_codec_vp9", "Video Codec: VP9 Destegi", "media"],
    165: ["main_flag", "Ana Bayrak", "token"],
    166: ["date_probe", "Tarih Probu (TZ Testi)", "probe"],
    176: ["video_codec_av1", "Video Codec: AV1 Destegi", "media"],
    178: ["analytics_code", "Analitik Kodu", "token"],
    180: ["proxy_pair", "Proxy Hash Cifti", "fingerprint"],
    182: ["proxy_val", "Proxy Degeri", "fingerprint"],
    189: ["api_code", "API Kodu", "browser"],
    192: ["iterator_val", "Iterator Degeri", "fingerprint"],
    194: ["generator_pair", "Generator Hash Cifti", "fingerprint"],
    196: ["event_flag", "Olay Bayragi", "event"],
    199: ["pointer_event_probe", "Pointer/Mouse Olay Probu", "event"],
    203: ["module_val", "Modul Degeri", "fingerprint"],
    205: ["module_val_2", "Modul Degeri 2", "fingerprint"],
    207: ["probe_flag", "Prob Bayragi", "probe"],
    210: ["perm_microphone", "Izin: Mikrofon (microphone)", "probe"],
    214: ["api_mode", "API Modu", "browser"],
    215: ["ua_brands", "UA Marka Bilgisi (JSON)", "browser"],
    217: ["ua_subcode", "UA Alt Kodu", "browser"],
    218: ["audio_sample_rate", "AudioContext Ornekleme Hizi (Hz)", "media"],
    221: ["nav_code", "Navigator Kodu", "browser"],
    224: ["timezone", "Saat Dilimi", "system"],
    226: ["tz_val", "Saat Dilimi Degeri", "system"],
    230: ["short_code", "Kisa Kod", "token"],
    233: ["format_val", "Format Degeri", "fingerprint"],
    235: ["gpu_renderer_dup", "GPU Isleyici (Kopya)", "browser"],
    239: ["fp_hex_1", "Parmak Izi Hex 1", "fingerprint"],
    240: ["webgl_flag", "WebGL Bayragi", "fingerprint"],
    242: ["browser_ver_detail", "Tarayici Surumu (Detay)", "browser"],
    243: ["battery_api_probe", "Batarya API Durumu (getBattery)", "system"],
    244: ["error_probe_prop", "Hata Probu: Property", "probe"],
    247: ["display_type", "Goruntu Tipi", "screen"],
    248: ["browser_version", "Tarayici Surumu", "browser"],
    250: ["perm_speaker", "Izin: Hoparlor Secimi (speaker-selection)", "probe"],
    252: ["screen_px", "Ekran Piksel Degeri", "screen"],
    253: ["network_flag", "Ag Bayragi", "network"],
    260: ["origin_url", "Kaynak URL", "network"],
    269: ["perf_timing", "Performans Zamanlamasi", "event"],
    270: ["perm_device_info", "Izin: Cihaz Bilgisi", "probe"],
    272: ["perf_code", "Performans Kodu", "event"],
    280: ["active_flag", "Aktiflik Bayragi", "session"],
    281: ["perm_bg_fetch", "Izin: Arka Plan Indirme (background-fetch)", "probe"],
    284: ["engine_ver_dup", "Motor Surumu (Kopya)", "browser"],
    289: ["webgl_ext_hash", "WebGL Uzanti Listesi Hash", "fingerprint"],
    293: ["accept_langs", "Kabul Edilen Diller", "browser"],
    303: ["sw_code", "ServiceWorker Kodu", "browser"],
    306: ["perm_bg_sync", "Izin: Arka Plan Senkronizasyon (background-sync)", "probe"],
    308: ["page_title", "Sayfa Basligi", "network"],
    311: ["page_code", "Sayfa Kodu", "network"],
    315: ["audio_codec_aac", "Ses Codec: AAC Destegi", "media"],
    316: ["adv_flag", "Gelismis Bayrak", "probe"],
    324: ["os_arch", "IS + Mimari Birlesik", "system"],
    325: ["timing_val_2", "Zamanlama Degeri 2", "event"],
    327: ["timing_val_3", "Zamanlama Degeri 3", "event"],
    332: ["gpu_vendor", "GPU Ureticisi", "browser"],
    334: ["color_depth", "Renk Derinligi", "screen"],
    338: ["perm_bluetooth", "Izin: Bluetooth", "probe"],
    339: ["perm_persistent_storage", "Izin: Kalici Depolama (persistent-storage)", "probe"],
    341: ["last_event", "Son Olay Tipi", "event"],
    342: ["event_code", "Olay Kodu", "event"],
    343: ["event_timing", "Olay Zamanlamasi", "event"],
    349: ["perm_ambient_light", "Izin: Ortam Isigi Sensoru", "probe"],
    352: ["screen_orient", "Ekran Yonu", "screen"],
    353: ["orient_delta", "Yon Deltasi", "screen"],
    359: ["protocol", "Protokol", "network"],
    362: ["perm_accelerometer", "Izin: Ivmeolcer (accelerometer)", "probe"],
    363: ["perf_val_2", "Performans Degeri 2", "event"],
    365: ["encoded_val", "Kodlu Deger", "token"],
    366: ["platform", "Platform", "system"],
    367: ["platform_sub", "Platform Alt Kodu", "system"],
    368: ["architecture", "Mimari", "system"],
    369: ["audio_codec_opus", "Ses Codec: Opus Destegi", "media"],
    373: ["crypto_val", "Kripto Degeri", "fingerprint"],
    374: ["hw_flag", "Donanim Bayragi", "system"],
    376: ["media_source_support", "MediaSource Extensions (MSE) Destegi", "media"],
    378: ["speech_voices_hash", "SpeechSynthesis Ses Listesi Hash", "media"],
    380: ["hw_val", "Donanim Degeri", "system"],
    382: ["hw_memory_limit", "JS Yigin Bellek Limiti (jsHeapSizeLimit)", "system"],
    383: ["cdp_flag", "CDP Protokol Bayragi", "probe"],
    391: ["selenium_code", "Selenium Kodu", "probe"],
    395: ["headless_code", "Headless Kodu", "probe"],
    396: ["headless_val", "Headless Degeri", "probe"],
    397: ["resolution_flag", "Cozunurluk Bayragi", "screen"],
    398: ["resolution_pair", "Cozunurluk Hash Cifti", "screen"],
    402: ["short_code_2", "Kisa Kod 2", "token"],
    403: ["net_timing", "Ag Zamanlamasi", "event"],
    404: ["history_length", "Tarayici Gecmis Uzunlugu (history.length)", "session"],
    406: ["ip_hash", "IP Bolgesi Hash", "fingerprint"],
    416: ["build_id", "Yapi Kimligi (Build ID)", "browser"],
    418: ["build_val", "Yapi Degeri", "browser"],
    419: ["error_probe_inv", "Hata Probu: Invocation", "probe"],
    422: ["perm_gyroscope", "Izin: Jiroskop (gyroscope)", "probe"],
    423: ["perm_magnetometer", "Izin: Manyetometre (magnetometer)", "probe"],
    427: ["misc_flag", "Cesitli Bayrak", "probe"],
    432: ["misc_val", "Cesitli Deger", "event"],
    433: ["perm_clipboard_read", "Izin: Pano Okuma (clipboard-read)", "probe"],
    437: ["fp_hex_2", "Parmak Izi Hex 2", "fingerprint"],
    438: ["feature_flags_bin", "Ozellik Bayrak Dizisi", "probe"],
    444: ["misc_val_2", "Cesitli Deger 2", "event"],
    445: ["audio_max_channels", "AudioContext Maksimum Kanal Sayisi", "media"],
    448: ["behavior_code", "Davranis Kodu", "event"],
    458: ["media_cap_3", "Medya Oynatma Yetenegi 3", "media"],
    460: ["pdf_viewer_enabled", "PDF Goruntuleyici Aktif mi (pdfViewerEnabled)", "browser"],
    463: ["screen_px_2", "Ekran Piksel Degeri 2", "screen"],
    466: ["short_flag", "Kisa Bayrak", "token"],
    469: ["fp_hex_3", "Parmak Izi Hex 3", "fingerprint"],
    471: ["perf_val_3", "Performans Degeri 3", "event"],
    473: ["client_ip", "Istemci IP Adresi", "network"],
    476: ["webrtc_cand_type", "WebRTC ICE Aday Tipi (host/srflx)", "network"],
    482: ["fp_hex_4", "Parmak Izi Hex 4", "fingerprint"],
    483: ["perf_val_4", "Performans Degeri 4", "event"],
    485: ["misc_val_3", "Cesitli Deger 3", "event"],
    490: ["intl_code", "Intl Kodu", "system"],
    492: ["fp_hex_5", "Parmak Izi Hex 5", "fingerprint"],
    495: ["webrtc_dtls_fp", "WebRTC DTLS Sertifika Durumu", "network"],
    496: ["adv_flag_2", "Gelismis Bayrak 2", "probe"],
    502: ["webrtc_flag", "WebRTC Bayragi", "probe"],
    507: ["perm_clipboard_write", "Izin: Pano Yazma (clipboard-write)", "probe"],
    511: ["perm_payment_handler", "Izin: Odeme Isleyici (payment-handler)", "probe"],
    517: ["api_code_2", "API Kodu 2", "browser"],
    519: ["perm_idle_detection", "Izin: Bosta Kalma Tespiti (idle-detection)", "probe"],
    520: ["site_domain", "Site Alan Adi", "network"],
    523: ["site_val", "Site Degeri", "network"],
    525: ["user_act_flag", "Kullanici Etkinlik Bayragi (userActivation)", "event"],
    529: ["shader_source", "WebGL Shader Kodu", "probe"],
    530: ["shader_val", "Shader Degeri", "probe"],
    533: ["perf_val_5", "Performans Degeri 5", "event"],
    541: ["nav_code_2", "Navigasyon Kodu", "session"],
    542: ["url_path", "URL Yolu", "network"],
    543: ["url_flag", "URL Bayragi", "network"],
    545: ["webgl2_context_probe", "WebGL2 Context Yetenek Kodu", "browser"],
    549: ["sw_controller_state", "ServiceWorker Denetleyici Durumu", "browser"],
    550: ["config_code", "Yapilandirma Kodu", "token"],
    561: ["api_code_3", "API Kodu 3", "browser"],
    564: ["visual_viewport_scale", "VisualViewport Olcek Degeri", "screen"],
    566: ["offscreen_canvas_sup", "OffscreenCanvas Destegi", "browser"],
    567: ["behavior_val", "Davranis Degeri", "event"],
    568: ["behavior_val_2", "Davranis Degeri 2", "event"],
    577: ["short_flag_2", "Kisa Bayrak 2", "token"],
    578: ["webgpu_adapter_fp", "WebGPU Adaptor Parmak Izi", "fingerprint"],
    579: ["proto_probe", "Prototip Dongu Probu", "probe"],
    581: ["behavior_flag", "Davranis Bayragi", "event"],
    588: ["timing_delta", "Zamanlama Deltasi", "event"],
    589: ["timing_val_4", "Zamanlama Degeri 4", "event"],
    590: ["timing_flag", "Zamanlama Bayragi", "event"],
    599: ["fp_hex_6", "Parmak Izi Hex 6", "fingerprint"],
    604: ["shared_array_buf_sup", "SharedArrayBuffer / Atomics Destegi", "browser"],
    608: ["doc_hidden_state", "Belge Gizlilik Durumu (document.hidden)", "screen"],
    609: ["secondary_ts", "Ikincil Zaman Damgasi", "session"],
    617: ["session_code", "Oturum Kodu", "session"],
    619: ["stack_probe", "Yigin Derinlik Probu", "probe"],
    622: ["session_id", "Oturum Kimligi", "session"],
    623: ["webgpu_limits_hash", "WebGPU Donanim Limitleri Hash", "fingerprint"],
    624: ["wasm_simd_support", "WebAssembly SIMD Destegi", "browser"],
    628: ["webrtc_sdp_hash", "WebRTC SDP Parmak Izi Hash", "network"],
    629: ["session_val", "Oturum Degeri", "session"],
    631: ["session_id_dup", "Oturum Kimligi (Kopya)", "session"],
    632: ["session_flag", "Oturum Bayragi", "session"],
    637: ["raf_timing_jitter", "requestAnimationFrame Zamanlama Sapmasi", "event"],
    638: ["ua_dup", "User-Agent (Kopya)", "browser"],
    643: ["nav_type", "Navigasyon Tipi", "session"],
    644: ["perm_local_fonts", "Izin: Yerel Font Erisimi (local-fonts)", "probe"],
    645: ["ua_brands_short", "UA Marka (Kisa JSON)", "browser"],
    646: ["css_media_queries_fp", "CSS Media Query Parmak Izi Cifti", "screen"],
    647: ["fp_hex_7", "Parmak Izi Hex 7", "fingerprint"],
    653: ["collector_exec_mode", "Toplayici Calisma Modu", "token"],
    655: ["final_val", "Son Zamanlama", "event"],
    658: ["screen_val_2", "Ekran Degeri", "screen"],
    659: ["webrtc_proto", "WebRTC Protokolu", "probe"],
    661: ["webrtc_val", "WebRTC Degeri", "probe"],
    665: ["zero_flags", "Sifir Bayrak Dizisi", "probe"],
    668: ["device_uuid", "Cihaz UUID", "session"],
    670: ["short_hash_1", "Kisa Hash 1", "fingerprint"],
    671: ["final_timing", "Son Zamanlama Degeri", "event"],
    673: ["final_code", "Son Kod Degeri", "token"],
    674: ["final_val_2", "Son Deger 2", "event"],
    675: ["adblock_dom_hash", "Reklam Engelleyici DOM Secici Hash", "fingerprint"],
    677: ["final_timing_2", "Son Zamanlama 2", "event"],
    679: ["short_hash_2", "Kisa Hash 2", "fingerprint"],
    680: ["collector_err_mask_1", "Toplayici Hata Bit Maskesi 1", "probe"],
    681: ["collector_err_mask_2", "Toplayici Hata Bit Maskesi 2", "probe"],
    682: ["collector_err_mask_3", "Toplayici Hata Bit Maskesi 3", "probe"],
    683: ["probe_time_perf_init", "Prob Suresi: Performans Baslatma (ms)", "timing"],
    689: ["probe_time_touch", "Prob Suresi: Dokunmatik/Olay (ms)", "timing"],
    712: ["probe_time_automation", "Prob Suresi: Otomasyon Tespiti (ms)", "timing"],
    720: ["probe_time_flags", "Prob Suresi: Kisa Bayraklar (ms)", "timing"],
    742: ["probe_time_webgl_delta", "Prob Suresi: WebGL Delta (ms)", "timing"],
    747: ["probe_time_sync_total", "Senkron Problar Toplam Suresi (ms)", "timing"],
    748: ["probe_time_total_token", "Toplam Token Uretim Suresi (ms)", "timing"],
    749: ["probe_time_async_all", "15 Asenkron Prob Toplam Suresi (ms)", "timing"],
    750: ["probe_time_webgl_async", "Asenkron Sure: WebGL/GPU (ms)", "timing"],
    751: ["probe_time_ua_entropy", "Asenkron Sure: UA HighEntropyValues (ms)", "timing"],
    752: ["probe_time_permissions", "Asenkron Sure: Permissions API (ms)", "timing"],
    753: ["probe_time_codecs_drm", "Asenkron Sure: Medya Codec/DRM (ms)", "timing"],
    754: ["probe_time_worker_dbg", "Asenkron Sure: Worker Debugger (ms)", "timing"],
    755: ["probe_time_webrtc_ice", "Asenkron Sure: WebRTC ICE/IP (ms)", "timing"],
    756: ["probe_time_audio_ctx", "Asenkron Sure: AudioContext (ms)", "timing"],
    757: ["probe_time_storage_est", "Asenkron Sure: Storage Estimate (ms)", "timing"],
    758: ["probe_time_media_dev", "Asenkron Sure: MediaDevices (ms)", "timing"],
    759: ["probe_time_battery", "Asenkron Sure: Battery API (ms)", "timing"],
    760: ["probe_time_speech", "Asenkron Sure: SpeechSynthesis (ms)", "timing"],
    761: ["probe_time_webrtc_sdp", "Asenkron Sure: WebRTC SDP (ms)", "timing"],
    762: ["probe_time_sw_state", "Asenkron Sure: ServiceWorker (ms)", "timing"],
    763: ["probe_time_webgpu", "Asenkron Sure: WebGPU Adaptor (ms)", "timing"],
    764: ["probe_time_raf_timer", "Asenkron Sure: rAF Zamanlayici (ms)", "timing"],
};

const PROBE_TIME_START = 683;
const PROBE_TIME_END = 764;

const CATEGORY_TR = {
    token: "Token/Protokol", system: "Sistem", browser: "Tarayici", screen: "Ekran",
    fingerprint: "Parmak Izi", media: "Medya", probe: "Prob/Test",
    network: "Ag", session: "Oturum", event: "Olay", font: "Font Testi",
    timing: "Sure Olcumu"
};

// --- kd() Float32 Prob Suresi Cozucu ---
function _kdDecodeFloat32(b64Str) {
    if (typeof b64Str !== 'string' || b64Str.length < 4) return null;
    try {
        let padded = b64Str;
        while (padded.length % 4 !== 0) padded += '=';
        const bin = atob(padded);
        if (bin.length !== 4) return null;
        const buf = new ArrayBuffer(4);
        const view = new DataView(buf);
        for (let i = 0; i < 4; i++) {
            let b = bin.charCodeAt(i) & 0xFF;
            b ^= 0xDC;
            b = ((b >>> 5) | (b << 3)) & 0xFF;
            b ^= 0xF8;
            b = Math.imul(b, 29) & 0xFF;
            view.setUint8(i, b);
        }
        return Number(view.getFloat32(0, false).toFixed(3));
    } catch (_) {
        return null;
    }
}

function _formatValue(idx, val, isV2) {
    if (val === null || val === undefined) return "bos";
    if (val === true) return "Evet";
    if (val === false) return "Hayir";
    if (typeof val === 'number') {
        if (val === 165) return "-- (olculmedi)";
        if (val === 161) return "-- (mevcut degil)";
        if (val === 173) return "-- (ayrilmis)";
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
        let displayVal = _formatValue(idx, val, isV2);
        if (cat === 'timing' && typeof val === 'string') {
            const ms = _kdDecodeFloat32(val);
            if (ms !== null) displayVal = ms + " ms";
        }
        return { label, category: CATEGORY_TR[cat] || cat, value: displayVal };
    }
    if (idx >= PROBE_TIME_START && idx <= PROBE_TIME_END) {
        let displayVal = "0.0 ms";
        if (typeof val === 'string' && val.length >= 4) {
            const ms = _kdDecodeFloat32(val);
            if (ms !== null) displayVal = ms + " ms";
            else displayVal = val;
        } else if (val !== null && val !== undefined) {
            displayVal = String(val);
        }
        return { label: "Prob Suresi #" + (idx - PROBE_TIME_START) + " (ms)", category: CATEGORY_TR.timing, value: displayVal };
    }
    let label, cat;
    if (val === null || val === undefined) { label = "Bos Alan"; cat = "token"; }
    else if (typeof val === 'boolean') { label = "Bayrak"; cat = "probe"; }
    else if (typeof val === 'number') {
        if (val === 165 || val === 161 || val === 173) { label = "Olculmedi/Ayrilmis"; cat = "token"; }
        else if (Math.abs(val) > 100000000) { label = "Parmak Izi Bileseni"; cat = "fingerprint"; }
        else if (Math.abs(val) > 999) { label = "Sayisal Deger"; cat = "event"; }
        else { label = "Parametre"; cat = "system"; }
    }
    else if (typeof val === 'string') { label = "Metin Degeri"; cat = "browser"; }
    else if (Array.isArray(val)) { label = "Hash Cifti"; cat = "fingerprint"; }
    else { label = "Deger"; cat = "token"; }
    return { label, category: CATEGORY_TR[cat] || cat, value: _formatValue(idx, val, isV2) };
}

// --- Yardimci Fonksiyonlar ---

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

// --- 1. Pn Timestamp Sifresi Tersine Cevirici ---

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

// --- 2. Castle Akis Sifresi Cozucu (FNV-1a + Xorshift32) ---

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

// --- 3. Ikili Protokol Ayristirici (LEB128 Varint + 11 Tip) ---

function _readVarint(data, off) {
    let r = 0, s = 0;
    while (true) {
        if (off >= data.length) throw new Error("Varint okunurken beklenmeyen veri sonu (ofset: " + off + ")");
        if (s > 35) throw new Error("Varint 32-bit sinirini asti (bozuk veri, ofset: " + off + ")");
        const b = data[off++];
        r = (r | ((b & 0x7F) << s)) >>> 0;
        if (!(b & 0x80)) return [r, off];
        s += 7;
    }
}

function _ensureBytes(data, off, byteCount, context) {
    if (byteCount < 0 || off + byteCount > data.length) {
        throw new Error(context + " okunurken veri siniri asildi: istenen " + byteCount + "B, kalan " + (data.length - off) + "B");
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
        _ensureBytes(data, off, len * 2, "UTF-16 string");
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
        _ensureBytes(data, off, len, "binary blob");
        const slice = data.slice(off, off + len); off += len;
        return [_bytesToB64(slice), off];
    }

    if (tag === 3) {
        _ensureBytes(data, off, 4, "uint32");
        const v = (data[off] | (data[off+1] << 8) | (data[off+2] << 16) | (data[off+3] << 24)) >>> 0;
        return [v, off + 4];
    }

    if (tag === 4) {
        _ensureBytes(data, off, 8, "float64");
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
        _ensureBytes(data, off, len, "ASCII string");
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

// --- 4b. V2 lr() Decode (Unicode destekli) ---

function _lrDecodeValue(s) {
    if (typeof s !== 'string' || s.length < 4 || s.length % 2 !== 0) return s;
    if (!/^[A-Za-z0-9+/=]+$/.test(s)) return s;
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
        if ((v < 32 && v !== 9 && v !== 10 && v !== 13) || (v >= 127 && v < 160) || v > 0xD7FF) {
            return s;
        }
        result += String.fromCharCode(v);
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

// --- 5. Guvenlik Basligi Dogrulama ---

function _verifySecurityHeader(seg1, seg2, ciphertextLen, checksumHex) {
    const totalSeg = seg1 + seg2;
    const lengthMatch = totalSeg === ciphertextLen;
    const splitValid = Math.abs(seg1 - seg2) <= 1;
    const sigNonZero = /^[0-9a-f]{32}$/i.test(checksumHex) && checksumHex !== '0'.repeat(32);
    return {
        is_valid: lengthMatch && splitValid && sigNonZero,
        length_match: lengthMatch,
        expected_bytes: totalSeg,
        actual_bytes: ciphertextLen,
        split_valid: splitValid,
        signature_present: sigNonZero
    };
}

// --- 6. Ana Decode Fonksiyonu ---

function decodeCastleToken(tokenStr) {
    tokenStr = tokenStr.trim();
    const pipeIdx = tokenStr.indexOf('|');
    if (pipeIdx < 1 || pipeIdx === tokenStr.length - 1) {
        throw new Error("Gecersiz Castle token bicimi: Token 'prefix|payload' formatinda olmalidir.");
    }
    const parts = [tokenStr.substring(0, pipeIdx), tokenStr.substring(pipeIdx + 1)];

    let b64 = parts[1].trim();
    while (b64.length % 4 !== 0) b64 += '=';
    const raw = _b64ToBytes(b64);

    if (raw.length < 28) {
        throw new Error("Token verisi cok kisa (" + raw.length + " bayt). En az 28 bayt bekleniyordu.");
    }

    const keyLen = raw[0] | (raw[1] << 8);
    if (keyLen < 8 || keyLen > 64 || 2 + keyLen + 24 >= raw.length) {
        throw new Error("Gecersiz zaman damgasi anahtar uzunlugu (keyLen=" + keyLen + ", toplam=" + raw.length + ").");
    }

    let keyB64 = '';
    for (let i = 2; i < 2 + keyLen; i++) keyB64 += String.fromCharCode(raw[i]);
    const tsStr = _recoverTimestampKey(keyB64);
    const tsMs = /^\d+$/.test(tsStr) ? parseInt(tsStr) : 0;

    const hOff = 2 + keyLen;
    const seg1 = ((raw[hOff] << 24) | (raw[hOff+1] << 16) | (raw[hOff+2] << 8) | raw[hOff+3]) >>> 0;
    const seg2 = ((raw[hOff+4] << 24) | (raw[hOff+5] << 16) | (raw[hOff+6] << 8) | raw[hOff+7]) >>> 0;
    let checksum = '';
    for (let i = 8; i < 24; i++) checksum += raw[hOff + i].toString(16).padStart(2, '0');

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

    const metrics = _deserialize(decompressed);

    // V2: once lr() decode, sonra cleanStr (siralama duzeltmesi)
    const cleaned = metrics.map(val => {
        const decoded = isV2 ? _lrDecodeValue(val) : val;
        return _cleanStr(decoded);
    });

    const m = (i, def) => cleaned.length > i && cleaned[i] != null ? cleaned[i] : def;

    const botDetected = _isBoolTrue(cleaned, 44);
    const webdriver = _isBoolTrue(cleaned, 22);
    const headless = _isBoolTrue(cleaned, 143);
    const devtools = _isBoolTrue(cleaned, 151);
    const cdp = _isBoolTrue(cleaned, 383);
    const isBot = botDetected || webdriver || cdp;

    const isoUtc = tsMs ? new Date(tsMs).toISOString() : "Bilinmiyor";
    const localTime = tsMs ? new Date(tsMs).toLocaleString('tr-TR') : "Bilinmiyor";

    const headerVerify = _verifySecurityHeader(seg1, seg2, ciphertext.length, checksum);

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
            auth_checksum_signature: checksum,
            integrity: headerVerify
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
                total_probe_time_slots: PROBE_TIME_END - PROBE_TIME_START + 1,
            }
        },
        formatted_metrics: formattedMetrics,
        raw_metrics_array: cleaned
    };
}

// --- 7. Token Karsilastirma (Diff) Motoru ---

function compareCastleTokens(tokenStrA, tokenStrB) {
    const decA = typeof tokenStrA === 'string' ? decodeCastleToken(tokenStrA) : tokenStrA;
    const decB = typeof tokenStrB === 'string' ? decodeCastleToken(tokenStrB) : tokenStrB;

    const maxLen = Math.max(decA.formatted_metrics.length, decB.formatted_metrics.length);
    const diffs = [];
    const identicalCount = { total: 0, fingerprint: 0 };

    for (let i = 0; i < maxLen; i++) {
        const mA = decA.formatted_metrics[i] || { label: 'Yok', category: '-', type: 'missing', value: '-', raw: undefined };
        const mB = decB.formatted_metrics[i] || { label: 'Yok', category: '-', type: 'missing', value: '-', raw: undefined };

        const rawA = JSON.stringify(mA.raw);
        const rawB = JSON.stringify(mB.raw);

        if (rawA === rawB) {
            identicalCount.total++;
            if (mA.category === 'Parmak Izi') identicalCount.fingerprint++;
        } else {
            let severity = 'info';
            if (mA.category === 'Prob/Test' || mA.type === 'boolean' || mB.type === 'boolean') {
                severity = 'high';
            } else if (mA.category === 'Parmak Izi' || mA.category === 'Sistem' || mA.category === 'Ekran') {
                severity = 'medium';
            }
            diffs.push({
                index: i,
                label: mA.label !== 'Bos Alan' ? mA.label : mB.label,
                category: mA.category !== 'Token/Protokol' ? mA.category : mB.category,
                typeA: mA.type, typeB: mB.type,
                valueA: mA.value, valueB: mB.value,
                severity
            });
        }
    }

    return {
        time_delta_ms: decB.timestamp.raw_timestamp_ms - decA.timestamp.raw_timestamp_ms,
        same_device_guid: decA.metrics_summary.device_id_fingerprint === decB.metrics_summary.device_id_fingerprint,
        same_ip: decA.metrics_summary.client_ip === decB.metrics_summary.client_ip,
        total_compared: maxLen,
        identical_metrics: identicalCount.total,
        changed_metrics: diffs.length,
        similarity_pct: Number(((identicalCount.total / maxLen) * 100).toFixed(2)),
        differences: diffs
    };
}

// --- 8. CSV ve Markdown Export ---

function exportMetricsToCSV(decodedObj) {
    const headers = ["Index", "Etiket", "Kategori", "Tip", "Formatli_Deger", "Ham_Deger"];
    const escapeCSV = (val) => {
        const s = val === null || val === undefined ? "" : String(val);
        return /[",\r\n]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s;
    };
    const rows = decodedObj.formatted_metrics.map(m => [
        m.index,
        escapeCSV(m.label),
        escapeCSV(m.category),
        escapeCSV(m.type),
        escapeCSV(m.value),
        escapeCSV(typeof m.raw === 'object' ? JSON.stringify(m.raw) : m.raw)
    ].join(","));
    return "﻿" + headers.join(",") + "\r\n" + rows.join("\r\n");
}

function exportMetricsToMarkdown(decodedObj) {
    const s = decodedObj.metrics_summary;
    let md = '# Castle Token Analiz Raporu\n\n';
    md += '- **Protokol / Surum:** `' + decodedObj.token_version + '`\n';
    md += '- **Zaman Damgasi (UTC):** `' + decodedObj.timestamp.iso_utc + '` (`' + decodedObj.timestamp.raw_timestamp_ms + '`)\n';
    md += '- **Istemci IP:** `' + s.client_ip + '`\n';
    md += '- **Isletim Sistemi / Tarayici:** `' + s.client_os + '` / `' + s.browser_build + '`\n';
    md += '- **Cihaz GUID:** `' + s.device_id_fingerprint + '`\n';
    md += '- **Guvenlik Karari:** **' + decodedObj.security_verdict_tr + '**\n\n';
    md += '## Onemli Metrikler\n\n| # | Etiket | Kategori | Tip | Deger |\n|---:|---|---|---|---|\n';
    for (const m of decodedObj.formatted_metrics) {
        if (m.raw !== null && m.raw !== 165 && m.raw !== 161 && m.raw !== 173) {
            const safeVal = String(m.value).replace(/\|/g, '\\|').replace(/\r?\n/g, ' ');
            md += '| ' + m.index + ' | ' + m.label + ' | ' + m.category + ' | `' + m.type + '` | `' + safeVal + '` |\n';
        }
    }
    return md;
}
