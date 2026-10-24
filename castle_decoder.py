#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
=============================================================================
             Castle Anti-Bot Token Deobfuscator & Pure Python Decoder
=============================================================================
 %100 Saf Python (Pure Python) ile çalışan Castle Token Çözücü.
 Harici hiçbir tarayıcı (Chrome, Playwright, Puppeteer), Java veya Node.js
 bağımlılığı YOKTUR. Sadece Python standart kütüphanesi kullanır.
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
from decode_token import PureCastleDecoder, METRIC_LABELS

# Windows terminali için UTF-8 desteği
if hasattr(sys.stdout, 'reconfigure'):
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except Exception:
        pass

class CastleTokenDecoder:
    """Geriye dönük uyumlu CastleTokenDecoder sınıfı (Saf Python motoru)."""

    def __init__(self, cdp_url: Optional[str] = None):
        self.pure_decoder = PureCastleDecoder()

    def decode(self, token_str: str) -> Dict[str, Any]:
        """Tokeni çözer, şifresini açar, dekomprese eder ve deobfuscate eder."""
        pure_res = self.pure_decoder.decode_token(token_str)
        
        # Web dashboard ve API için uyumlu format
        p = pure_res["client_profile"]
        b = pure_res["anti_bot_telemetry"]
        s = pure_res["session_time"]
        g = pure_res["graphics_and_fingerprints"]
        h = pure_res["protocol_headers"]

        return {
            "status": "success",
            "token_version": pure_res["token_version"],
            "security_verdict": pure_res["security_verdict"],
            "security_verdict_tr": pure_res["security_verdict_tr"],
            "timestamp": {
                "raw_timestamp_ms": s["epoch_ms"],
                "timestamp_str": str(s["epoch_ms"]),
                "iso_utc": s["utc"],
                "local_time": s["local"]
            },
            "security_header": {
                "segment_1_length": h["segment_1_bytes"],
                "segment_2_length": h["segment_2_bytes"],
                "total_ciphertext_bytes": h["total_ciphertext_bytes"],
                "decompressed_payload_bytes": h["decompressed_payload_bytes"],
                "auth_checksum_signature": h["signature_hash"]
            },
            "metrics_summary": {
                "total_metrics_count": pure_res["total_metrics_count"],
                "client_ip": p["ip_address"],
                "client_os": p["operating_system"],
                "browser_build": p["browser_version"],
                "device_id_fingerprint": p["device_guid"],
                "bot_flags": b
            },
            "categories": {
                "network": {"ip": p["ip_address"]},
                "device": {
                    "os": p["operating_system"],
                    "browser_version": p["browser_version"],
                    "device_fingerprint": p["device_guid"],
                    "architecture": "x86_64"
                },
                "screen_and_display": {
                    "resolution": p["screen_resolution"],
                    "pixel_ratio": p["pixel_ratio"]
                },
                "bot_detection": b,
                "font_and_canvas": g
            },
            "labeled_metrics": pure_res["labeled_metrics"],
            "raw_metrics_array": pure_res["all_metrics_cleaned"]
        }

def main():
    import argparse
    parser = argparse.ArgumentParser(description="Castle Anti-Bot Token Deobfuscator & Pure Python Decoder")
    parser.add_argument("token", nargs="?", help="Tam castle_token dizesi (uq1seNrd| ile başlar)")
    parser.add_argument("--file", "-f", help="Token içeren dosya yolu")
    parser.add_argument("--output", "-o", help="Çıktı JSON dosya yolu")
    parser.add_argument("--json", "-j", action="store_true", help="Sadece JSON çıktısı verir")
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
        print("[!] Hata: Token belirtilmedi. Argüman olarak veya --file ile verin.", file=sys.stderr)
        sys.exit(1)

    decoder = CastleTokenDecoder()
    try:
        res = decoder.decode(token)
        out_json = json.dumps(res, indent=2, ensure_ascii=False)
        if args.json or not args.output:
            print(out_json)
        if args.output:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(out_json)
            print(f"[+] Çıktı kaydedildi: {args.output}")
    except Exception as e:
        print(f"[-] Hata: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
