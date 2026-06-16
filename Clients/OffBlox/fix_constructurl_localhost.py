#!/usr/bin/env python3
r"""
Make the shared RobloxAPI/Http module build localhost URLs.

ROOT CAUSE (GameSettings)
-------------------------
The module's constructUrl(sub) builds the host as:
    "https://" .. sub .. "." .. domain
where `domain` is parsed from game:GetService("ContentProvider").BaseUrl. In
OffBlox that parse yields an EMPTY domain (the parser strips the first label and
"localhost" is a single label), so every call becomes "https://apis." /
"https://develop." -> Enum.HttpError.DnsResolve (offline, no such host).

FIX
---
Change the separator constant "." (between sub and domain) to "@localhost".
constructUrl then returns:
    "https://" .. sub .. "@localhost" .. domain      (domain == "")
  = "https://apis@localhost"
so the subdomain becomes ignored URL *userinfo* and the HOST is localhost. The
path is appended unchanged by composeUrl:
    "https://apis@localhost/experience-guidelines-service/v1beta1/..."
-> hits the local HookedWebserver on :443 (localhost cert), correct path.

This is a string-table edit only (Roblox bytecode opcodes are encoded and are NOT
touched). Strings are referenced by index, so length changes are safe. Only blobs
that are the http module (contain BOTH "parseBaseUrlInformation" and
"constructUrl") are touched, and within them only the lone "." constant.

  python fix_constructurl_localhost.py            # default: both GameSettings copies
  python fix_constructurl_localhost.py <file.rbxm> ...
"""

import os, sys, io, struct, shutil
import zstandard as zstd
try:
    import lz4.block as lz4b
except Exception:
    lz4b = None

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULTS = [
    os.path.join(HERE, "BuiltInPlugins", "Packed", "GameSettings.rbxm"),
    os.path.join(HERE, "BuiltInPlugins", "Optimized_Embedded_Signature", "GameSettings.rbxm"),
]
MARK1 = b"parseBaseUrlInformation"
MARK2 = b"constructUrl"
MATCH = b"."
REPL  = b"@localhost"


def _rdvar(buf, p):
    r = 0; s = 0
    while True:
        x = buf[p]; p += 1
        r |= (x & 0x7f) << s
        if not (x & 0x80):
            return r, p
        s += 7


def _wrvar(v):
    o = bytearray()
    while True:
        x = v & 0x7f; v >>= 7
        if v: o.append(x | 0x80)
        else: o.append(x); break
    return bytes(o)


def patch_blob(b):
    if len(b) < 3 or b[0] not in (5, 6):
        return b, 0
    if MARK1 not in b or MARK2 not in b:
        return b, 0
    i = 0
    out = bytearray()
    out.append(b[i]); i += 1
    out.append(b[i]); i += 1
    cnt, i = _rdvar(b, i)
    out += _wrvar(cnt)
    n = 0
    for _ in range(cnt):
        ln, j = _rdvar(b, i)
        s = b[j:j + ln]
        if s == MATCH:
            s = REPL; n += 1
        out += _wrvar(len(s)); out += s
        i = j + ln
    out += b[i:]
    return bytes(out), n


def patch_source_prop(data):
    if len(data) < 9:
        return data, 0
    nl = struct.unpack_from("<i", data, 4)[0]
    name = bytes(data[8:8 + nl]); tp = 8 + nl
    if tp >= len(data) or name != b"Source" or data[tp] != 0x1d:
        return data, 0
    out = bytearray(data[:tp + 1]); p = tp + 1; n = 0
    while p + 4 <= len(data):
        vl = struct.unpack_from("<I", data, p)[0]; p += 4
        blob = bytes(data[p:p + vl]); p += vl
        if MARK1 in blob and MARK2 in blob and blob[:1] in (b"\x05", b"\x06"):
            nb, k = patch_blob(blob)
            if k: n += k; blob = nb
        out += struct.pack("<I", len(blob)) + blob
    return bytes(out), n


def process(path):
    d = open(path, "rb").read()
    dec = zstd.ZstdDecompressor(); cmp = zstd.ZstdCompressor(level=19)
    hdr = 8 + 6 + 2 + 8 + 8
    out = bytearray(d[:hdr]); pos = hdr; total = 0
    while pos + 16 <= len(d):
        tag = d[pos:pos + 4]
        comp, uncomp, res = struct.unpack_from("<iii", d, pos + 4); pos += 16
        n = comp if comp > 0 else uncomp
        raw = d[pos:pos + n]; pos += n
        if comp == 0: data = bytes(raw)
        elif raw[:4] == b"\x28\xb5\x2f\xfd": data = dec.stream_reader(io.BytesIO(raw)).read()
        elif lz4b: data = lz4b.decompress(raw, uncompressed_size=uncomp)
        else: data = bytes(raw)
        k = 0
        if tag == b"PROP":
            data, k = patch_source_prop(data); total += k
        if k:
            body = cmp.compress(data)
            out += tag + struct.pack("<iii", len(body), len(data), 0) + body
        else:
            out += tag + struct.pack("<iii", comp, uncomp, res) + raw
        if tag == b"END\x00": break
    return total, bytes(out)


def verify(buf):
    """re-decompress; confirm http-module blobs now have 0 lone '.', and '@localhost' present; structure intact."""
    dec = zstd.ZstdDecompressor()
    pos = 8 + 6 + 2 + 8 + 8; lone = 0; repl = 0; ok = True
    def rv(b, q):
        r = s = 0
        while True:
            x = b[q]; q += 1; r |= (x & 0x7f) << s
            if not (x & 0x80): return r, q
            s += 7
    while pos + 16 <= len(buf):
        tag = buf[pos:pos + 4]
        comp, uncomp, res = struct.unpack_from("<iii", buf, pos + 4); pos += 16
        n = comp if comp > 0 else uncomp
        raw = buf[pos:pos + n]; pos += n
        try:
            data = raw if comp == 0 else (dec.stream_reader(io.BytesIO(raw)).read()
                   if raw[:4] == b"\x28\xb5\x2f\xfd" else raw)
            if comp != 0 and len(data) != uncomp: ok = False
        except Exception:
            ok = False; data = b""
        if tag == b"PROP" and len(data) > 9:
            nl = struct.unpack_from("<i", data, 4)[0]; nm = bytes(data[8:8+nl]); tpp = 8+nl
            if tpp < len(data) and nm == b"Source" and data[tpp] == 0x1d:
                p = tpp + 1
                while p + 4 <= len(data):
                    vl = struct.unpack_from("<I", data, p)[0]; p += 4
                    blob = data[p:p+vl]; p += vl
                    if blob[:1] in (b"\x05", b"\x06") and MARK1 in blob and MARK2 in blob:
                        try:
                            i = 2; cnt, i = rv(blob, i)
                            for _ in range(cnt):
                                ln, i = rv(blob, i); s = blob[i:i+ln]; i += ln
                                if s == MATCH: lone += 1
                                elif s == REPL: repl += 1
                        except Exception: ok = False
        if tag == b"END\x00": break
    return lone, repl, ok


def main():
    args = [a for a in sys.argv[1:] if a != "--dry-run"]
    dry = "--dry-run" in sys.argv[1:]
    targets = args or DEFAULTS
    for p in targets:
        if not os.path.exists(p):
            print(f"  [not found] {p}"); continue
        total, buf = process(p)
        lone, repl, ok = verify(buf)
        if total and not dry:
            bak = p + ".orig_constructurl"
            if not os.path.exists(bak): shutil.copy2(p, bak)
            open(p, "wb").write(buf)
        print(f"  {'[dry] ' if dry else ''}{os.path.basename(os.path.dirname(p))}/{os.path.basename(p)}: "
              f"replaced={total}  module_lone_dot_remaining={lone}  @localhost_in_module={repl}  reparse_ok={ok}")
    if not dry:
        print("\nDone. Backups: *.orig_constructurl . Restart Studio.")


if __name__ == "__main__":
    main()
