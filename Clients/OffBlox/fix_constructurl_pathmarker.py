#!/usr/bin/env python3
r"""
Make the shared RobloxAPI/Http module emit a localhost URL with the subdomain
folded into the path under a unique marker, which HookedWebserver strips.

constructUrl(sub) originally = "https://" .. sub .. "." .. domain   (domain == "")
After this edit (str "https://" -> "http://localhost/__rbxsub__/"):
    constructUrl("apis")  = "http://localhost/__rbxsub__/apis."
    composeUrl + path     = "http://localhost/__rbxsub__/apis./experience-..."
HookedWebserver strips "/__rbxsub__/<sub-segment>" -> "/experience-...".

Why not a bare localhost host? Studio's HttpService rejects userinfo ("apis@host"
-> InvalidUrl) and the encoded bytecode opcodes can't be edited to drop the
subdomain argument, so the subdomain must live in the path. http (port 80) avoids
any TLS/cert mismatch. String-table edit only; only the http-module blob (has
both "parseBaseUrlInformation" and "constructUrl") is touched.

  python fix_constructurl_pathmarker.py            # both GameSettings copies
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
# exact string-table entry -> replacement (only inside the http-module blob)
REPLACEMENTS = {
    b"https://": b"http://localhost/__rbxsub__/",
    b"@localhost": b".",     # revert the earlier userinfo attempt if present
}


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
    if len(b) < 3 or b[0] not in (5, 6) or MARK1 not in b or MARK2 not in b:
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
        if s in REPLACEMENTS:
            s = REPLACEMENTS[s]; n += 1
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
    dec = zstd.ZstdDecompressor()
    pos = 8 + 6 + 2 + 8 + 8; marker = 0; ok = True
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
                                if s == b"http://localhost/__rbxsub__/": marker += 1
                        except Exception: ok = False
        if tag == b"END\x00": break
    return marker, ok


def main():
    targets = sys.argv[1:] or DEFAULTS
    for p in targets:
        if not os.path.exists(p):
            print(f"  [not found] {p}"); continue
        total, buf = process(p)
        marker, ok = verify(buf)
        if total:
            bak = p + ".orig_pathmarker"
            if not os.path.exists(bak): shutil.copy2(p, bak)
            open(p, "wb").write(buf)
        print(f"  {os.path.basename(os.path.dirname(p))}/{os.path.basename(p)}: "
              f"replaced={total}  marker_present={marker}  reparse_ok={ok}")
    print("\nDone. Backups: *.orig_pathmarker . Rebuild DLL + restart Studio.")


if __name__ == "__main__":
    main()
