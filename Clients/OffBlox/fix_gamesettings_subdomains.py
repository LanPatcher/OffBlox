#!/usr/bin/env python3
r"""
Fix GameSettings.rbxm subdomains so every Roblox API subdomain resolves to the
local HookedWebserver instead of the (unreachable) live roblox.com.

ROOT CAUSE
----------
GameSettings' Url module holds a table of subdomain templates of the form
"https://<sub>.%s" (apis, develop, groups, games, publish, thumbnails, ...).
The "%s" is filled with the engine base domain, which is EMPTY in OffBlox, so
every call resolves to a broken host like "https://apis." -> DNS failure.
BuildRobloxUrl("apis", path) / ("groups", ...) / ("www", ...) all go through
these templates, so fixing the templates fixes every subdomain call at once.

WHAT THIS DOES
--------------
Rewrites each "https://<sub>.%s" template string to "http://localhost" inside
the compiled Luau bytecode. The templates live in each script's bytecode string
table as [varint len][bytes]; strings are referenced by INDEX, not byte offset,
so changing a string's bytes/length is safe as long as the table order/count is
preserved (it is). Steps per affected script blob:
  1. parse the blob header: u8 version (5/6), u8 typesVersion, varint stringCount
  2. walk the string table; replace matching templates; re-emit with new varints
  3. leave the rest of the bytecode (protos/instructions) byte-identical
Then fix the blob's outer [u32 length] prefix in the Source PROP (typeid 0x1d),
recompress the chunk (zstd), and rewrite the rbxm chunk header. Plugin signature
is already bypassed (patch_plugin_signature.py), so the edited rbxm loads.

  python fix_gamesettings_subdomains.py            # patch both copies in place
  python fix_gamesettings_subdomains.py --dry-run  # report only, write nothing
"""

import os, sys, re, io, struct, shutil
import zstandard as zstd
try:
    import lz4.block as lz4b
except Exception:
    lz4b = None

HERE = os.path.dirname(os.path.abspath(__file__))
TARGETS = [
    os.path.join(HERE, "BuiltInPlugins", "Packed", "GameSettings.rbxm"),
    os.path.join(HERE, "BuiltInPlugins", "Optimized_Embedded_Signature", "GameSettings.rbxm"),
]

REPL = b"http://localhost"                 # no trailing slash: matches the templates'
                                           # "https://<sub>.%s" (also no trailing slash),
                                           # so the existing path-join behavior is preserved.
TPL = re.compile(rb"https?://[a-z][a-z0-9]*\.%s\Z")   # https://apis.%s , https://develop.%s , ...


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
        if v:
            o.append(x | 0x80)
        else:
            o.append(x); break
    return bytes(o)


def patch_blob(b):
    """b = compiled Luau bytecode blob. Returns (new_blob, n_replaced)."""
    if len(b) < 3 or b[0] not in (5, 6):
        return b, 0
    i = 0
    out = bytearray()
    out.append(b[i]); i += 1            # version
    out.append(b[i]); i += 1            # typesVersion
    cnt, i = _rdvar(b, i)
    out += _wrvar(cnt)
    n = 0
    for _ in range(cnt):
        ln, j = _rdvar(b, i)
        s = b[j:j + ln]
        nxt = j + ln
        if TPL.match(s):
            s = REPL; n += 1
        out += _wrvar(len(s)); out += s
        i = nxt
    out += b[i:]                         # remainder (protos/instructions) unchanged
    return bytes(out), n


def patch_source_prop(data):
    """data = decompressed PROP chunk. If it's the Source (typeid 0x1d) columnar
    blob array, rewrite templates in each blob and fix each blob's u32 length.
    Returns (new_data, n_replaced)."""
    if len(data) < 9:
        return data, 0
    nl = struct.unpack_from("<i", data, 4)[0]
    name = bytes(data[8:8 + nl]); tp = 8 + nl
    if tp >= len(data):
        return data, 0
    typeid = data[tp]
    vpos = tp + 1
    if name != b"Source" or typeid != 0x1d:
        return data, 0
    out = bytearray(data[:vpos])
    p = vpos
    n = 0
    while p + 4 <= len(data):
        vl = struct.unpack_from("<I", data, p)[0]; p += 4
        blob = bytes(data[p:p + vl]); p += vl
        if b".%s" in blob and blob[:1] in (b"\x05", b"\x06"):
            nb, k = patch_blob(blob)
            if k:
                n += k; blob = nb
        out += struct.pack("<I", len(blob)) + blob
    return bytes(out), n


def process(path, dry_run=False):
    d = open(path, "rb").read()
    dec = zstd.ZstdDecompressor()
    cmp = zstd.ZstdCompressor(level=19)
    hdr = 8 + 6 + 2 + 8 + 8
    out = bytearray(d[:hdr])
    pos = hdr
    total = 0
    while pos + 16 <= len(d):
        tag = d[pos:pos + 4]
        comp, uncomp, res = struct.unpack_from("<iii", d, pos + 4)
        pos += 16
        n = comp if comp > 0 else uncomp
        raw = d[pos:pos + n]; pos += n
        if comp == 0:
            data = bytes(raw); was = "raw"
        elif raw[:4] == b"\x28\xb5\x2f\xfd":
            data = dec.stream_reader(io.BytesIO(raw)).read(); was = "zstd"
        elif lz4b:
            data = lz4b.decompress(raw, uncompressed_size=uncomp); was = "lz4"
        else:
            data = bytes(raw); was = "raw"
        k = 0
        if tag == b"PROP":
            data, k = patch_source_prop(data)
            total += k
        # re-emit: keep original compression scheme for fidelity
        if k:
            body = cmp.compress(data)
            out += tag + struct.pack("<iii", len(body), len(data), 0) + body
        else:
            out += tag + struct.pack("<iii", comp, uncomp, res) + raw
        if tag == b"END\x00":
            break
    if not dry_run and total:
        bak = path + ".orig_subdomains"
        if not os.path.exists(bak):
            shutil.copy2(path, bak)
        open(path, "wb").write(out)
    return total, bytes(out)


def verify(buf):
    """Re-decompress patched bytes; return (remaining_templates, localhost_count, ok)."""
    dec = zstd.ZstdDecompressor()
    pos = 8 + 6 + 2 + 8 + 8
    full = bytearray()
    ok = True
    while pos + 16 <= len(buf):
        tag = buf[pos:pos + 4]
        comp, uncomp, res = struct.unpack_from("<iii", buf, pos + 4)
        pos += 16
        n = comp if comp > 0 else uncomp
        raw = buf[pos:pos + n]; pos += n
        try:
            if comp == 0:
                data = raw
            elif raw[:4] == b"\x28\xb5\x2f\xfd":
                data = dec.stream_reader(io.BytesIO(raw)).read()
            else:
                data = raw
            if len(data) != uncomp and comp != 0:
                ok = False
        except Exception:
            ok = False
            data = b""
        full += data
        if tag == b"END\x00":
            break
    left = len(re.findall(rb"https?://[a-z][a-z0-9]*\.%s", bytes(full)))
    return left, bytes(full).count(REPL), ok


def main():
    dry = "--dry-run" in sys.argv[1:]
    any_done = False
    for p in TARGETS:
        if not os.path.exists(p):
            print(f"  [not found] {p}")
            continue
        total, buf = process(p, dry_run=dry)
        left, lh, ok = verify(buf)
        any_done = any_done or bool(total)
        print(f"  {'[dry] ' if dry else ''}{os.path.basename(os.path.dirname(p))}/GameSettings.rbxm: "
              f"replaced={total}  remaining_templates={left}  http://localhost={lh}  reparse_ok={ok}")
    if not any_done:
        print("Nothing replaced.")
    elif not dry:
        print("\nDone. Backups: *.orig_subdomains . Restart Studio.")


if __name__ == "__main__":
    main()
