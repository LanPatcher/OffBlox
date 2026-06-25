#!/usr/bin/env python3
# fix_datamodelpatch_signature.py
#
# Forces the DataModelPatch (and any rbxm) embedded-signature verification to
# SUCCEED on the OffBloxModern x64 Studio build (0.725.0.7251148).
#
# WHY THIS, AND NOT THE 2023-STYLE jne->jmp PATCH
#   The 2023 reference client is 32-bit; its bypass was a handful of
#   `test al,al; jne ok` flips. This build is 64-bit and the patch-config
#   ORCHESTRATION strings are reached through FASTLOG channel indirection
#   (no direct lea), so they can't anchor a branch flip. The actual crypto
#   path, however, is plain .text.
#
# WHAT WE PATCH
#   The model-signature verifier at VA 0x1431069c0. It is an MSVC RVO function:
#       arg0 (rcx)            -> std::vector<errorcode> result (it zero-inits
#                               [rcx],[rcx+8],[rcx+0x10] = begin/end/cap)
#       7th arg ([rsp+0x38])  -> pointer to a "verified" byte (it does
#                               `mov byte[r12], al` early via r12=[rsp+0xc0])
#   It loops over every signature; each failure appends an error code to the
#   result vector. The caller (deserializeAndVerifyPatch) treats an EMPTY error
#   vector as success (`cmp rbx,rsi ; je <ok>`) and also reads the verified byte.
#
#   So we overwrite the function entry with a stub that:
#       result.begin = result.end = result.cap = 0   (no errors -> all valid)
#       *verified = 1
#       return result ptr (rax = rcx, per RVO)
#   i.e. "every signature verified, zero errors".
#
#   This makes the engine accept the (modified) DataModelPatch.rbxm. The log
#   line "No signatures in the model could be verified" should no longer appear.
#
# SAFETY
#   * Anchored on a UNIQUE 0x4C-byte signature of the function body, so it will
#     only patch this exact build; on any other build it aborts with a message.
#   * Idempotent (detects an already-applied stub).
#   * Writes a one-time backup: OffBlox.exe.bak_sigbypass
#   * Verifies the bytes after writing.

import os, sys, shutil

# --- unique signature of verifyModelSignatures @ VA 0x1431069c0 (file 0x3105dc0) ---
ANCHOR = bytes.fromhex(
    "48895c2410"      # mov [rsp+10], rbx
    "48896c2418"      # mov [rsp+18], rbp
    "4889742420"      # mov [rsp+20], rsi
    "48894c2408"      # mov [rsp+08], rcx   (arg0 = result vector)
    "57" "4154" "4155" "4156" "4157"   # push rdi,r12,r13,r14,r15
    "4883ec60"        # sub rsp, 0x60
    "4d8be9"          # mov r13, r9
    "498bd8"          # mov rbx, r8
    "488bf9"          # mov rdi, rcx
    "33c0"            # xor eax, eax
    "89442420"        # mov [rsp+20], eax
    "4c8ba424c0000000"# mov r12, [rsp+0xC0]   (7th arg -> verified byte ptr)
    "41880424"        # mov byte [r12], al    (verified = 0 initially)
    "488901"          # mov [rcx], rax        (result.begin = 0)
    "48894108"        # mov [rcx+8], rax      (result.end   = 0)
    "48894110"        # mov [rcx+10], rax     (result.cap   = 0)
    "c7442420" + "01"  # mov dword [rsp+20], 1 (start of next insn; anchor tail)
)
assert len(ANCHOR) == 0x4C, len(ANCHOR)

# --- replacement stub written at the function entry (26 bytes) ---
#   xor  rax, rax
#   mov  [rcx], rax            ; vec.begin = 0
#   mov  [rcx+8], rax          ; vec.end   = 0
#   mov  [rcx+0x10], rax       ; vec.cap   = 0  -> EMPTY error vector
#   mov  rax, [rsp+0x38]       ; 7th arg = verified-byte out-ptr (entry rsp)
#   mov  byte [rax], 1         ; verified = 1
#   mov  rax, rcx             ; return result ptr (RVO)
#   ret
STUB = bytes.fromhex("4831c0" "488901" "48894108" "48894110"
                     "488b442438" "c60001" "488bc1" "c3")
assert len(STUB) == 26, len(STUB)

PATCHED_MARKER = STUB + ANCHOR[len(STUB):]   # what the site looks like once patched
VERIFY_VA = 0x1431069c0

def main():
    here = os.path.dirname(os.path.abspath(__file__))
    target = sys.argv[1] if len(sys.argv) > 1 else os.path.join(here, "Clients", "OffBlox", "OffBlox.exe")
    if not os.path.isfile(target):
        print(f"[!] target not found: {target}")
        print("    usage: python fix_datamodelpatch_signature.py [path\\to\\OffBlox.exe]")
        sys.exit(1)

    data = bytearray(open(target, "rb").read())

    # already patched?
    if PATCHED_MARKER in data:
        print("[=] Already patched - signature verifier already returns success. Nothing to do.")
        return

    n = data.count(ANCHOR)
    if n == 0:
        print("[!] Signature pattern NOT found.")
        print("    This is not the expected 0.725.0.7251148 build, or it's already")
        print("    modified differently. Aborting (no changes made).")
        sys.exit(2)
    if n > 1:
        print(f"[!] Pattern found {n} times (ambiguous). Aborting to avoid corruption.")
        sys.exit(3)

    off = data.find(ANCHOR)
    print(f"[+] Found verifyModelSignatures @ file 0x{off:08x} (VA ~0x{VERIFY_VA:x})")

    # one-time backup
    bak = target + ".bak_sigbypass"
    if not os.path.exists(bak):
        shutil.copy2(target, bak)
        print(f"[+] Backup written: {bak}")
    else:
        print(f"[=] Backup already exists: {bak}")

    # apply stub over the function entry
    data[off:off+len(STUB)] = STUB
    open(target, "wb").write(data)

    # verify
    check = bytearray(open(target, "rb").read())
    if check[off:off+len(STUB)] == STUB:
        print(f"[+] Patched {len(STUB)} bytes at 0x{off:08x}.")
        print("    Signature verification will now report: empty error list + verified=1.")
        print("    Expected: 'No signatures in the model could be verified' is GONE,")
        print("    and the modified DataModelPatch.rbxm loads.")
    else:
        print("[!] Verification failed - bytes did not take. Restore from the .bak_sigbypass file.")
        sys.exit(4)

if __name__ == "__main__":
    main()
