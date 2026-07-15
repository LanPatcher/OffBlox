// OffBloxExec.cpp
// ---------------------------------------------------------------------------
// Standalone injected DLL that runs Luau on the live OffBlox server DataModel,
// receiving scripts over a bidirectional named pipe (a C# client can connect).
//
// Pipe:   \\.\pipe\OffBloxExec   (PIPE_ACCESS_DUPLEX, message mode)
//   client -> DLL : each message is one Luau script to run
//   DLL -> client : status / error / result messages (one per WriteFile)
//
// It is fully self-contained: it inline-hooks the engine's internal coroutine
// resume, patches loadstring's two "not available" gates so loadstring compiles
// in every context, auto-detects the live server VM (the DataModel whose
// Workspace has >1 child), and executes typed lines there with elevated Proto
// capabilities. Mirrors the in-process console build; only the I/O differs.
//
// Target: OffBlox.exe (Studio fork), ImageBase 0x140000000. All addresses are
// module-relative (base + RVA), so ASLR is irrelevant.
// ---------------------------------------------------------------------------

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <cstdint>
#include <cstring>
#include <cstdio>
#include <string>
#include <vector>
#include <deque>
#include <mutex>
#include <exception>
#include <thread>
#include <chrono>

namespace offblox {

// ======================= configuration / constants =========================

static const wchar_t* kPipeName = L"\\\\.\\pipe\\OffBloxExec";

// Engine RVAs (base + RVA; verified against this build).
static const uintptr_t kPubResumeRva   = 0x664cd40;  // lua_resume(L, StkId, narg)
static const uintptr_t kIntResumeRva   = 0x664ce00;  // internal resume(L)   [hooked]
static const uintptr_t kNewThreadRva   = 0x6648fb0;  // lua_newthread(L)
static const uintptr_t kRawGetRva      = 0x6649f10;  // lua_rawget(L, idx)->tag
static const uintptr_t kNewLStrRva     = 0x6674d50;  // luaS_newlstr(L, s, len)
static const uintptr_t kLoadstrGate1Rva = 0x35d35ce; // jne throw "RobloxScript context"
static const uintptr_t kLoadstrGate2Rva = 0x35d36cc; // je  throw "LoadStringEnabled off"
static const uintptr_t kLoadstrGate3Rva = 0x35d3a09; // je  throw "not available" (policy bool)
static const uintptr_t kLoadstrGate4Rva = 0x35d3a16; // je  throw "not available" (policy bool)

// --- FE / client-replication anchors (from Docs/FE_Replication_REMap.md) ------
// The Replicator's outgoing serialize method is virtual slot 134 ([this+0x430]).
// ClientReplicator vtable = base+kClientReplVtRva. The send tick that invokes the
// slot is base+kReplTickRva (this=rcx). ChangePropertyItem ctor = base+kChangePropCtorRva.
// We hook the ClientReplicator vtable slot 134 ONLY to capture the live replicator
// pointer + validate member offsets (log-only, SEH-guarded). The FE-off mechanism
// itself is server-side (the join-bit patch, Docs/FE_Replication_REMap.md 6e).
static const uintptr_t kReplTickRva      = 0x21497a0; // Replicator send tick (calls slot 134)
static const uintptr_t kClientReplVtRva  = 0x8c98ef8; // ClientReplicator vtable
static const uintptr_t kChangePropCtorRva= 0x28c3200; // ChangePropertyItem::ctor
static const uintptr_t kReplSendSlotOff  = 0x430;     // vtable byte offset of the serialize method
static const uintptr_t kProcPacketRva    = 0x2759d10; // ClientReplicator::processPacket (per-packet, RELIABLE capture)
static const uintptr_t kDispatchRva      = 0x28a86d0; // onCombinedSignal -> per-replicator PROPERTY_CHANGED dispatch
                                                      //   (rcx=Replicator, rdx=changeStruct{+8=Instance*}, r8=signalData{+8=PropertyDescriptor*})

// lua_State / TValue / Proto layout.
static const int kOffGlobal = 0x28;   // lua_State.global (global_State*)
static const int kOffBase   = 0x30;   // lua_State.base
static const int kOffTop    = 0x38;   // lua_State.top
static const int kOffCaps   = 0x58;   // capability mask within ExtraSpace
static const int kOffGT     = 0x60;   // lua_State.gt (global table)
static const int kOffExtra  = 0x68;   // lua_State.userdata/ExtraSpace
static const int kOffMainTh = 0x70;   // global_State.mainthread
static const int kOffTT     = 0x0c;   // TValue type-tag
static const int kTValSize  = 16;
static const int kTagNumber = 3;
static const int kTagTable  = 7;
static const int kTagString = 6;
static const int kTagFunc   = 8;
static const int kTagThread = 10;
static const int kGlobalsIdx = -10002;             // LUA_GLOBALSINDEX
static const unsigned char kResumePrologue[5] = { 0x40, 0x53, 0x48, 0x83, 0xec };

// ============================ pipe + logging ===============================

static HANDLE                  g_pipe = INVALID_HANDLE_VALUE;
static std::mutex              g_pipeMtx;
static std::deque<std::string> g_outQueue;   // pending outbound log lines
static std::mutex              g_outMtx;

// Log NEVER does pipe I/O on the caller's thread - it only appends to a queue.
// The game (Lua) thread must never block on WriteFile (pipe backpressure would
// freeze the whole game); a dedicated WriterThread flushes the queue instead.
static void Log(const std::string& s)
{
    OutputDebugStringA(("[OffBloxExec] " + s + "\n").c_str());
    std::lock_guard<std::mutex> lk(g_outMtx);
    if (g_outQueue.size() < 4000) g_outQueue.push_back(s);   // cap: drop under flood
}
// const char* wrapper so callers using __try build no unwindable temporary.
static void LogC(const char* s) { Log(std::string(s)); }

static DWORD WINAPI WriterThread(LPVOID)
{
    for (;;)
    {
        HANDLE h;
        { std::lock_guard<std::mutex> lk(g_pipeMtx); h = g_pipe; }
        if (h == INVALID_HANDLE_VALUE) { Sleep(30); continue; }   // wait for a client

        std::string msg; bool have = false;
        {
            std::lock_guard<std::mutex> lk(g_outMtx);
            if (!g_outQueue.empty()) { msg = std::move(g_outQueue.front()); g_outQueue.pop_front(); have = true; }
        }
        if (have) { DWORD w = 0; WriteFile(h, msg.data(), (DWORD)msg.size(), &w, nullptr); }
        else Sleep(3);
    }
}

// ========================= x64 inline hook ================================

static SIZE_T InsnLen(const BYTE* p)
{
    const BYTE* op = p;
    while (*op == 0x66 || *op == 0x67 || *op == 0xF2 || *op == 0xF3) ++op;
    if (*op >= 0x40 && *op <= 0x4F) ++op;                 // REX
    BYTE b = *op;
    SIZE_T pre = (SIZE_T)(op - p);

    auto modrmLen = [](const BYTE* m, bool& ripRel) -> SIZE_T
    {
        BYTE mod = (m[0] >> 6) & 3, rm = m[0] & 7;
        SIZE_T len = 1;
        if (mod == 3) return len;
        if (mod == 0 && rm == 5) { ripRel = true; return len + 4; }
        if (rm == 4)
        {
            len += 1; BYTE base = m[1] & 7;
            if (mod == 0 && base == 5) len += 4;
            else if (mod == 1) len += 1;
            else if (mod == 2) len += 4;
        }
        else { if (mod == 1) len += 1; if (mod == 2) len += 4; }
        return len;
    };

    switch (b)
    {
    case 0x50: case 0x51: case 0x52: case 0x53:
    case 0x54: case 0x55: case 0x56: case 0x57:
    case 0x58: case 0x59: case 0x5A: case 0x5B:
    case 0x5C: case 0x5D: case 0x5E: case 0x5F:
        return pre + 1;
    case 0x88: case 0x89: case 0x8A: case 0x8B: case 0x8D:
    { bool r = false; SIZE_T ml = modrmLen(op + 1, r); if (r) return 0; return pre + 1 + ml; }
    case 0x83:
    { bool r = false; SIZE_T ml = modrmLen(op + 1, r); if (r) return 0; return pre + 1 + ml + 1; }
    case 0x81:
    { bool r = false; SIZE_T ml = modrmLen(op + 1, r); if (r) return 0; return pre + 1 + ml + 4; }
    case 0x0F:
    {
        BYTE b2 = op[1];
        if (b2 == 0xB6 || b2 == 0xB7 || b2 == 0xBE || b2 == 0xBF || b2 == 0x1F)
        { bool r = false; SIZE_T ml = modrmLen(op + 2, r); if (r) return 0; return pre + 2 + ml; }
        return 0;
    }
    default: return 0;
    }
}

static bool InlineHookVA(uintptr_t targetVA, void* newFn, void** outOrig)
{
    if (!targetVA || !newFn) return false;
    BYTE* target = reinterpret_cast<BYTE*>(targetVA);
    const SIZE_T kJmpSize = 14;

    SIZE_T copied = 0;
    for (int i = 0; i < 32 && copied < kJmpSize; ++i)
    {
        SIZE_T len = InsnLen(target + copied);
        if (len == 0) return false;
        copied += len;
    }
    if (copied < kJmpSize) return false;

    BYTE* tramp = reinterpret_cast<BYTE*>(
        VirtualAlloc(nullptr, copied + kJmpSize + 8,
                     MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
    if (!tramp) return false;

    std::memcpy(tramp, target, copied);
    BYTE* retTarget = target + copied;
    tramp[copied + 0] = 0xFF; tramp[copied + 1] = 0x25;
    *reinterpret_cast<int32_t*>(tramp + copied + 2) = 0;
    *reinterpret_cast<void**>(tramp + copied + 6) = retTarget;
    FlushInstructionCache(GetCurrentProcess(), tramp, copied + kJmpSize + 8);
    if (outOrig) *outOrig = tramp;

    DWORD oldp = 0;
    if (!VirtualProtect(target, copied, PAGE_EXECUTE_READWRITE, &oldp))
    { VirtualFree(tramp, 0, MEM_RELEASE); return false; }
    BYTE patch[14] = { 0xFF, 0x25, 0,0,0,0, 0,0,0,0,0,0,0,0 };
    *reinterpret_cast<void**>(patch + 6) = newFn;
    std::memcpy(target, patch, kJmpSize);
    if (copied > kJmpSize) std::memset(target + kJmpSize, 0x90, copied - kJmpSize);
    VirtualProtect(target, copied, oldp, &oldp);
    FlushInstructionCache(GetCurrentProcess(), target, copied);
    return true;
}

// ============================ engine bindings ==============================

typedef int   (*PubResume_t)(void* L, void* argSlot, int narg);
typedef int   (*IntResume_t)(void* L);
typedef void* (*NewThread_t)(void* L);
typedef int   (*RawGet_t)(void* L, int idx);
typedef void* (*NewLStr_t)(void* L, const char* s, size_t len);

static PubResume_t g_pubResume  = nullptr;
static IntResume_t g_origResume = nullptr;   // trampoline
static NewThread_t g_newthread  = nullptr;
static RawGet_t    g_rawget     = nullptr;
static NewLStr_t   g_newlstr    = nullptr;

static uint64_t s_allCaps = ~0ULL;           // proto caps target

// --- client-replicator capture (diagnostic only) ---------------------------
// g_clientRepl is the live ClientReplicator captured from its send method (vtable
// slot 134). We only log its layout once for validation - we never write engine
// state here. The actual FE-off mechanism is server-side (the join-bit patch); see
// Docs/FE_Replication_REMap.md section 6e.
// 4 register args forwarded (rcx/rdx/r8/r9) to preserve the ABI - the serialize
// method reads r8 as well as this/rdx.
typedef void (*ReplSend_t)(void* self, uintptr_t a2, uintptr_t a3, uintptr_t a4);
static ReplSend_t     g_origReplSend = nullptr;   // original ClientReplicator slot-134
static ReplSend_t     g_origProcPkt  = nullptr;   // original ClientReplicator::processPacket (reliable capture)
static void* volatile g_clientRepl   = nullptr;   // live ClientReplicator (diagnostic capture)
static volatile long  g_replDumped   = 0;
static ReplSend_t     g_origReplSetup = nullptr;  // original ClientReplicator slot-45 (setup)

// Capture the live ClientReplicator via its slot-45 setup method (0x27AAEC0), which
// runs once at join. Vtable-slot hook (pointer swap) - safe, unlike the inline
// processPacket hook that corrupted sends. Just records `self`, forwards the call.
static void Hook_ReplSetup(void* self, uintptr_t a2, uintptr_t a3, uintptr_t a4)
{
    if (self && !g_clientRepl) g_clientRepl = self;
    g_origReplSetup(self, a2, a3, a4);
}
// --- PROPERTY_CHANGED dispatch observer (0x28a86d0) -------------------------
// The confirmed native path: onCombinedSignal iterates replicators and calls this
// per replicator for every type-2 (property-changed) signal. We hook it purely to
// answer the one open question - does a CLIENT-side property write ever reach the
// client's replicator? - and to latch the REAL argument-struct layout from the
// working new-instance/child dispatches so a synthetic property emit is byte-exact
// rather than guessed. Log-only + SEH-guarded; forwards unconditionally.
typedef void (*Dispatch_t)(void* repl, void* changeStruct, void* signalData, void* a4);
static Dispatch_t     g_origDispatch  = nullptr;
static volatile long  g_dispTotal     = 0;   // all dispatch calls (any replicator)
static volatile long  g_dispClient    = 0;   // calls where repl == g_clientRepl
static uintptr_t      g_dispDump[8]   = {0};  // last client-call struct snapshot
static volatile long  g_dispHaveDump  = 0;

// Extra probe: reverse the Instance->ClassDescriptor offset and the descriptor's
// name field, from a live (Instance*, descriptor) pair. Filled once, read in DrainOfq.
static uintptr_t g_probeInst = 0, g_probeDesc = 0;
static uintptr_t g_probeInstWords[10] = {0};   // *(Instance + 0x08*i)
static uintptr_t g_probeDescWords[10] = {0};   // *(descriptor + 0x08*i)
static uintptr_t g_probeCD = 0;                // ClassDescriptor = *(Instance + 0x18)
static uintptr_t g_probeCDWords[20] = {0};     // *(ClassDescriptor + 0x08*i)
static uintptr_t g_probeDescVt = 0;            // *(descriptor) = PropertyDescriptor vtable
static uintptr_t g_probeVtSlots[32] = {0};     // *(vtable + 0x08*i)  (virtual method targets)

// ================= Instance Guid (referent) read ==========================
// Confirmed from the RBX source functions in the 2022 PDB (serializeId / getReadableDebugId
// / lookupByGuid): in this build Guid::Data is 8 bytes = { int index (+0), int scope (+4) }
// and it lives at Instance+0x30 (GuidItem base: registry @ +0x28, guid @ +0x30). index==-1
// means unassigned. The pair {index,scope} is the wire referent the server resolves via
// its guid Registry (registry pointer = *(inst+0x28)).
static const long kGuidOff     = 0x30;   // guid.index @ inst+0x30, guid.scope @ inst+0x34
static const long kRegistryOff = 0x28;   // GuidItem.registry

// Read the instance's referent as a single u64 = (scope<<32 | index). 0 if unassigned.
static unsigned long long ReadInstanceGuid(uintptr_t inst)
{
    if (!inst) return 0;
    __try
    {
        unsigned index = *reinterpret_cast<unsigned*>(inst + kGuidOff);
        unsigned scope = *reinterpret_cast<unsigned*>(inst + kGuidOff + 4);
        if (index == 0xFFFFFFFFu) return 0;                 // unassigned
        return (static_cast<unsigned long long>(scope) << 32) | index;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) { return 0; }
}

static void DumpDispatch(void* repl, void* cs, void* sd)   // C-only, SEH-safe
{
    __try
    {
        g_dispDump[0] = reinterpret_cast<uintptr_t>(repl);
        g_dispDump[1] = cs ? *reinterpret_cast<uintptr_t*>(reinterpret_cast<char*>(cs) + 0x00) : 0;
        g_dispDump[2] = cs ? *reinterpret_cast<uintptr_t*>(reinterpret_cast<char*>(cs) + 0x08) : 0; // Instance*
        g_dispDump[3] = cs ? *reinterpret_cast<uintptr_t*>(reinterpret_cast<char*>(cs) + 0x18) : 0;
        g_dispDump[4] = cs ? *reinterpret_cast<uintptr_t*>(reinterpret_cast<char*>(cs) + 0x28) : 0;
        g_dispDump[5] = sd ? *reinterpret_cast<uintptr_t*>(reinterpret_cast<char*>(sd) + 0x00) : 0;
        g_dispDump[6] = sd ? *reinterpret_cast<uintptr_t*>(reinterpret_cast<char*>(sd) + 0x08) : 0; // PropertyDescriptor*
        g_dispDump[7] = reinterpret_cast<uintptr_t>(sd);
        // Structural probe: raw words of the Instance and the PropertyDescriptor so we
        // can locate ClassDescriptor (on the Instance) and the name field (on the desc).
        uintptr_t inst = g_dispDump[2], desc = g_dispDump[6];
        g_probeInst = inst; g_probeDesc = desc;
        for (int i = 0; i < 10; ++i)
        {
            g_probeInstWords[i] = inst ? *reinterpret_cast<uintptr_t*>(reinterpret_cast<char*>(inst) + 8 * i) : 0;
            g_probeDescWords[i] = desc ? *reinterpret_cast<uintptr_t*>(reinterpret_cast<char*>(desc) + 8 * i) : 0;
        }
        uintptr_t cd = inst ? *reinterpret_cast<uintptr_t*>(reinterpret_cast<char*>(inst) + 0x18) : 0;
        g_probeCD = cd;
        for (int i = 0; i < 20; ++i)
            g_probeCDWords[i] = cd ? *reinterpret_cast<uintptr_t*>(reinterpret_cast<char*>(cd) + 8 * i) : 0;
        // PropertyDescriptor vtable + its virtual-method slots (to locate the setter).
        uintptr_t vt = desc ? *reinterpret_cast<uintptr_t*>(desc) : 0;
        g_probeDescVt = vt;
        for (int i = 0; i < 32; ++i)
            g_probeVtSlots[i] = vt ? *reinterpret_cast<uintptr_t*>(vt + 8 * i) : 0;
        g_dispHaveDump = 1;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {}
}

// Also latch the Instance's vtable RVA so we can identify its class, and record
// whether repl relates to the captured client replicator.
static uintptr_t g_dispInstVt = 0;   // *(Instance*) = its vtable (module-relative tells class)
static void* volatile g_dispRepl = nullptr;   // repl object observed IN the dispatcher (real ctx)
static void Hook_Dispatch(void* repl, void* cs, void* sd, void* a4)
{
    InterlockedIncrement(&g_dispTotal);
    if (repl && !g_dispRepl) g_dispRepl = repl;   // capture the real dispatch context (slot-45 missed)
    if (repl && repl == g_clientRepl) InterlockedIncrement(&g_dispClient);
    // Dump the FIRST real dispatch of ANY replicator (dispClient is 0, so the
    // client-only dump never fired). This reveals the exact struct layout + what
    // object `repl` is, which is what a synthetic emit must reproduce.
    if (!g_dispHaveDump)
    {
        DumpDispatch(repl, cs, sd);
        __try {
            uintptr_t inst = g_dispDump[2];
            if (inst) g_dispInstVt = *reinterpret_cast<uintptr_t*>(inst);   // Instance vtable
        } __except (EXCEPTION_EXECUTE_HANDLER) {}
    }
    g_origDispatch(repl, cs, sd, a4);
}

// ---- Native property-change emit -------------------------------------------
// Resolve (Instance*, propName) -> PropertyDescriptor* by walking the class's
// property list. Layout confirmed at runtime from a live dispatch:
//   ClassDescriptor  = *(Instance + 0x18)
//   property array   = *(ClassDescriptor + 0x40)  (array of PropertyDescriptor*)
//   property count   = *(ClassDescriptor + 0x48)
//   property name    = *(PropertyDescriptor + 0x08)  (char*)
// SEH-guarded (walks engine structs). Returns nullptr on miss/fault.
static const uintptr_t kCDOff       = 0x18;
static const uintptr_t kPropArrOff  = 0x40;
static const uintptr_t kPropCntOff  = 0x48;
static const uintptr_t kDescNameOff = 0x08;

static void* ResolveDescriptor(void* instance, const char* propName)
{
    if (!instance || !propName) return nullptr;
    __try
    {
        uintptr_t cd = *reinterpret_cast<uintptr_t*>(reinterpret_cast<char*>(instance) + kCDOff);
        if (!cd) return nullptr;
        uintptr_t begin = *reinterpret_cast<uintptr_t*>(cd + kPropArrOff);
        uintptr_t count = *reinterpret_cast<uintptr_t*>(cd + kPropCntOff);
        if (!begin || count == 0 || count > 8192) return nullptr;
        for (uintptr_t i = 0; i < count; ++i)
        {
            uintptr_t pd = *reinterpret_cast<uintptr_t*>(begin + i * 8);
            if (!pd) continue;
            const char* nm = *reinterpret_cast<const char**>(pd + kDescNameOff);
            if (nm && std::strcmp(nm, propName) == 0) return reinterpret_cast<void*>(pd);
        }
        return nullptr;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) { return nullptr; }
}

// Verify a resolved descriptor's name really matches (guards against a bad walk).
static bool DescNameMatches(void* desc, const char* propName)
{
    if (!desc || !propName) return false;
    __try
    {
        const char* nm = *reinterpret_cast<const char**>(reinterpret_cast<char*>(desc) + kDescNameOff);
        return nm && std::strcmp(nm, propName) == 0;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}

// Force the engine to enqueue a ChangePropertyItem for (instance, desc) by calling
// the dispatcher exactly the way onCombinedSignal does for a type-2 signal:
//   rcx = repl (dispatch context, captured live from the dispatcher)
//   rdx = changeStruct { +8 = Instance* }   (+0x18/+0x28 observed as 0)
//   r8  = sigData      { +8 = PropertyDescriptor* }
// SEH-guarded. Returns true if the call returned without faulting.
static bool EmitChange(void* repl, void* instance, void* desc)
{
    if (!repl || !instance || !desc || !g_origDispatch) return false;
    __try
    {
        uintptr_t cs[6] = {0};   // change-struct (0x30), +8 = Instance*
        uintptr_t sd[2] = {0};   // signal-data  (0x10), +8 = descriptor
        cs[1] = reinterpret_cast<uintptr_t>(instance);
        sd[1] = reinterpret_cast<uintptr_t>(desc);
        g_origDispatch(repl, cs, sd, nullptr);
        return true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}

static volatile long g_emitOK = 0, g_emitResolveFail = 0;

// getValue: call the descriptor's get-accessor to box the current value into a Variant.
//   accessor = *(descriptor + 0x90); getValue = accessor.vtable[+0x18](accessor, &out, instance)
// The Variant is POD for value types (number/Vector3/CFrame/Color3/UDim2/bool/Enum), so it
// copies across the relay to the server's setValue. SEH-guarded. Returns bytes written (fixed).
static const int kVariantSize = 96;   // holds tag + largest value payload (CFrame = 48)
static bool GetValueVariant(void* desc, void* instance, void* outVariant)
{
    if (!desc || !instance) return false;
    __try
    {
        void* accessor = *reinterpret_cast<void**>(reinterpret_cast<char*>(desc) + 0x90);
        if (!accessor) return false;
        void* vt = *reinterpret_cast<void**>(accessor);
        typedef void (*GetVal_t)(void* acc, void* out, void* inst);
        GetVal_t fn = *reinterpret_cast<GetVal_t*>(reinterpret_cast<char*>(vt) + 0x18);
        if (!fn) return false;
        fn(accessor, outVariant, instance);
        return true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}

// Binary relay to the server (exported by RobloxStudioPatcher.dll as OffBloxRelayServerBin).
typedef void (*RelayBin_t)(const void*, int);
static RelayBin_t g_relayBin = nullptr;
static void ResolveRelayBin()
{
    if (g_relayBin) return;
    typedef BOOL (WINAPI *EnumMods_t)(HANDLE, HMODULE*, DWORD, LPDWORD);
    HMODULE k32 = GetModuleHandleW(L"kernel32.dll");
    EnumMods_t enumMods = k32 ? reinterpret_cast<EnumMods_t>(GetProcAddress(k32, "K32EnumProcessModules")) : nullptr;
    if (!enumMods) return;
    HMODULE mods[512]; DWORD needed = 0;
    if (enumMods(GetCurrentProcess(), mods, sizeof(mods), &needed))
    {
        int n = (int)(needed / sizeof(HMODULE)); if (n > 512) n = 512;
        for (int i = 0; i < n; ++i)
        {
            FARPROC p = GetProcAddress(mods[i], "OffBloxRelayServerBin");
            if (p) { g_relayBin = reinterpret_cast<RelayBin_t>(p); break; }
        }
    }
}

// Build + ship a property-change packet: [guid64(8)][propLen(1)][prop][varLen(1)][variant].
static volatile long g_shipOK = 0, g_shipFail = 0;
static void ShipGuidChange(void* instance, const char* prop, void* desc)
{
    if (!g_relayBin || !instance || !prop || !desc) { g_shipFail++; return; }
    __try
    {
        unsigned long long guid64 = ReadInstanceGuid(reinterpret_cast<uintptr_t>(instance));
        if (!guid64) { g_shipFail++; return; }
        char var[kVariantSize] = {0};
        if (!GetValueVariant(desc, instance, var)) { g_shipFail++; return; }
        // One-time raw dump of the getValue Variant so the server-side layout can be
        // decoded (is +0 an 8-byte Type* or a 4-byte type index? where is the value?).
        static volatile long s_vlog = 0;
        if (s_vlog < 12)
        {
            InterlockedIncrement(&s_vlog);
            // Dump all 96 bytes across 2 lines so the type tag (past the value payload -
            // a CFrame value alone is 48 bytes) is visible. Look for an 8-byte pointer
            // (00 .. 7F ptr) or a small int index near the end.
            char hx[260]; int hp = 0;
            hp += _snprintf_s(hx + hp, sizeof(hx) - hp, _TRUNCATE, "[ofq-dll] VARDUMP prop=%s [0..47]:", prop);
            for (int i = 0; i < 48 && hp < (int)sizeof(hx) - 4; ++i)
                hp += _snprintf_s(hx + hp, sizeof(hx) - hp, _TRUNCATE, " %02X", (unsigned char)var[i]);
            LogC(hx);
            hp = 0;
            hp += _snprintf_s(hx + hp, sizeof(hx) - hp, _TRUNCATE, "[ofq-dll] VARDUMP prop=%s [48..95]:", prop);
            for (int i = 48; i < 96 && hp < (int)sizeof(hx) - 4; ++i)
                hp += _snprintf_s(hx + hp, sizeof(hx) - hp, _TRUNCATE, " %02X", (unsigned char)var[i]);
            LogC(hx);
        }
        int plen = (int)strnlen_s(prop, 64);
        char blob[8 + 1 + 64 + 1 + kVariantSize];
        int o = 0;
        std::memcpy(blob + o, &guid64, 8); o += 8;
        blob[o++] = (char)plen;
        std::memcpy(blob + o, prop, plen); o += plen;
        blob[o++] = (char)kVariantSize;
        std::memcpy(blob + o, var, kVariantSize); o += kVariantSize;
        g_relayBin(blob, o);
        g_shipOK++;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) { g_shipFail++; }
}

// Referent probe: find where the client replicator (or a structure it owns) stores a
// live instance pointer - that's the instance->id registry, and the id sits adjacent.
// Bounded + SEH-guarded; runs once off the hot path.
static uintptr_t g_refAt = 0, g_refContainer = 0;
static uintptr_t g_refCw[16] = {0};    // window around the instance
static uintptr_t g_refNmW[8] = {0};    // *(at-8) fields (node-minus target)
static uintptr_t g_refNpW[8] = {0};    // *(at+8) fields (node-plus target)
static long      g_refInstOffInContainer = -1;
static volatile long g_refDone = 0;
static void CaptureRefContainer(uintptr_t container, uintptr_t at)
{
    __try
    {
        g_refContainer = container; g_refAt = at;
        g_refInstOffInContainer = (long)(at - container);
        // Dump the WINDOW AROUND the instance pointer (at-0x40 .. at+0x38).
        for (int i = 0; i < 16; ++i)
            g_refCw[i] = *reinterpret_cast<uintptr_t*>(at - 0x40 + 8 * i);
        // Follow the two adjacent node pointers one level (the id lives behind one of
        // them, e.g. a ReplicationData / Guid holding the network id).
        uintptr_t nm = *reinterpret_cast<uintptr_t*>(at - 8);   // node minus
        uintptr_t np = *reinterpret_cast<uintptr_t*>(at + 8);   // node plus
        for (int i = 0; i < 8; ++i)
        {
            g_refNmW[i] = (nm > 0x10000 && !(nm & 7)) ? *reinterpret_cast<uintptr_t*>(nm + 8 * i) : 0;
            g_refNpW[i] = (np > 0x10000 && !(np & 7)) ? *reinterpret_cast<uintptr_t*>(np + 8 * i) : 0;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {}
}
// Does the window around `at` contain a plausible small-int network id?
static bool HasSmallIntNeighbor(uintptr_t at, uintptr_t* idOut, long* idOffOut)
{
    __try
    {
        for (long o = -0x18; o <= 0x18; o += 8)
        {
            if (o == 0) continue;
            uintptr_t v = *reinterpret_cast<uintptr_t*>(at + o);
            if (v > 0 && v < 0x2000000) { *idOut = v; *idOffOut = o; return true; }   // 1..~33M
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {}
    return false;
}
static uintptr_t g_refId = 0; static long g_refIdOff = 0;
static void ScanReplForInstance(uintptr_t repl, uintptr_t inst)
{
    if (!repl || !inst || g_refDone) return;
    g_refDone = 1;
    __try
    {
        // Find the occurrence of the instance pointer that has a small-int id neighbor
        // (the network-id registry), preferred over shared_ptr/tree containers.
        for (unsigned off = 0; off < 0x1000; off += 8)
        {
            uintptr_t p = *reinterpret_cast<uintptr_t*>(repl + off);
            if (p <= 0x10000 || (p & 7)) continue;
            __try
            {
                for (unsigned o2 = 0; o2 < 0x8000; o2 += 8)
                {
                    if (*reinterpret_cast<uintptr_t*>(p + o2) != inst) continue;
                    uintptr_t id = 0; long idoff = 0;
                    if (HasSmallIntNeighbor(p + o2, &id, &idoff))
                    {
                        g_refId = id; g_refIdOff = idoff;
                        CaptureRefContainer(p, p + o2);
                        return;
                    }
                }
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {}
        }
        // Fallback: first occurrence anywhere (for the window dump).
        for (unsigned off = 0; off < 0x1000; off += 8)
        {
            uintptr_t p = *reinterpret_cast<uintptr_t*>(repl + off);
            if (p <= 0x10000 || (p & 7)) continue;
            __try
            {
                for (unsigned o2 = 0; o2 < 0x8000; o2 += 8)
                    if (*reinterpret_cast<uintptr_t*>(p + o2) == inst) { CaptureRefContainer(p, p + o2); return; }
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {}
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {}
}

// Observer on the Mega-enqueue (0x14299F740) - the function the dispatcher calls to
// actually push a ChangePropertyItem into the outgoing queue. Counting it tells us
// whether our synthetic dispatches reach the enqueue (=> block is the send-flush) or
// no-op inside the dispatcher (=> our struct/repl is wrong). Log-only.
typedef void (*MegaEnq_t)(void* item, void* repl, void* a3, void* a4);
static MegaEnq_t     g_origMegaEnq = nullptr;
static volatile long g_enqTotal    = 0;
static void Hook_MegaEnq(void* item, void* repl, void* a3, void* a4)
{
    InterlockedIncrement(&g_enqTotal);
    g_origMegaEnq(item, repl, a3, a4);
}
static const uintptr_t kMegaEnqRva = 0x299F740;

// SEH-guarded read of a short C string at p (C-only so __try is legal). Returns
// true and fills out[] if p points to printable ASCII.
static bool ProbeStr(uintptr_t p, char* out, int cap)
{
    if (!p || cap < 2) return false;
    __try
    {
        const char* s = reinterpret_cast<const char*>(p);
        int i = 0;
        for (; i < cap - 1; ++i)
        {
            char c = s[i];
            if (c == 0) break;
            if (c < 0x20 || c > 0x7E) { out[0] = 0; return false; }
            out[i] = c;
        }
        out[i] = 0;
        return i >= 2;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) { out[0] = 0; return false; }
}

// SEH-guarded qword read (C-only). Returns *(p) or 0 on fault/null.
static uintptr_t ProbeDeref(uintptr_t p)
{
    if (!p) return 0;
    __try { return *reinterpret_cast<uintptr_t*>(p); }
    __except (EXCEPTION_EXECUTE_HANDLER) { return 0; }
}

static void ForceClientFeOff(void* self, bool report);   // defined below; nulls the strictFilter

// --- outgoing value serializer (serializeValue @ 0x2724260) -----------------
// In this build serializeValue THROWS on a value type it can't encode (the
// `else { return false; }` of 2016 was compiled to a throw + int3). That throw
// unwinds the whole outgoing packet -> RakNet "Error while sending" -> both ends
// disconnect. With strictFilter null the client now tries to serialize its full
// changed set, and one property whose type has no outgoing wire format takes the
// client down at join. We wrap the call: on the throw we log the offending
// type-id and return false (skip the value) instead of letting the exception kill
// the connection. This (a) names the culprit type and (b) may keep the session
// alive if the caller drops the item cleanly on false.
typedef char (__fastcall *SerVal_t)(void* type, void* value, unsigned char useDict, void* bitstream);
static SerVal_t g_origSerVal = nullptr;

// ============================ script queue =================================

static std::deque<std::string> g_queue;
static std::mutex              g_qmtx;
static volatile long          g_pending = 0;
static volatile long          g_inExec  = 0;


static void EnqueueScript(const std::string& code)
{
    if (code.empty()) return;
    { std::lock_guard<std::mutex> lk(g_qmtx); g_queue.push_back(code); }
    InterlockedExchange(&g_pending, 1);
}
static bool Dequeue(std::string& out)
{
    std::lock_guard<std::mutex> lk(g_qmtx);
    if (g_queue.empty()) { InterlockedExchange(&g_pending, 0); return false; }
    out = std::move(g_queue.front()); g_queue.pop_front();
    if (g_queue.empty()) InterlockedExchange(&g_pending, 0);
    return true;
}

// ============================ VM helpers ===================================

static inline char* Top(void* L){ return *reinterpret_cast<char**>(reinterpret_cast<char*>(L)+kOffTop); }
static inline void  SetTop(void* L, char* t){ *reinterpret_cast<char**>(reinterpret_cast<char*>(L)+kOffTop)=t; }
static inline char* Base(void* L){ return *reinterpret_cast<char**>(reinterpret_cast<char*>(L)+kOffBase); }
static inline void* MainThread(void* L)
{
    char* g = *reinterpret_cast<char**>(reinterpret_cast<char*>(L) + kOffGlobal);
    return *reinterpret_cast<void**>(g + kOffMainTh);
}

static void PushString(void* L, const std::string& s)
{
    char* t = Top(L);
    void* ts = g_newlstr(L, s.data(), s.size());
    *reinterpret_cast<void**>(t + 0)    = ts;
    *reinterpret_cast<int*>(t + kOffTT) = kTagString;
    SetTop(L, t + kTValSize);
}
// Push a Luau number (stored as a double at TValue+0, tag kTagNumber).
static void PushInt(void* L, long long v)
{
    char* t = Top(L);
    *reinterpret_cast<double*>(t + 0)   = static_cast<double>(v);
    *reinterpret_cast<int*>(t + kOffTT) = kTagNumber;
    SetTop(L, t + kTValSize);
}
static int RawGetGlobal(void* L, const char* name)
{
    PushString(L, std::string(name));
    return g_rawget(L, kGlobalsIdx);
}
static void ElevateClosureCaps(void* closure)
{
    if (!closure) return;
    void* proto = *reinterpret_cast<void**>(reinterpret_cast<char*>(closure) + 0x20);
    if (proto) *reinterpret_cast<void**>(reinterpret_cast<char*>(proto) + 0x48) = &s_allCaps;
}

// Compile `code` on a fresh thread (borrowing the mainthread gt + a private
// cap-elevated ExtraSpace) and hand the compiled function to the game's own
// scheduler via task.defer. task.defer only queues a coroutine - it never touches
// the DataModel - so calling it from inside the resume hook is safe; the code
// itself runs at a normal frame boundary. Running DataModel code inline here
// deadlocks the client on its DataModel lock (a hard freeze).
static bool TaskDefer(void* L, const std::string& code, bool quiet)
{
    char* saveTop = Top(L);
    void* mt      = MainThread(L);
    void* mainGT  = *reinterpret_cast<void**>(reinterpret_cast<char*>(mt) + kOffGT);
    void* mtExtra = *reinterpret_cast<void**>(reinterpret_cast<char*>(mt) + kOffExtra);

    static unsigned char s_extra[0x100];
    std::memcpy(s_extra, mtExtra, sizeof(s_extra));
    *reinterpret_cast<uint64_t*>(s_extra + kOffCaps) = ~0x8ULL;   // clear bit3(restricted)
    void* myExtra = s_extra;

    void* NL = g_newthread(L);
    if (!NL) { SetTop(L, saveTop); return false; }
    *reinterpret_cast<void**>(reinterpret_cast<char*>(NL) + kOffGT)    = mainGT;
    *reinterpret_cast<void**>(reinterpret_cast<char*>(NL) + kOffExtra) = myExtra;
    struct ExtraGuard {
        void* th[1] = { nullptr };
        ~ExtraGuard(){ for (void* x : th) if (x)
            *reinterpret_cast<void**>(reinterpret_cast<char*>(x) + kOffExtra) = nullptr; }
    } eg;
    eg.th[0] = NL;

    // 1. compile: loadstring(code) -> F  (compilation touches no DataModel)
    LogC("td: fetch loadstring");
    if (RawGetGlobal(NL, "loadstring") != kTagFunc)
    { if (!quiet) Log(std::string("loadstring unavailable - dropping: ") + code); SetTop(L, saveTop); return false; }
    PushString(NL, code);
    char* nlb = Base(NL);
    LogC("td: compiling (resume)");
    try { g_pubResume(NL, nlb + kTValSize, 1); }
    catch (const std::exception& e) { SetTop(L, saveTop); if (!quiet) Log(std::string("loadstring threw: ") + e.what()); return false; }
    catch (...)                     { SetTop(L, saveTop); if (!quiet) LogC("loadstring threw: <non-std>"); return false; }

    char* nltop = Top(NL);
    if (nltop <= nlb || *reinterpret_cast<int*>(nlb + kOffTT) != kTagFunc)
    {
        if (!quiet)
        {
            int topTT = (nltop > nlb) ? *reinterpret_cast<int*>(nltop - kTValSize + kOffTT) : -99;
            if (topTT == kTagString)
                Log(std::string("compile error: ") +
                    (reinterpret_cast<const char*>(*reinterpret_cast<void**>(nltop - kTValSize)) + 0x18));
            else Log(std::string("compile error: ") + code);
        }
        SetTop(L, saveTop); return false;
    }
    LogC("td: compiled ok");
    ElevateClosureCaps(*reinterpret_cast<void**>(nlb));   // F's proto -> full caps

    // 2. task.defer(F). Stack: F@nlb+0. Fetch task, then task.defer, then call.
    //    (Stable baseline: engine-managed coroutine. Corescript identity can't be
    //    granted by poking ExtraSpace - see notes - so we just run F normally.)
    if (RawGetGlobal(NL, "task") != kTagTable)            // task table @ nlb+0x10
    { if (!quiet) LogC("task global missing"); SetTop(L, saveTop); return false; }
    PushString(NL, "defer");                              // "defer" @ nlb+0x20
    g_rawget(NL, 2);                                      // task.defer @ nlb+0x20 (idx 2 = task)
    if (*reinterpret_cast<int*>(nlb + 0x20 + kOffTT) != kTagFunc)
    { if (!quiet) LogC("task.defer missing"); SetTop(L, saveTop); return false; }
    std::memcpy(nlb + 0x30, nlb + 0x20, kTValSize);       // [task.defer]
    std::memcpy(nlb + 0x40, nlb + 0x00, kTValSize);       // [F]
    SetTop(NL, nlb + 0x50);
    LogC("td: calling task.defer (resume)");
    try { g_pubResume(NL, nlb + 0x40, 1); }               // task.defer(F) - queues, returns the coroutine
    catch (const std::exception& e) { SetTop(L, saveTop); if (!quiet) Log(std::string("defer threw: ") + e.what()); return false; }
    catch (...)                     { SetTop(L, saveTop); if (!quiet) LogC("defer threw: <non-std>"); return false; }

    // Best-effort: raise the returned coroutine's cap mask (helps basic Instance
    // access; does NOT grant corescript identity - that check ignores ExtraSpace).
    {
        char* rb = nlb + 0x30;
        if (Top(NL) > rb && *reinterpret_cast<int*>(rb + kOffTT) == kTagThread)
        {
            void* co = *reinterpret_cast<void**>(rb);
            void* coExtra = co ? *reinterpret_cast<void**>(reinterpret_cast<char*>(co) + kOffExtra) : nullptr;
            if (coExtra)
                *reinterpret_cast<uint64_t*>(reinterpret_cast<char*>(coExtra) + kOffCaps) = ~0x8ULL;
        }
    }

    LogC("td: task.defer returned");
    SetTop(L, saveTop);
    if (!quiet) Log(std::string("scheduled: ") + code);
    return true;
}

// ============================ scheduler drain ==============================

static void* g_serverGlobal = nullptr;   // cached global_State of the locked game VM
static void* g_probed[24];
static int   g_nprobed = 0;

// Read the global __offblox_player (a string the deferred detector writes with the
// LocalPlayer's name) via raw lookup only - safe, no DataModel access. Returns the
// name (non-empty) if this VM has a LocalPlayer, else "".
static std::string ReadPlayerFlag(void* L)
{
    char* saveTop = Top(L);
    void* mt = MainThread(L);
    void* mainGT = *reinterpret_cast<void**>(reinterpret_cast<char*>(mt) + kOffGT);
    void* NL = g_newthread(L);
    if (!NL) { SetTop(L, saveTop); return ""; }
    *reinterpret_cast<void**>(reinterpret_cast<char*>(NL) + kOffGT) = mainGT;
    std::string out;
    if (RawGetGlobal(NL, "__offblox_player") == kTagString)
        out = reinterpret_cast<const char*>(*reinterpret_cast<void**>(Base(NL))) + 0x18;
    SetTop(L, saveTop);
    return out;
}

// ===================== native property-repl drain (V1: log-only) ===========
// The preamble queues {instance,propName} into globals __ofq/__ofp (count __ofn,
// generation __ofg). We drain here on the VM thread. V1 only LOGS the raw
// instance userdata bytes + property name so we can pin the Instance* offset and
// confirm the pipeline before enabling the native enqueue in V2.
static long      g_ofqDrained = 0;
static long      g_ofqGen     = -1;
static ULONGLONG g_ofqLastMs  = 0;

// Read a global number; false if absent/not-a-number.
static bool ReadGlobalNumber(void* L, const char* name, double* out)
{
    char* saveTop = Top(L);
    void* mt = MainThread(L);
    void* mainGT = *reinterpret_cast<void**>(reinterpret_cast<char*>(mt) + kOffGT);
    void* NL = g_newthread(L);
    if (!NL) { SetTop(L, saveTop); return false; }
    *reinterpret_cast<void**>(reinterpret_cast<char*>(NL) + kOffGT) = mainGT;
    bool ok = false;
    if (RawGetGlobal(NL, name) == kTagNumber) { *out = *reinterpret_cast<double*>(Base(NL)); ok = true; }
    SetTop(L, saveTop);
    return ok;
}

// Read global-table[i]; returns the Luau tag, *valOut = TValue value word.
static int ReadTableElem(void* L, const char* tbl, long i, void** valOut)
{
    *valOut = nullptr;
    char* saveTop = Top(L);
    void* mt = MainThread(L);
    void* mainGT = *reinterpret_cast<void**>(reinterpret_cast<char*>(mt) + kOffGT);
    void* NL = g_newthread(L);
    if (!NL) { SetTop(L, saveTop); return -1; }
    *reinterpret_cast<void**>(reinterpret_cast<char*>(NL) + kOffGT) = mainGT;
    int tag = -1;
    if (RawGetGlobal(NL, tbl) == kTagTable)      // table now at stack index 1 (Base+0)
    {
        PushInt(NL, i);
        tag = g_rawget(NL, 1);
        *valOut = *reinterpret_cast<void**>(Top(NL) - kTValSize);
    }
    SetTop(L, saveTop);
    return tag;
}

// Main-module address range (for identifying Instance vtables inside a userdata).
static uintptr_t g_modLo = 0, g_modLen = 0;
static bool InMod(uintptr_t p)
{
    if (!g_modLo)
    {
        g_modLo = reinterpret_cast<uintptr_t>(GetModuleHandleW(nullptr));
        if (g_modLo)
        {
            auto dos = reinterpret_cast<IMAGE_DOS_HEADER*>(g_modLo);
            auto nt  = reinterpret_cast<IMAGE_NT_HEADERS*>(g_modLo + dos->e_lfanew);
            g_modLen = nt->OptionalHeader.SizeOfImage;
        }
    }
    return g_modLo && p >= g_modLo && p < g_modLo + g_modLen;
}

// The detected offset of the raw Instance* inside the Luau userdata payload.
static long g_instOff = -2;   // -2 = not started, -1 = searching, >=0 = locked

// SEH-guarded. No C++ objects here so __try is legal. While the Instance* offset
// is unknown, probe each userdata for the word whose target's first qword is a
// vtable inside the main module (= an RBX::Instance) and lock that offset.
static void LogOfqEntry(long i, int utag, const char* prop, void* ud)
{
    if (g_instOff >= 0 || !ud) return;   // locked already, or nothing to probe
    __try
    {
        unsigned char* base = reinterpret_cast<unsigned char*>(ud);
        for (int off = 0; off <= 0x40; off += 8)
        {
            uintptr_t w = *reinterpret_cast<uintptr_t*>(base + off);
            if (w > 0x10000 && (w & 7) == 0)
            {
                uintptr_t vt = *reinterpret_cast<uintptr_t*>(w);   // candidate Instance vtable
                if (InMod(vt))
                {
                    g_instOff = off;
                    char b[160];
                    _snprintf_s(b, sizeof(b), _TRUNCATE,
                        "ofq: LOCKED Instance* @ ud+0x%X (utag=%d prop=%s inst=%p vtbl=%p)",
                        off, utag, prop, reinterpret_cast<void*>(w), reinterpret_cast<void*>(vt));
                    LogC(b);
                    return;
                }
            }
        }
        // Not found this entry -> log a compact probe so we can pin it manually.
        char b[200];
        _snprintf_s(b, sizeof(b), _TRUNCATE,
            "ofq probe utag=%d prop=%s ud=%p +0=%p +8=%p +10=%p +18=%p +20=%p +28=%p",
            utag, prop, ud, *reinterpret_cast<void**>(base + 0), *reinterpret_cast<void**>(base + 8),
            *reinterpret_cast<void**>(base + 0x10), *reinterpret_cast<void**>(base + 0x18),
            *reinterpret_cast<void**>(base + 0x20), *reinterpret_cast<void**>(base + 0x28));
        LogC(b);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) { LogC("ofq probe FAULT"); }
}

static ULONGLONG g_ofqHbMs = 0;
static long      g_instReported = 0;   // have we print()ed the offset to Studio yet

// --- property-replication relay (client -> server VM via RobloxStudioCommunication.dll)
// The shared DLL exports OffBloxRelayServerLua(const char*). We resolve it once by
// scanning loaded modules (name-agnostic) and hand it each captured Lua assignment
// statement; the relay ships it to the host as a v10 magic packet and the server runs
// it. Pure C++/DLL pipe - no in-game object, nothing a game script can see or delete.
typedef void (*RelaySend_t)(const char*);
static RelaySend_t g_relaySend = nullptr;
static ULONGLONG   g_relayLastTry = 0;
static long        g_ofsShipped = 0;
static volatile long g_gatesOpened = 0;   // count of send/scope gates successfully patched (post-join)

static void ResolveRelaySend()
{
   /* if (g_relaySend) return;                       // found already
    ULONGLONG now = GetTickCount64();
    if (now - g_relayLastTry < 2000) return;       // throttle module scans to ~2s
    g_relayLastTry = now;
    // K32EnumProcessModules lives in kernel32 (no psapi import needed). The shared
    // RobloxStudioCommunication.dll may map after we first look, so we keep retrying.
    typedef BOOL (WINAPI *EnumMods_t)(HANDLE, HMODULE*, DWORD, LPDWORD);
    HMODULE k32 = GetModuleHandleW(L"kernel32.dll");
    EnumMods_t enumMods = k32 ? reinterpret_cast<EnumMods_t>(
        GetProcAddress(k32, "K32EnumProcessModules")) : nullptr;
    if (!enumMods) return;
    HMODULE mods[512]; DWORD needed = 0;
    if (enumMods(GetCurrentProcess(), mods, sizeof(mods), &needed))
    {
        int n = (int)(needed / sizeof(HMODULE));
        if (n > 512) n = 512;
        for (int i = 0; i < n; ++i)
        {
            FARPROC p = GetProcAddress(mods[i], "OffBloxRelayServerLua");
            if (p) { g_relaySend = reinterpret_cast<RelaySend_t>(p); break; }
        }
    }*/
}

// SEH-guarded ship (C types only, so __try is legal here - DrainOfq itself builds
// std::string temporaries and therefore cannot host a __try without C2712).
static void ShipStmt(RelaySend_t fn, const char* stmt)
{
    __try { fn(stmt); }
    __except (EXCEPTION_EXECUTE_HANDLER) { LogC("relaySend FAULT"); }
}

static void DrainOfq(void* L)
{
    // throttle to ~150ms so we don't spawn scratch threads every resume tick
    /*ULONGLONG now = GetTickCount64();
    if (now - g_ofqLastMs < 150) return;
    g_ofqLastMs = now;

    double gd, nd;
    bool haveG = ReadGlobalNumber(L, "__ofg", &gd);   // capture generation
    bool haveN = ReadGlobalNumber(L, "__ofn", &nd);   // captured-change count

    if (!haveG || !haveN) return;   // capture machinery not up on this VM yet
    ResolveRelaySend();             // find the shared-DLL export (once)

    // Heartbeat every ~5s, ROUTED TO STUDIO OUTPUT via print() so it lands next to
    // the [ofq] lines (not the separate pipe/exploit console).
    if (now - g_ofqHbMs > 5000)
    {
        g_ofqHbMs = now;
        char b[220];
        _snprintf_s(b, sizeof(b), _TRUNCATE,
            "print('[ofq-dll] drain alive captured=%.0f shipOK=%ld shipFail=%ld bin=%d')",
            nd, g_shipOK, g_shipFail, g_relayBin ? 1 : 0);
        TaskDefer(L, std::string(b),true);

        static long s_dumpReported = 0;
        if (g_dispHaveDump && !s_dumpReported)
        {
            s_dumpReported = 1;
            uintptr_t modBase = reinterpret_cast<uintptr_t>(GetModuleHandleW(nullptr));
            uintptr_t instVtRva = g_dispInstVt > modBase ? g_dispInstVt - modBase : 0;
            uintptr_t descRva   = g_dispDump[6] > modBase ? g_dispDump[6] - modBase : 0;
            (void)descRva;
            uintptr_t replRel   = (g_clientRepl && g_dispDump[0] >= reinterpret_cast<uintptr_t>(g_clientRepl))
                                  ? g_dispDump[0] - reinterpret_cast<uintptr_t>(g_clientRepl) : (uintptr_t)-1;
            char d[300];
            _snprintf_s(d, sizeof(d), _TRUNCATE,
                "print('[ofq-dll] DISP repl=%p InstVtRVA=0x%llX DescRVA=0x%llX modBase=%p cs18=%p cs28=%p')",
                reinterpret_cast<void*>(g_dispDump[0]), (unsigned long long)instVtRva,
                (unsigned long long)descRva, reinterpret_cast<void*>(modBase),
                reinterpret_cast<void*>(g_dispDump[3]), reinterpret_cast<void*>(g_dispDump[4]));
            (void)replRel;
            TaskDefer(L, std::string(d),true);

            char iw[460]; int iwl = 0;
            iwl += _snprintf_s(iw + iwl, sizeof(iw) - iwl, _TRUNCATE, "print('[ofq-dll] NAMESCAN");
            for (int off = 0x8; off <= 0x90 && iwl < (int)sizeof(iw) - 40; off += 8)
            {
                uintptr_t addr = g_probeInst + off;
                char nm3[28]; nm3[0] = 0;
                if (ProbeStr(addr, nm3, 24))                                   // inline SSO string
                    iwl += _snprintf_s(iw + iwl, sizeof(iw) - iwl, _TRUNCATE, " i+%X=[%s]", (unsigned)off, nm3);
                else if (ProbeStr(ProbeDeref(addr), nm3, 24))                  // char* at inst+off
                    iwl += _snprintf_s(iw + iwl, sizeof(iw) - iwl, _TRUNCATE, " p+%X=[%s]", (unsigned)off, nm3);
            }
            _snprintf_s(iw + iwl, sizeof(iw) - iwl, _TRUNCATE, "')");
            TaskDefer(L, std::string(iw), true);

            char nm[8][40];
            for (int i = 0; i < 8; ++i)
            {
                nm[i][0] = 0;
                if (!ProbeStr(g_probeDescWords[i], nm[i], 32))
                {
                    // try one deref (name may be a pointer-to-struct whose +0 is the string)
                    ProbeStr(ProbeDeref(g_probeDescWords[i]), nm[i], 32);
                }
            }
            char dw[400];
            _snprintf_s(dw, sizeof(dw), _TRUNCATE,
                "print('[ofq-dll] DESCW +8=%p(%s) +10=%p(%s) +18=%p(%s) +20=%p(%s) +28=%p(%s)')",
                reinterpret_cast<void*>(g_probeDescWords[1]), nm[1],
                reinterpret_cast<void*>(g_probeDescWords[2]), nm[2],
                reinterpret_cast<void*>(g_probeDescWords[3]), nm[3],
                reinterpret_cast<void*>(g_probeDescWords[4]), nm[4],
                reinterpret_cast<void*>(g_probeDescWords[5]), nm[5]);
            TaskDefer(L, std::string(dw), true);

            // ClassDescriptor fields + heuristic: treat each pointer field as a possible
            // property-collection 'begin' (array of PropertyDescriptor*). If *(field) is a
            // descriptor whose +8 reads a name string, that's our property list.
            char cw[420]; int cwl = 0;
            cwl += _snprintf_s(cw + cwl, sizeof(cw) - cwl, _TRUNCATE, "print('[ofq-dll] CD=%p",
                               reinterpret_cast<void*>(g_probeCD));
            for (int i = 3; i <= 14 && cwl < (int)sizeof(cw) - 60; ++i)
            {
                uintptr_t f = g_probeCDWords[i];
                char nm2[24]; nm2[0] = 0;
                if (f) ProbeStr(ProbeDeref(ProbeDeref(f) + 8), nm2, 20);   // *( *(field)+8 ) as string
                cwl += _snprintf_s(cw + cwl, sizeof(cw) - cwl, _TRUNCATE,
                                   " +%X=%p%s%s%s", (unsigned)(i * 8), reinterpret_cast<void*>(f),
                                   nm2[0] ? "(" : "", nm2, nm2[0] ? ")" : "");
            }
            _snprintf_s(cw + cwl, sizeof(cw) - cwl, _TRUNCATE, "')");
            TaskDefer(L, std::string(cw), true);

            // PropertyDescriptor vtable + slot RVAs (to identify the setter slot).
            uintptr_t vtRva = g_probeDescVt > modBase ? g_probeDescVt - modBase : 0;
            for (int half = 0; half < 2; ++half)
            {
                char vw[440]; int vwl = 0;
                vwl += _snprintf_s(vw + vwl, sizeof(vw) - vwl, _TRUNCATE,
                                   "print('[ofq-dll] VT=0x%llX s%d:", (unsigned long long)vtRva, half * 16);
                for (int i = half * 16; i < half * 16 + 16 && vwl < (int)sizeof(vw) - 24; ++i)
                {
                    uintptr_t s = g_probeVtSlots[i];
                    uintptr_t r = (s > modBase && s < modBase + 0x8000000) ? s - modBase : 0;
                    vwl += _snprintf_s(vw + vwl, sizeof(vw) - vwl, _TRUNCATE, " %X=%llX", i, (unsigned long long)r);
                }
                _snprintf_s(vw + vwl, sizeof(vw) - vwl, _TRUNCATE, "')");
                TaskDefer(L, std::string(vw), true);
            }

            // Confirmed Guid read: {index @ inst+0x30, scope @ inst+0x34}, registry @ inst+0x28.
            unsigned long long guid = ReadInstanceGuid(g_probeInst);
            uintptr_t reg = ProbeDeref(g_probeInst + kRegistryOff);
            char gb[200];
            _snprintf_s(gb, sizeof(gb), _TRUNCATE,
                "print('[ofq-dll] GUID index=%u scope=%u guid64=0x%llX registry=%p')",
                (unsigned)(guid & 0xFFFFFFFF), (unsigned)(guid >> 32),
                (unsigned long long)guid, reinterpret_cast<void*>(reg));
            TaskDefer(L, std::string(gb), true);
            char rf[320];
            _snprintf_s(rf, sizeof(rf), _TRUNCATE,
                "print('[ofq-dll] REFSCAN inst=%p container=%p instOff=+0x%lX  ID=%llu (0x%llX) idOff=%+ld')",
                reinterpret_cast<void*>(g_probeInst), reinterpret_cast<void*>(g_refContainer),
                (unsigned long)g_refInstOffInContainer,
                (unsigned long long)g_refId, (unsigned long long)g_refId, (long)g_refIdOff);
            TaskDefer(L, std::string(rf), true);
            char rc[380]; int rcl = 0;
            rcl += _snprintf_s(rc + rcl, sizeof(rc) - rcl, _TRUNCATE, "print('[ofq-dll] AROUND(at-0x40)");
            for (int i = 0; i < 16 && rcl < (int)sizeof(rc) - 26; ++i)
                rcl += _snprintf_s(rc + rcl, sizeof(rc) - rcl, _TRUNCATE, " %c%X=%llX",
                                   (i * 8 < 0x40 ? '-' : '+'), (unsigned)(i * 8 < 0x40 ? 0x40 - i * 8 : i * 8 - 0x40),
                                   (unsigned long long)g_refCw[i]);
            _snprintf_s(rc + rcl, sizeof(rc) - rcl, _TRUNCATE, "')");
            TaskDefer(L, std::string(rc), true);
            char rn[380]; int rnl = 0;
            rnl += _snprintf_s(rn + rnl, sizeof(rn) - rnl, _TRUNCATE, "print('[ofq-dll] NODEPTRS  at-8*:");
            for (int i = 0; i < 8; ++i)
                rnl += _snprintf_s(rn + rnl, sizeof(rn) - rnl, _TRUNCATE, " +%X=%llX", (unsigned)(i*8), (unsigned long long)g_refNmW[i]);
            rnl += _snprintf_s(rn + rnl, sizeof(rn) - rnl, _TRUNCATE, " | at+8*:");
            for (int i = 0; i < 8; ++i)
                rnl += _snprintf_s(rn + rnl, sizeof(rn) - rnl, _TRUNCATE, " +%X=%llX", (unsigned)(i*8), (unsigned long long)g_refNpW[i]);
            _snprintf_s(rn + rnl, sizeof(rn) - rnl, _TRUNCATE, "')");
            TaskDefer(L, std::string(rn), true);
        }
    }

    long gen = static_cast<long>(gd), n = static_cast<long>(nd);
    if (gen != g_ofqGen) { g_ofqGen = gen; g_ofqDrained = 0; }   // Lua reset the queue
    if (n < g_ofqDrained) g_ofqDrained = 0;
    if (n <= g_ofqDrained) return;

    ResolveRelayBin();
    if (!g_relayBin) return;   // binary transport not resolved yet - retry next tick

    long start = g_ofqDrained + 1;
    if (n - start > 200) start = n - 200;   // cap catch-up burst
    for (long i = start; i <= n; ++i)
    {
        void* udv = nullptr; void* pv = nullptr;
        int utag = ReadTableElem(L, "__ofq", i, &udv);   // instance userdata
        int ptag = ReadTableElem(L, "__ofp", i, &pv);    // property-name string
        (void)utag;
        if (ptag != kTagString || !pv || !udv) continue;
        const char* prop = reinterpret_cast<const char*>(pv) + 0x18;         // Luau string payload
        void* inst = reinterpret_cast<void*>(ProbeDeref(reinterpret_cast<uintptr_t>(udv) + 0x10)); // Instance*
        if (!inst) continue;
        void* desc = ResolveDescriptor(inst, prop);
        if (!desc || !DescNameMatches(desc, prop)) { g_emitResolveFail++; continue; }
        ShipGuidChange(inst, prop, desc);   // reads guid64 + getValue -> ships {guid64,prop,variant}
    }
    g_ofqDrained = n;*/
}

static void OpenClientSendGates();   // fwd: defined below; called before first execute

// Open the outgoing send-gates exactly once, synchronously. Called at the head of the
// execute path so the install fully finishes BEFORE any user code runs (and never
// mid-script). The patch itself is instant (3-byte writes), so there is no wait time.
static void EnsureSendGates()
{
    static volatile long gatesOpened = 0;
    if (InterlockedCompareExchange(&gatesOpened, 1, 0) == 0)
    {
        __try { OpenClientSendGates(); }
        __except (EXCEPTION_EXECUTE_HANDLER) { LogC("OpenClientSendGates FAULT"); }
    }
}

static void DrainAndRunAll(void* L)
{
    void* g = *reinterpret_cast<void**>(reinterpret_cast<char*>(L) + kOffGlobal);

    // All VMs have game/workspace, so the real client VM is the one with a
    // LocalPlayer. We can't read the DataModel inline (freeze), so a deferred
    // detector writes the LocalPlayer name into the global __offblox_player; we
    // read that back with a safe raw lookup. Lock the VM whose flag is a string.
    if (!g_serverGlobal)
    {
        std::string name = ReadPlayerFlag(L);
        if (!name.empty())
        {
            g_serverGlobal = g;
            Log(std::string("game VM locked - LocalPlayer=") + name);
        }
        else
        {
            // Schedule the detector on this VM once. It runs deferred (safe), and
            // sets __offblox_player if this VM has a LocalPlayer.
            bool probed = false;
            for (int i = 0; i < g_nprobed; ++i) if (g_probed[i] == g) probed = true;
            if (!probed && g_nprobed < 24)
            {
                g_probed[g_nprobed++] = g;
                // No nested function (would lose caps) - LocalPlayer returns nil safely.
                bool ok = TaskDefer(L,
                    "local p = game:GetService('Players').LocalPlayer "
                    "if p then __offblox_player = p.Name end", /*quiet*/false);
                char b[112];
                _snprintf_s(b, sizeof(b), _TRUNCATE, "detector on VM=%p scheduled(ok=%d)", g, ok ? 1 : 0);
                Log(b);
            }
            return;
        }
    }
    if (g != g_serverGlobal) return;

    // FE nulling disabled (whole-filter null crashes/floods). Whitelist stays; the
    // new-instance gate is the targeted lever. Just report capture state on execute.
    if (g_clientRepl) LogC("FE-status: ClientReplicator captured (whitelist intact; targeted mode)");
    else              LogC("FE-status: ClientReplicator NOT captured yet");

    // ---- Property-replication capture (one-shot) ---------------------------
    // Runs on the locked client VM. Connects Instance.Changed on every workspace
    // descendant (and future ones), and for each non-physics property change builds
    // a COMPLETE, ready-to-run Lua assignment statement (game:FindFirstChild chain +
    // a value literal rebuilt in Lua where the type is live) and pushes it to __ofs.
    // The DLL drain (DrainOfq) ships each statement to the server via the relay, where
    // it is run and the write replicates natively. Value serialization happens in Lua
    // (not the crashing client wire-serializer). last[] gives an echo/no-op guard so a
    // server->client echo of our own change is not re-shipped (breaks the loop).
    // The capture is PREPENDED to the user's chunk (guarded by __ofinit) rather than
    // deferred separately, so the Changed listeners are connected BEFORE the user's very
    // first line runs. Deferring it raced the first script and lost, so the first execute's
    // changes were made before the capture was armed and never replicated.
   /* static const char* kCapture = R"LUA(
if not __ofinit then
  __ofinit = true
  __ofq = {}   -- instance (userdata)
  __ofp = {}   -- property name (string)
  __ofn = 0
  __ofg = (tonumber(__ofg) or 0) + 1
  local fmt = string.format
  local RunService = game:GetService("RunService")
  -- Physics/per-frame + client-local props are skipped (would flood). Discrete props replicate.
  -- Only skip physics/camera props that native network-ownership already replicates.
  -- Everything script-driven (C0/C1, Health, PlatformStand, welds, etc.) must go through.
  local skip = {CFrame=true,CoordinateFrame=true,Position=true,Rotation=true,Orientation=true,
    Velocity=true,RotVelocity=true,AssemblyLinearVelocity=true,AssemblyAngularVelocity=true,
    Transform=true,WorldPivot=true,LocalTransparencyModifier=true,NetworkOwner=true,
    Focus=true,FieldOfView=true,DiagonalFieldOfView=true,MaxAxisFieldOfView=true,
    CameraSubject=true,CameraType=true,HeadLocked=true,NetworkIsSleeping=true,
    CenterOfMass=true,AssemblyMass=true,AssemblyCenterOfMass=true}
  local skipClass = {Camera=true,Terrain=true}
  -- Echo/no-op guard: only ship POD value types whose Variant copies across processes.
  -- STRING is excluded: its Variant holds a heap pointer that is garbage on the server
  -- (would crash setValue). Numbers/enums/Vector3/CFrame/Color3/UDim2/BrickColor are inline.
  local function key(v)
    local t = typeof(v)
    if t=="number" or t=="boolean" or t=="EnumItem" then return tostring(v)
    elseif t=="Vector3" or t=="Vector2" or t=="Color3" or t=="UDim2" or t=="UDim" or t=="BrickColor" then return tostring(v)
    elseif t=="CFrame" then return table.concat({v:GetComponents()},",")
    end
    return nil
  end
  local last    = setmetatable({}, {__mode="k"})
  local pending = setmetatable({}, {__mode="k"})
  local pendCount = 0
  local function onChg(o, prop)
    if type(prop) ~= "string" or skip[prop] then return end
    if skipClass[o.ClassName] then return end
    local ok, v = pcall(function() return o[prop] end); if not ok then return end
    local k = key(v); if k == nil then return end   -- only value types we can round-trip
    local lt = last[o]; if not lt then lt = {}; last[o] = lt end
    if lt[prop] == k then return end                -- unchanged / echo of our own write
    lt[prop] = k
    local pt = pending[o]; if not pt then pt = {}; pending[o] = pt end
    if pt[prop] == nil then pendCount = pendCount + 1 end
    pt[prop] = true
  end
  local function hook(o)
    if skipClass[o.ClassName] then return end
    pcall(function() o.Changed:Connect(function(prop) onChg(o, prop) end) end)
  end
  for _,o in ipairs(workspace:GetDescendants()) do hook(o) end
  workspace.DescendantAdded:Connect(hook)
  local acc = 0
  RunService.Heartbeat:Connect(function(dt)
    acc = acc + dt
    if acc < 0.1 then return end
    acc = 0
    if pendCount == 0 then return end
    local emitted = 0
    for o, pt in pairs(pending) do
      local anyLeft = false
      for prop in pairs(pt) do
        if emitted >= 80 then anyLeft = true break end
        pt[prop] = nil
        pendCount = pendCount - 1
        __ofn = __ofn + 1
        __ofq[__ofn] = o
        __ofp[__ofn] = prop
        emitted = emitted + 1
      end
      if not anyLeft then pending[o] = nil end
      if emitted >= 80 then break end
    end
  end)
  print("[ofq-dll] guid-capture installed (gen "..__ofg..")")
end
)LUA";*/

    // Preamble prepended to every user script so `script` and `LoadLibrary` are
    // predefined in the SAME compiled chunk (locals only reach the user code if
    // they share the chunk - which is why adding it client-side and running it as
    // a separate execution doesn't work).
    // Preamble prepended to every user script. `_G` is predefined (the executor
    // environment leaves it nil, which breaks scripts that use it). `script` is a
    // client-only LocalScript and `LoadLibrary` is the shared library, both defined
    // in the SAME chunk so the user code can see them. (Automatic property
    // replication is handled the targeted C++ way, not by a Lua reparent watcher.)
    static const char* kPreamble =
        "local _G = {} "
        "local script = Instance.new(\"LocalScript\") "
        "local LoadLibrary = require(game:GetObjects(\"rbxassetid://1\")[1]:Clone()) ";

    std::string code;
    bool first = true;
    while (Dequeue(code))
    {
        if (first)
        {
            // Install-before-execute: arm the outgoing send-gates completely and
            // synchronously BEFORE the first user chunk is queued. OpenClientSendGates
            // returns before TaskDefer, and the user code is deferred to run even later,
            // so the gates are guaranteed open before any user line executes. No timer,
            // no runtime install racing the script.
            EnsureSendGates();
            first = false;
        }
        TaskDefer(L, kPreamble + code, /*quiet*/false);   // capture arms first, then user code
    }
}

// Open the client's outgoing send-gates so client-created instances + their
// property changes replicate to the server (classic FE-off behaviour). These are
// ClientReplicator virtuals (located via the vtable + the fastDynamicCast<Message>
// class-id pattern; strictFilter for the primary `this` lives at [this+0x2E50]):
//   isLegalSendInstance  0x27AA970 (vt slot 117) -> mov al,1; ret  (send new instances)
//   isLegalSendProperty  0x27AAB00 (vt slot 116) -> mov al,1; ret  (send all prop changes)
// Applied ONCE, a few seconds AFTER the VM starts (post-join) - NOT at load. During
// join the gates still filter (whitelist), so the initial state sync does not flood
// the un-encodable value types that crash the serializer; only changes made AFTER
// this point (e.g. the executor creating a Part) are sent, and Part properties are
// all encodable. Entry-byte verified. The server accepts them (AcceptClientReplication).
static void OpenClientSendGates()
{
    uintptr_t base = reinterpret_cast<uintptr_t>(GetModuleHandleW(nullptr));
    if (!base) return;
    struct G { uintptr_t rva; unsigned char expect[3]; unsigned char stub[3]; const char* name; };
    // ONLY isLegalSendInstance. This lets the client emit well-formed NewInstanceItems
    // (new-part replication). All the property-send forcing that used to live here
    // (isLegalSendProperty, filterReplicatorChangedProperty, slot92 send-enable,
    // handlePropertyChanged NOPs, propChange-dispatch NOPs, mode=1) is REMOVED: it
    // never actually enqueued anything (the client's property-changed SUBSCRIPTION is
    // the missing link, upstream of all these gates) and it forced the send machinery
    // into unready states -> half-formed property items relayed to peers -> crashes on
    // join / big scripts. Property replication is now done via the native bridge
    // (call 0x28A86D0 with the captured replicator), not by prying these gates open.
    const G gates[3] = {
        { 0x27AA970, { 0x48,0x89,0x5C }, { 0xB0, 0x01, 0xC3 }, "isLegalSendInstance" },              // mov al,1;ret (true)
        // Replication-scope filter (0x273F490): the dispatcher + enqueue gate both call
        // this and treat true as "enqueue/replicate". For property changes it returns
        // FALSE for instances the client isn't authoritative over (server-scoped parts),
        // which is why only owned character parts replicated. Forcing it true is the
        // direct FE-off lever - the client now enqueues property changes for ANY instance.
        { 0x273F490, { 0x48,0x89,0x5C }, { 0xB0, 0x01, 0xC3 }, "replicationScopeFilter" },            // mov al,1;ret (true)
        // isLegalSendProperty: the SEND-time whitelist filter that rejects enqueued
        // property changes. dispTotal proves owned-instance changes ARE enqueued (the
        // dispatcher's enqueue gate 0x14299F440 already passed them, and it only passes
        // REPLICABLE/encodable props - so opening this send filter cannot leak an
        // un-encodable type into serializeValue). Forcing it true is what actually lets
        // client-owned property changes leave the client. Post-join only (join sync has
        // already flowed through the intact whitelist).
        { 0x27AAB00, { 0x48,0x89,0x5C }, { 0xB0, 0x01, 0xC3 }, "isLegalSendProperty" },              // mov al,1;ret (true)
    };
    for (const G& g : gates)
    {
        unsigned char* p = reinterpret_cast<unsigned char*>(base + g.rva);
        if (!(p[0] == g.expect[0] && p[1] == g.expect[1] && p[2] == g.expect[2]))
        {
            char b[96];
            _snprintf_s(b, sizeof(b), _TRUNCATE, "send-gate %s entry mismatch (%02X %02X %02X) - skipped",
                        g.name, p[0], p[1], p[2]);
            LogC(b); continue;
        }
        DWORD oldp = 0;
        if (VirtualProtect(p, 3, PAGE_EXECUTE_READWRITE, &oldp))
        {
            std::memcpy(p, g.stub, 3);
            VirtualProtect(p, 3, oldp, &oldp);
            FlushInstructionCache(GetCurrentProcess(), p, 3);
            g_gatesOpened++;
            char b[96];
            _snprintf_s(b, sizeof(b), _TRUNCATE, "send-gate opened: %s -> replicate", g.name);
            LogC(b);
        }
    }

    // (Property-send forcing blocks removed - see note above. They crashed peers and
    // never enqueued anything. Native bridge handles property replication instead.)
    //
    // NOTE: flipping the CLIENT FilteringEnabled getter (0x6FF1D0 -> mov al,0) here was
    // tried and FREEZES/CLOSES the game: it makes the client's send filters accept every
    // property, and this enforced build's serializeValue THROWS on value types with no
    // outgoing wire format, tearing down the connection. Post-join timing did not help
    // (ongoing writes still hit those types). The broad getter flip is a dead end on the
    // client - property replication must be the TARGETED native bridge (emit only
    // well-formed ChangePropertyItems for encodable properties via dispatcher 0x28A86D0),
    // never the blanket getter/filter flip. Getter stays TRUE on the client.
}

static int Hook_resume(void* L)
{
    static volatile long once = 0;
    if (InterlockedCompareExchange(&once, 1, 0) == 0) LogC("resume hook firing (VM is running)");

    // NOTE: the send-gate install is NO LONGER done here on a timer. It is opened
    // synchronously at the head of the execute path (DrainAndRunAll), once, BEFORE the
    // first user chunk runs - so execution waits for a finished install and nothing
    // installs mid-script. See DrainAndRunAll / EnsureSendGates.

    int r = g_origResume(L);   // real resume first (non-re-entrant afterward)

    if (g_pending && InterlockedCompareExchange(&g_inExec, 1, 0) == 0)
    {
        __try { DrainAndRunAll(L); }
        __except (EXCEPTION_EXECUTE_HANDLER) { LogC("tick: FAULT (SEH caught)"); }
        InterlockedExchange(&g_inExec, 0);
    }

    // Native property-repl queue drain (V1: log-only). SEH-guarded, throttled.
    __try { DrainOfq(L); }
    __except (EXCEPTION_EXECUTE_HANDLER) { LogC("DrainOfq FAULT"); }

    return r;
}

// Dump the live ClientReplicator layout once, to validate the RE-map offsets
// against the running process. Log-only; SEH-guarded by the caller.
static void DumpReplicator(void* self)
{
    char* r = reinterpret_cast<char*>(self);
    void* vt   = *reinterpret_cast<void**>(r);
    void* strm = *reinterpret_cast<void**>(r + 0x2b90);   // [this+0x2b90] stream/writer
    char b[160];
    _snprintf_s(b, sizeof(b), _TRUNCATE,
        "CLIENT ClientReplicator captured @%p vt=%p +0x2b90(stream)=%p", self, vt, strm);
    Log(b);
}

// Force FE-off on the live client replicator by dropping its StrictNetworkFilter.
// The whitelist filter at [replicator+0x1b0] (shared_ptr: ptr@+0x1b0, ctrl@+0x1b8)
// is what rejects non-whitelisted client property/instance/event changes. In this
// FE-ENFORCED build the client builds it regardless of the server's join bit, so
// nulling it here is the deterministic FE-off switch. `if (strictFilter)` is
// checked everywhere, so null is the legitimate FE-off state. The StrictNetworkFilter
// object is leaked (its refcount isn't decremented) - negligible and crash-free.
// The StrictNetworkFilter is stored at [joinHandlerThis + 0x1b0], but the join
// handler runs on a SECONDARY-base subobject (its `this` != the send-hook `self`,
// classic multiple inheritance). So we can't use 0x1b0 off `self` directly (that
// crashed - wrong field). Instead we locate that subobject inside `self` at
// runtime by finding where its vtable pointer lives (D = offset of one of the join
// handler's vtables within the object), then strictFilter is at [self + D + 0x1b0].
static const uintptr_t kJoinSubVtRva[3] = { 0x8c94f68, 0x8ca3d50, 0x8ca9df8 };

static void ForceClientFeOff(void* self, bool report)
{
    uintptr_t base = reinterpret_cast<uintptr_t>(GetModuleHandleW(nullptr));
    char* r = reinterpret_cast<char*>(self);
    int D = -1;
    for (int off = 0; off < 0x600 && D < 0; off += 8)
    {
        void* v = *reinterpret_cast<void**>(r + off);
        for (int k = 0; k < 3; ++k)
            if (v == reinterpret_cast<void*>(base + kJoinSubVtRva[k])) { D = off; break; }
    }
    if (D < 0)
    {
        if (report) LogC("FE-status: repl captured, but join-subobject vtable NOT found in it (D=-1) - strictFilter offset unknown");
        return;
    }
    void** sf   = reinterpret_cast<void**>(r + D + 0x1b0);
    void** ctrl = reinterpret_cast<void**>(r + D + 0x1b8);
    void* before = *sf;
    if (before != nullptr) { *sf = nullptr; *ctrl = nullptr; }
    if (report)
    {
        char b[140];
        _snprintf_s(b, sizeof(b), _TRUNCATE,
                    "FE-status: repl=%p D=0x%x strictFilter was=%p now=%p -> %s",
                    self, D, before, *sf, (*sf == nullptr) ? "FE-OFF" : "STILL ON");
        LogC(b);
    }
    else if (before != nullptr)
    {
        static bool once = false;
        if (!once) { once = true; char b[112];
            _snprintf_s(b, sizeof(b), _TRUNCATE, "strictFilter nulled at self+0x%x (D=0x%x) -> client FE-off", D + 0x1b0, D);
            LogC(b); }
    }
}

// Client replicator send hook (vtable slot 134). Only the ClientReplicator's
// vtable slot is patched, so this fires solely for the client's own replicator.
// We capture `self` (the live ClientReplicator) once + validate its layout, then
// always call the original. Capture/validate only - never writes engine state.
static volatile long g_sendFires = 0;   // # times the outgoing send loop ran (has data)

static void Hook_ReplSend(void* self, uintptr_t a2, uintptr_t a3, uintptr_t a4)
{
    if (self)
    {
        __try
        {
            if (!g_clientRepl)
            {
                g_clientRepl = self;
                if (InterlockedCompareExchange(&g_replDumped, 1, 0) == 0)
                    DumpReplicator(self);
            }
            // NOTE: runtime strictFilter nulling DISABLED. Nulling the whole filter
            // (here or via the static born-null patch) floods the join with value
            // types that have no outgoing wire format -> serializeValue throws
            // (disconnect) or, if forced to return false, corrupts the packet
            // (crash). The whitelist must stay; replication is enabled via the
            // targeted new-instance gate instead. Capture below stays (diagnostic).
            // ForceClientFeOff(self, false);   // <- intentionally disabled

            // SEND-SIDE PROBE: slot 134 (the outgoing serialize loop) only runs
            // when the client actually has queued outgoing items. So each firing
            // = the client IS emitting replication. If this bumps right after you
            // create a Part, the send side works and the problem is server-side
            // (reject/kick). If it NEVER bumps on Part creation, the client isn't
            // enqueuing the change (outgoing subscription not wired -> Option B).
            long n = InterlockedIncrement(&g_sendFires);
            if (n <= 10 || (n % 64) == 0)
            {
                char b[96];
                _snprintf_s(b, sizeof(b), _TRUNCATE, "OUTGOING send-loop fired #%ld (client is emitting data)", n);
                LogC(b);
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {}
    }
    g_origReplSend(self, a2, a3, a4);
}

// RELIABLE capture: ClientReplicator::processPacket runs on every incoming packet
// (the server streams to the client constantly), so `self` = the live replicator
// is available from the first frame - unlike slot 134 which only fires when the
// client already has outgoing data. Capture + FE-off here every packet.
static void Hook_ProcessPacket(void* self, uintptr_t a2, uintptr_t a3, uintptr_t a4)
{
    if (self)
    {
        __try
        {
            if (!g_clientRepl)
            {
                g_clientRepl = self;
                if (InterlockedCompareExchange(&g_replDumped, 1, 0) == 0)
                    DumpReplicator(self);
            }
            // ForceClientFeOff(self, false);   // <- disabled: whole-filter null crashes/floods
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {}
    }
    g_origProcPkt(self, a2, a3, a4);
}

// Wrap serializeValue (outgoing value serializer). PURE POINTER LOGGING ONLY:
// no engine calls, no virtual dispatch, no SEH around the original. `type` (rcx)
// is the Reflection::Type the engine is about to encode; the engine itself does
// `mov rax,[rcx]; call [rax+0x10]` on it, so it's an in-module Type singleton at a
// stable address. We log its module RVA (distinct values only) so the LAST one
// before the unknown-format disconnect identifies the culprit type - which we then
// map to a name offline. We do NOT reconstruct the virtual id call (that reads
// registers the vfn expects and crashed at join), and we do NOT SEH-catch the
// original's C++ throw (that crashes this build's EH model). Both were the crash.
static uintptr_t g_modBase = 0;

static char __fastcall Hook_SerializeValue(void* type, void* value, unsigned char useDict, void* bitstream)
{
    __try
    {
        uintptr_t t = reinterpret_cast<uintptr_t>(type);
        if (g_modBase && t > g_modBase)
        {
            uintptr_t rva = t - g_modBase;
            static volatile long seen[192] = { 0 };
            static volatile long nseen = 0;
            long cnt = nseen;
            bool known = false;
            for (long i = 0; i < cnt && i < 192; ++i)
                if (static_cast<uintptr_t>(seen[i]) == (rva & 0xffffffff)) { known = true; break; }
            if (!known && cnt < 192)
            {
                seen[cnt] = static_cast<long>(rva & 0xffffffff);
                InterlockedIncrement(&nseen);
                char b[80];
                _snprintf_s(b, sizeof(b), _TRUNCATE, "outgoing value type@rva=0x%llx",
                            static_cast<unsigned long long>(rva));
                LogC(b);
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {}

    // Call the original untouched - graceful disconnect on the throw, as before.
    return g_origSerVal(type, value, useDict, bitstream);
}

// Patch one absolute vtable slot to `hook`, saving the original. The vtable lives
// in read-only .rdata, so flip protection around the write.
static bool HookVTableSlot(uintptr_t slotVA, void* hook, void** outOrig)
{
    void** slot = reinterpret_cast<void**>(slotVA);
    DWORD oldp = 0;
    if (!VirtualProtect(slot, sizeof(void*), PAGE_READWRITE, &oldp)) return false;
    *outOrig = *slot;
    *slot = hook;
    VirtualProtect(slot, sizeof(void*), oldp, &oldp);
    return true;
}

// NOTE: the FE-off mechanism is NOT a client-side mode flip. Per the 2016 source
// (see Docs/FE_Replication_REMap.md), the client is set FE-off *at join* when the
// server sends join-bit = getNetworkFilteringEnabled() == false (we patch that
// getter, 0x6FF1D0, false on the server). No client mode/send-loop patch is used;
// the capture hook below is diagnostic only.

// ============================ install ======================================

static void PatchGate(uintptr_t va, const unsigned char (&expect)[6], const char* tag)
{
    unsigned char* p = reinterpret_cast<unsigned char*>(va);
    if (std::memcmp(p, expect, 6) != 0)
    {
        char b[112];
        _snprintf_s(b, sizeof(b), _TRUNCATE, "gate mismatch %s (%02X %02X %02X %02X %02X %02X)",
                    tag, p[0], p[1], p[2], p[3], p[4], p[5]);
        Log(b); return;
    }
    DWORD oldp = 0;
    if (VirtualProtect(p, 6, PAGE_EXECUTE_READWRITE, &oldp))
    {
        std::memset(p, 0x90, 6);
        VirtualProtect(p, 6, oldp, &oldp);
        FlushInstructionCache(GetCurrentProcess(), p, 6);
        Log(std::string("loadstring gate patched: ") + tag);
    }
}

// Verify `expect` then overwrite with `patch` (both length n). Used for the
// corescript-permission bypasses. Returns true if patched.
static bool PatchVerify(uintptr_t va, const unsigned char* expect,
                        const unsigned char* patch, size_t n, const char* tag)
{
    unsigned char* p = reinterpret_cast<unsigned char*>(va);
    if (std::memcmp(p, expect, n) != 0)
    {
        char b[128];
        _snprintf_s(b, sizeof(b), _TRUNCATE, "patch mismatch %s (%02X %02X %02X %02X)",
                    tag, p[0], p[1], p[2], p[3]);
        Log(b); return false;
    }
    DWORD oldp = 0;
    if (!VirtualProtect(p, n, PAGE_EXECUTE_READWRITE, &oldp)) return false;
    std::memcpy(p, patch, n);
    VirtualProtect(p, n, oldp, &oldp);
    FlushInstructionCache(GetCurrentProcess(), p, n);
    Log(std::string("patched: ") + tag);
    return true;
}

// CoreScript permission bypasses (client only - this DLL never loads on the
// server). Two script-permission systems gate CoreGui/GetObjects; neither is the
// network anti-impersonation/cookie/signature system, which is untouched.
//   1) Capability system: ~70 call sites assert a capability and, on failure,
//      throw via the error formatter at kCapFormatterRva. Making that formatter
//      an immediate `ret` turns every failed assertion into a pass (the checker
//      returns normally and its caller proceeds). One byte.
//   2) Restricted-child access (e.g. CoreGui): a shared predicate (20 callers)
//      ANDs the thread's effective caps with the instance's required caps and
//      returns bool "permitted". On false the getter warns and returns nil.
//      Patching its entry to `mov al,1; ret` makes every restricted child (CoreGui
//      and friends) resolve to the real instance. This is the actual gate - the
//      earlier warn-formatter / getchild-branch bytes were only the "explain the
//      nil" path, so we no longer patch those.
static const uintptr_t kCapFormatterRva = 0x6686af0;
static const uintptr_t kAccessPredRva   = 0x65f5680;

static bool g_installed = false;

static bool Install()
{
    if (g_installed) return true;
    uintptr_t base = reinterpret_cast<uintptr_t>(GetModuleHandleW(nullptr));
    if (!base) return false;
    g_modBase = base;   // for the serializeValue type-pointer -> RVA logging

    g_pubResume = reinterpret_cast<PubResume_t>(base + kPubResumeRva);
    g_newthread = reinterpret_cast<NewThread_t>(base + kNewThreadRva);
    g_rawget    = reinterpret_cast<RawGet_t>(base + kRawGetRva);
    g_newlstr   = reinterpret_cast<NewLStr_t>(base + kNewLStrRva);

    const unsigned char e1[6] = { 0x0F, 0x85, 0x01, 0x05, 0x00, 0x00 };
    const unsigned char e2[6] = { 0x0F, 0x84, 0xF6, 0x03, 0x00, 0x00 };
    const unsigned char e3[6] = { 0x0F, 0x84, 0xB9, 0x00, 0x00, 0x00 };
    const unsigned char e4[6] = { 0x0F, 0x84, 0xAC, 0x00, 0x00, 0x00 };
    PatchGate(base + kLoadstrGate1Rva, e1, "RobloxScript-context");
    PatchGate(base + kLoadstrGate2Rva, e2, "LoadStringEnabled");
    PatchGate(base + kLoadstrGate3Rva, e3, "not-available-3");
    PatchGate(base + kLoadstrGate4Rva, e4, "not-available-4");

    // corescript permission bypasses
    const unsigned char capExpect[1] = { 0x48 };                          // mov [rsp+8],rbx
    const unsigned char capPatch [1] = { 0xC3 };                          // ret
    PatchVerify(base + kCapFormatterRva, capExpect, capPatch, 1, "capability-check bypass");

    const unsigned char predExpect[5] = { 0x48, 0x89, 0x5C, 0x24, 0x08 };  // mov [rsp+8],rbx
    const unsigned char predPatch [5] = { 0xB0, 0x01, 0xC3, 0x24, 0x08 };  // mov al,1; ret (tail unreached)
    PatchVerify(base + kAccessPredRva, predExpect, predPatch, 5, "restricted-child access -> allow");

    // ---- FE-off (client), STATIC, one-shot at load (the analog of the server's
    // getter patch) ----------------------------------------------------------
    // The join handler (0x2831EF0) builds a StrictNetworkFilter UNCONDITIONALLY in
    // this enforced build and stores it as a shared_ptr on the replicator:
    //     0x2832B9B  mov rcx,[rax]      ; rcx = new filter ptr
    //     0x2832B9E  mov rdx,[rax+8]    ; rdx = new control block
    //     ...
    //     0x2832BA9  mov [rdi+0x1B0],rcx   -> strictFilter.ptr
    //     0x2832BB7  mov [rdi+0x1B8],rdx   -> strictFilter.ctrl
    // We zero rcx/rdx before those stores, so the replicator is born with
    // strictFilter == NULL. That is the genuine 2016 FilteringEnabled==false state:
    // ClientReplicator::isLegalSendProperty / filterNew / filterEvent all return
    // Accept when strictFilter is null, so property changes, NewInstance, and events
    // all replicate. One byte-patch, applied at DLL load - no live capture, no
    // per-tick D-scan, no timing dependence (join-independent). The freshly built
    // filter object leaks (never referenced); negligible, and crash-free because
    // every consumer guards `if (strictFilter)`. The server getter patch stays so
    // the server ACCEPTS the incoming changes.
    // ---- FE-off replication: TARGETED, not the blunt whole-filter null ---------
    // Proven dead-ends (see Docs/FE_Replication_REMap.md 6h-6j): nulling the whole
    // strictFilter floods the join with value types that have no OUTGOING wire
    // format; serializeValue THROWS on them (disconnect), and forcing it to return
    // false corrupts the half-written packet (crash). The 2022L PDB shows the
    // StrictNetworkFilter whitelist is DESIGNED to allow BasePart/Player/Tool/etc.,
    // so the filter must stay (it keeps the join clean). Replication is enabled by
    // broadening only the NEW-INSTANCE gate (isLegalSendInstance -> true) while the
    // per-property whitelist still runs, so no un-encodable property is ever queued.
    // (isLegalSendInstance address resolved separately; patch applied there.)

    // NOTE: do NOT force ClientReplicator slot92 true / mode=1 - the client's
    // outgoing send structures are uninitialized (it never sends), so running the
    // send loop crashes on join. Send-enable must come AFTER those structures are
    // built. Capture + the changed-map diagnostic below stay (read-only, safe).

    unsigned char* rs = reinterpret_cast<unsigned char*>(base + kIntResumeRva);
    if (std::memcmp(rs, kResumePrologue, sizeof(kResumePrologue)) != 0)
    {
        char b[128];
        _snprintf_s(b, sizeof(b), _TRUNCATE, "resume prologue mismatch (%02X %02X %02X %02X %02X)",
                    rs[0], rs[1], rs[2], rs[3], rs[4]);
        Log(b); return false;
    }
    if (!InlineHookVA(base + kIntResumeRva, reinterpret_cast<void*>(&Hook_resume),
                      reinterpret_cast<void**>(&g_origResume)))
    { Log("InlineHookVA(internal resume) FAILED"); return false; }

    // REMOVED: the ClientReplicator capture hooks (slot-134 vtable hook + the
    // processPacket inline hook). They existed only to capture the live replicator
    // for the runtime FE-off nulling, which is abandoned. Both sit on hot
    // replication paths - the processPacket inline hook rewrites that function's
    // prologue on every incoming packet - and are the prime suspect for the
    // "Variant cast failed" / "unknown network format" send errors at join. With FE
    // nulling gone they serve no purpose, so we no longer install them; the client's
    // replication path runs un-hooked (vanilla), which is what joined cleanly before
    // any FE work. Only the executor patches (gates, capability, resume hook) remain.
    // Capture the live ClientReplicator via a vtable-slot hook on slot 45 (its setup
    // method 0x27AAEC0), for the runtime mode=1 write in OpenClientSendGates.
    {
        uintptr_t slot = base + kClientReplVtRva + 0x168;   // ClientReplicator vt+0x168 = slot 45
        void* expect = reinterpret_cast<void*>(base + 0x27AAEC0);
        if (*reinterpret_cast<void**>(slot) == expect &&
            HookVTableSlot(slot, reinterpret_cast<void*>(&Hook_ReplSetup),
                           reinterpret_cast<void**>(&g_origReplSetup)))
            Log("ClientReplicator capture hook (slot 45 setup) installed");
        else
            Log("ClientReplicator slot45 capture NOT installed (slot mismatch)");
    }

    // PROPERTY_CHANGED dispatch observer (0x28a86d0). Confirmed function; inline hook
    // with a minimal, SEH-guarded body (counter + one-shot struct latch). Tells us
    // whether client-side property writes reach the client replicator, and captures
    // the exact arg layout from the working dispatches. Read-only - forwards always.
   /* if (InlineHookVA(base + kDispatchRva, reinterpret_cast<void*>(&Hook_Dispatch),
                     reinterpret_cast<void**>(&g_origDispatch)))
        Log("PROPERTY_CHANGED dispatch observer (0x28a86d0) installed");
    else
        Log("dispatch observer install FAILED");*/

   /* if (InlineHookVA(base + kMegaEnqRva, reinterpret_cast<void*>(&Hook_MegaEnq),
                     reinterpret_cast<void**>(&g_origMegaEnq)))
        Log("Mega-enqueue observer (0x14299F740) installed");
    else
        Log("Mega-enqueue observer install FAILED");

    (void)&Hook_ReplSend;         // no longer installed
    (void)&Hook_ProcessPacket;    // no longer installed
    (void)&Hook_SerializeValue;   // never installed (crashes if hooked)
    (void)&ForceClientFeOff;      // disabled - whole-filter null crashes/floods
    (void)&DumpReplicator; (void)&g_sendFires; (void)&g_modBase; (void)&HookVTableSlot;
    */
    g_installed = true;
    Log("installed - hook + gate patches active");
    return true;
}

// ============================ pipe server ==================================

static DWORD WINAPI PipeThread(LPVOID)
{
      // engine code is mapped in the injected process; hook immediately

    for (;;)
    {
        // PIPE_UNLIMITED_INSTANCES so multiple clients (multiple Studio processes)
        // can each host their own pipe instance under the same name instead of the
        // second one failing to create the pipe. Each GUI connection lands on a free
        // instance -> one GUI per client.
        HANDLE h = CreateNamedPipeW(
            kPipeName, PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
            PIPE_UNLIMITED_INSTANCES, 1 << 16, 1 << 16, 0, nullptr);
        if (h == INVALID_HANDLE_VALUE) { Sleep(1000); continue; }

        BOOL ok = ConnectNamedPipe(h, nullptr) ? TRUE : (GetLastError() == ERROR_PIPE_CONNECTED);
        if (!ok) { CloseHandle(h); continue; }

        { std::lock_guard<std::mutex> lk(g_pipeMtx); g_pipe = h; }   // WriterThread flushes the backlog
        Log("client connected - send Luau (one script per message)");

        if (!g_installed) {
            Install();
        }

        // Read whole messages, reassembling any that exceed the buffer. In message
        // mode a message larger than `buf` makes ReadFile fail with ERROR_MORE_DATA
        // and return a partial chunk; we append chunks until the message completes.
        // The message is raw bytes, so arbitrary special characters (quotes, tabs,
        // newlines, unicode, embedded NULs) are preserved verbatim.
        std::vector<char> buf(1 << 16);
        std::string msg;
        for (;;)
        {
            DWORD n = 0;
            BOOL r = ReadFile(h, buf.data(), (DWORD)buf.size(), &n, nullptr);
            if (r)
            {
                msg.append(buf.data(), n);            // final chunk of this message
                if (!msg.empty())
                {
                    char b[64];
                    _snprintf_s(b, sizeof(b), _TRUNCATE, "received: %zu bytes", msg.size());
                    Log(b);
                    EnqueueScript(msg); //script = Instance.new('LocalScript') LoadLibrary = require(game:GetObjects('rbxassetid://1')[1]:Clone())                enqueue; runs on the Lua thread
                }
                msg.clear();
            }
            else if (GetLastError() == ERROR_MORE_DATA)
            {
                msg.append(buf.data(), n);            // partial - keep reading this message
            }
            else break;                               // real error / client disconnect
        }

        { std::lock_guard<std::mutex> lk(g_pipeMtx); g_pipe = INVALID_HANDLE_VALUE; }
        DisconnectNamedPipe(h);
        CloseHandle(h);
    }
    return 0;
}

} // namespace offblox

BOOL WINAPI DllMain(HINSTANCE hinst, DWORD reason, LPVOID)
{
    if (reason == DLL_PROCESS_ATTACH)
    {
        DisableThreadLibraryCalls(hinst);
        CreateThread(nullptr, 0, offblox::WriterThread, nullptr, 0, nullptr);
        CreateThread(nullptr, 0, offblox::PipeThread, nullptr, 0, nullptr);
    }
    return TRUE;
}
