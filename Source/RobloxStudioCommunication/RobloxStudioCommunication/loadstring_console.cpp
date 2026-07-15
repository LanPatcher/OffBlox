// loadstring_console.cpp - see loadstring_console.h.
//
// Standalone server-console -> Luau executor. No in-game script, no HTTP, no
// startup Lua - it works on a bare baseplate. (Reference: rakion99/Axon: call
// the game's own lua functions directly.)
//
// We inline-hook the INTERNAL resume(L) (0x664ce00), not the public C-API
// lua_resume (0x664cd40). The public wrapper has zero direct callers - the task
// scheduler resumes every script/coroutine through the internal resume, so its
// `L` is a real script thread whose globals (print, loadstring, ...) are
// populated. (The public wrapper only ever saw scheduler/continuation threads
// with an EMPTY global table, which is why getfield returned nil for everything.)
// The scheduler runs it every frame even on a bare baseplate, so it's a free,
// safe, on-thread tick. When the host has typed a line we run it there: make a
// fresh thread, fetch the global `loadstring`, push the source, resume (via the
// public 3-arg lua_resume, which sets up the initial call frame) to COMPILE it,
// then resume a second thread to RUN the compiled function. resume protects
// errors, so no lua_pcall is needed.
//
// Engine functions used (verified against this build, ImageBase 0x140000000):
//     resume(int.) 0x14664ce00  (L)->int                [hooked]
//     lua_resume   0x14664cd40  (L, from, narg)->int     [run temp threads]
//     lua_newthread 0x146648fb0  (L)->lua_State*
//     lua_getfield  0x146649fb0  (L, idx, const char* k)
//     luaS_newlstr  0x146674d50  (L, s, len)->TString*
// Layout: L->base=[L+0x30], L->top=[L+0x38], L->gt=[L+0x60]; TValue=16B
//         (value@0, tt@0x0c); type tags: string=6, function=8.
//         LUA_GLOBALSINDEX=-10002. A fresh lua_newthread is sandboxed with an
//         empty gt, so we copy the resumed thread's gt onto it (see RunSource).
// All VM access is SEH-guarded; a bad offset fault-skips and the real resume
// still runs.

#include "loadstring_console.h"
#include "iat_hook.h"
#include "patcher.h"

#include <deque>
#include <mutex>
#include <string>
#include <cstdint>
#include <unordered_map>
#include <cstring>
#include <cstdio>
#include <exception>

namespace RobloxStudioPatcher
{
    extern bool IsStartServerTask_Pub();
    void ServerConsoleLog(const std::string& line);   // server_console.cpp
    void ForceFilteringDisabled_Pub();                // dllmain.cpp (server accept patches)
    void ForceFilteringDisabledGetter_Pub();          // dllmain.cpp (FilteringEnabled getter -> false)

    // C-string wrapper: builds the std::string in ITS OWN frame so callers that
    // use __try (Hook_resume) stay free of unwindable objects (avoids C2712).
    static void LogC(const char* s) { ServerConsoleLog(std::string(s)); }

    // SEH filter: log the exception code, the faulting instruction (as a module
    // RVA so it maps to the disassembly) and the address it tried to touch, then
    // handle it. Runs in its own frame (no C2712).
    static int LogExFilter(EXCEPTION_POINTERS* ep)
    {
        unsigned long code = ep->ExceptionRecord->ExceptionCode;
        void* at   = ep->ExceptionRecord->ExceptionAddress;
        void* data = (code == 0xC0000005 && ep->ExceptionRecord->NumberParameters >= 2)
                     ? reinterpret_cast<void*>(ep->ExceptionRecord->ExceptionInformation[1])
                     : nullptr;
        uintptr_t base = reinterpret_cast<uintptr_t>(GetModuleHandleW(nullptr));
        char b[128];
        _snprintf_s(b, sizeof(b), _TRUNCATE,
            "[offblox] except=0x%08lX at=%p rva=0x%llX accessed=%p",
            code, at, (unsigned long long)(reinterpret_cast<uintptr_t>(at) - base), data);
        ServerConsoleLog(std::string(b));
        return 1; // EXCEPTION_EXECUTE_HANDLER
    }

    // Public lua_resume(L, from, narg) - USED to run our temp threads (it sets
    // up the initial call frame from the pushed args). NOT hooked: the task
    // scheduler bypasses it, so the threads that reach it have empty globals.
    static const uintptr_t kPubResumeRva  = 0x664cd40;
    // Internal resume(L) - the scheduler's real resume path; HOOKED. Its L is
    // the actual script/coroutine being resumed, so its globals are populated.
    static const uintptr_t kIntResumeRva  = 0x664ce00;
    static const uintptr_t kNewThreadRva  = 0x6648fb0;
    static const uintptr_t kGetFieldRva   = 0x6649fb0;
    // lua_rawget(L, idx): key from stack top, RAW luaH_get (no __index) - returns
    // the fetched value's type tag. Metamethod-free, so indexing the protected
    // global table for a missing key returns nil instead of raising a Luau error.
    static const uintptr_t kRawGetRva     = 0x6649f10;
    static const uintptr_t kNewLStrRva    = 0x6674d50;
    // loadstring's C impl has two policy jumps to the "not available" throws:
    //   1) RobloxScript-context gate  `jne` @ 0x35d35ce  (0F 85 01 05 00 00)
    //   2) LoadStringEnabled check    `je`  @ 0x35d36cc  (0F 84 F6 03 00 00)
    // NOPing both makes loadstring compile in every context / on the live server.
    static const uintptr_t kLoadstrGate1Rva = 0x35d35ce;
    static const uintptr_t kLoadstrGate2Rva = 0x35d36cc;
    static const int  kOffBase   = 0x30;
    static const int  kOffTop    = 0x38;
    static const int  kOffGlobal = 0x28;   // lua_State.global (global_State*)
    static const int  kOffGT     = 0x60;   // lua_State.gt (global table)
    static const int  kOffExtra  = 0x68;   // lua_State.userdata/ExtraSpace (identity+
                                           // capabilities @ +0x58); zeroed on fresh
                                           // threads - loadstring AVs without it.
    static const int  kOffCaps   = 0x58;   // capability bitmask within ExtraSpace
    static const int  kOffMainTh = 0x70;   // global_State.mainthread
    static const int  kTValSize  = 16;
    static const int  kOffTT     = 0x0c;
    static const int  kTagNumber = 3;
    static const int  kTagString = 6;
    static const int  kTagFunc   = 8;
    static const int  kGlobalsIdx = -10002;   // LUA_GLOBALSINDEX
    // Internal resume prologue: push rbx; sub rsp,0x20; mov rbx,rcx; nop dword[rax]
    static const unsigned char kResumePrologue[5] = { 0x40,0x53,0x48,0x83,0xec };

    typedef int        (*PubResume_t)(void* L, void* from, int narg);
    typedef int        (*IntResume_t)(void* L);            // internal resume(L)
    typedef void*      (*NewThread_t)(void* L);
    typedef void       (*GetField_t)(void* L, int idx, const char* k);
    typedef int        (*RawGet_t)(void* L, int idx);      // returns value's type tag
    typedef void*      (*NewLStr_t)(void* L, const char* s, size_t len);

    static PubResume_t g_pubResume   = nullptr;   // run temp threads
    static IntResume_t g_origResume  = nullptr;   // trampoline to internal resume
    static NewThread_t g_newthread   = nullptr;
    static GetField_t  g_getfield    = nullptr;
    static RawGet_t    g_rawget      = nullptr;
    static NewLStr_t   g_newlstr     = nullptr;

    static std::deque<std::string> g_queue;
    static std::deque<std::string> g_queueQuiet;   // v10 property-repl: run without console echo
    static std::mutex              g_qmtx;
    static volatile long           g_pending = 0;   // fast "queue non-empty" flag
    static volatile long           g_inExec  = 0;   // re-entrancy guard

    void EnqueueConsoleScript(const std::string& code)
    {
        if (code.empty()) return;
        { std::lock_guard<std::mutex> lk(g_qmtx); g_queue.push_back(code); }
        InterlockedExchange(&g_pending, 1);
    }
    // Quiet variant for auto-applied property replication - runs on the server VM but
    // does NOT echo to the server console (would flood it). Cap the backlog so a burst
    // can't grow unbounded if the VM stalls.
    void EnqueueConsoleScriptQuiet(const std::string& code)
    {
        if (code.empty()) return;
        {
            std::lock_guard<std::mutex> lk(g_qmtx);
            if (g_queueQuiet.size() >= 8192) g_queueQuiet.pop_front();
            g_queueQuiet.push_back(code);
        }
        InterlockedExchange(&g_pending, 1);
    }
    static bool Dequeue(std::string& out)
    {
        std::lock_guard<std::mutex> lk(g_qmtx);
        if (g_queue.empty()) { if (g_queueQuiet.empty()) InterlockedExchange(&g_pending, 0); return false; }
        out = std::move(g_queue.front());
        g_queue.pop_front();
        if (g_queue.empty() && g_queueQuiet.empty()) InterlockedExchange(&g_pending, 0);
        return true;
    }
    static bool DequeueQuiet(std::string& out)
    {
        std::lock_guard<std::mutex> lk(g_qmtx);
        if (g_queueQuiet.empty()) { if (g_queue.empty()) InterlockedExchange(&g_pending, 0); return false; }
        out = std::move(g_queueQuiet.front());
        g_queueQuiet.pop_front();
        if (g_queue.empty() && g_queueQuiet.empty()) InterlockedExchange(&g_pending, 0);
        return true;
    }

    static inline char* Top(void* L){ return *reinterpret_cast<char**>(reinterpret_cast<char*>(L)+kOffTop); }
    static inline void  SetTop(void* L, char* t){ *reinterpret_cast<char**>(reinterpret_cast<char*>(L)+kOffTop)=t; }
    static inline char* Base(void* L){ return *reinterpret_cast<char**>(reinterpret_cast<char*>(L)+kOffBase); }

    // The VM's main thread: L->global->mainthread. Its gt is the real global
    // table (print, pairs, and - when LoadStringEnabled - loadstring), unlike the
    // sandboxed/empty gt on the coroutines the scheduler resumes. We only READ its
    // gt pointer; we never spawn from or push onto the mainthread's own stack
    // (it may be live below us on the C stack), which would corrupt it.
    static inline void* MainThread(void* L)
    {
        char* g = *reinterpret_cast<char**>(reinterpret_cast<char*>(L) + kOffGlobal);
        return *reinterpret_cast<void**>(g + kOffMainTh);
    }

    // Push a Lua string built from `code` onto thread L's stack.
    static void PushString(void* L, const std::string& code)
    {
        char* t = Top(L);
        void* ts = g_newlstr(L, code.data(), code.size());
        *reinterpret_cast<void**>(t + 0)      = ts;
        *reinterpret_cast<int*>(t + kOffTT)   = kTagString;
        SetTop(L, t + kTValSize);
    }

    // Raw (metamethod-free) fetch of a global by name onto L's stack. Leaves the
    // value on top and returns its Luau type tag. Never triggers __index, so it
    // won't raise a Luau error on the protected global table.
    static int RawGetGlobal(void* L, const char* name)
    {
        PushString(L, std::string(name));      // push key string
        return g_rawget(L, kGlobalsIdx);       // pop key, push globals[name] raw
    }

    // All-capabilities value the elevated Protos point their cap field at.
    static uint64_t s_allCaps = ~0ULL;

    // Give a compiled closure's Proto full capabilities so the code may touch
    // Instances/DataModel. The capability callback reads caps from
    // closure->[0x20](proto)->[0x48] (a pointer to the mask); we repoint it at
    // s_allCaps. (Main proto only for now - nested-proto offsets unverified.)
    static void ElevateClosureCaps(void* closure)
    {
        if (!closure) return;
        void* proto = *reinterpret_cast<void**>(reinterpret_cast<char*>(closure) + 0x20);
        if (proto)
            *reinterpret_cast<void**>(reinterpret_cast<char*>(proto) + 0x48) = &s_allCaps;
    }

    // Compile + run `code` on fresh threads spawned off the current thread L,
    // borrowing the VM main thread's global table + a private elevated-capability
    // ExtraSpace. If outNum!=null and the chunk returns a number, it's captured.
    // quiet suppresses per-step logging (used for the silent server-VM probe).
    // Owns C++ objects, so no __try here (the SEH wrapper is above).
    static bool RunSource(void* L, const std::string& code, double* outNum, bool quiet)
    {
        char* saveTop = Top(L);

        // A fresh thread has an empty gt AND a null ExtraSpace (userdata @ +0x68).
        // loadstring's capability callback derefs [thread+0x68]->[+0x58], so a null
        // there is an instant AV. Borrow the gt + a PRIVATE, cap-elevated copy of
        // the ExtraSpace (mutating the shared one corrupts other threads), spawning
        // off the safe current L so we never touch the mainthread's own stack.
        void* mt      = MainThread(L);
        void* mainGT  = *reinterpret_cast<void**>(reinterpret_cast<char*>(mt) + kOffGT);
        void* mtExtra = *reinterpret_cast<void**>(reinterpret_cast<char*>(mt) + kOffExtra);

        static unsigned char s_extra[0x100];
        std::memcpy(s_extra, mtExtra, sizeof(s_extra));
        *reinterpret_cast<uint64_t*>(s_extra + kOffCaps) = ~0x8ULL;   // bit3(restricted) clear
        void* myExtra = s_extra;

        void* NL = g_newthread(L);
        if (!NL) { SetTop(L, saveTop); return false; }
        *reinterpret_cast<void**>(reinterpret_cast<char*>(NL) + kOffGT)    = mainGT;
        *reinterpret_cast<void**>(reinterpret_cast<char*>(NL) + kOffExtra) = myExtra;

        // Our worker threads point their ExtraSpace at a static buffer for the run.
        // When the GC later collects these throwaway threads it runs a userthread
        // destructor over [thread+0x68]; over a static buffer that crashes. This
        // guard nulls it back out on EVERY exit path (a fresh thread is null there,
        // which the destructor handles), via a C++ destructor - hence no __try here.
        struct ExtraGuard
        {
            void* th[2] = { nullptr, nullptr };
            ~ExtraGuard()
            {
                for (void* x : th)
                    if (x) *reinterpret_cast<void**>(reinterpret_cast<char*>(x) + kOffExtra) = nullptr;
            }
        } eg;
        eg.th[0] = NL;

        int lsTT = RawGetGlobal(NL, "loadstring");   // raw: no __index fault
        if (lsTT != kTagFunc)
        {
            if (!quiet) ServerConsoleLog(std::string("[offblox] loadstring unavailable - dropping: ") + code);
            SetTop(L, saveTop);
            return true;
        }

        // This lua_resume's 2nd arg is a StkId = the first ARG slot (func+1); func
        // is derived as (arg - 0x10). loadstring @ Base(NL), src @ Base(NL)+0x10.
        PushString(NL, code);
        char* nlb = Base(NL);
        int st = -1;
        try { st = g_pubResume(NL, nlb + kTValSize, 1); }   // compile: loadstring(src)
        catch (const std::exception& e)
        { SetTop(L, saveTop); if (!quiet) ServerConsoleLog(std::string("[offblox] loadstring threw: ") + e.what()); return true; }
        catch (...)
        { SetTop(L, saveTop); if (!quiet) ServerConsoleLog("[offblox] loadstring threw: <non-std>"); return true; }

        char* nltop = Top(NL);
        int baseTT = (nltop > nlb) ? *reinterpret_cast<int*>(nlb + kOffTT) : -99;
        if (baseTT != kTagFunc)                  // syntax error: loadstring -> nil, msg
        {
            if (!quiet)
            {
                int topTT = (nltop > nlb) ? *reinterpret_cast<int*>(nltop - kTValSize + kOffTT) : -99;
                if (topTT == kTagString)
                {
                    void* ts = *reinterpret_cast<void**>(nltop - kTValSize);
                    char b[200];
                    _snprintf_s(b, sizeof(b), _TRUNCATE, "[offblox] compile error: %.170s",
                                reinterpret_cast<const char*>(ts) + 0x18);
                    ServerConsoleLog(b);
                }
                else ServerConsoleLog(std::string("[offblox] compile error: ") + code);
            }
            SetTop(L, saveTop);
            return true;
        }

        // Compiled OK. Elevate the chunk's Proto caps so it may touch Instances.
        ElevateClosureCaps(*reinterpret_cast<void**>(nlb));

        void* NL2 = g_newthread(L);
        eg.th[1] = NL2;
        bool ok = false;
        if (NL2)
        {
            *reinterpret_cast<void**>(reinterpret_cast<char*>(NL2) + kOffGT)    = mainGT;
            *reinterpret_cast<void**>(reinterpret_cast<char*>(NL2) + kOffExtra) = myExtra;
            char* n2b = Base(NL2);
            std::memcpy(n2b, nlb, kTValSize);
            SetTop(NL2, n2b + kTValSize);
            int st2 = -1;
            try { st2 = g_pubResume(NL2, n2b + kTValSize, 0); }   // run the chunk
            catch (const std::exception& e)
            { if (!quiet) ServerConsoleLog(std::string("[offblox] run threw: ") + e.what()); st2 = -2; }
            catch (...)
            { if (!quiet) ServerConsoleLog("[offblox] run threw: <non-std>"); st2 = -2; }
            ok = (st2 == 0 || st2 == 1);
            char* n2top = Top(NL2);
            if (outNum && ok && n2top > n2b &&
                *reinterpret_cast<int*>(n2b + kOffTT) == kTagNumber)
                *outNum = *reinterpret_cast<double*>(n2b);   // capture numeric return
            if (!quiet && st2 > 1 && n2top > n2b &&
                *reinterpret_cast<int*>(n2top - kTValSize + kOffTT) == kTagString)
            {
                void* ts = *reinterpret_cast<void**>(n2top - kTValSize);
                char b[200];
                _snprintf_s(b, sizeof(b), _TRUNCATE, "[offblox] run error: %.170s",
                            reinterpret_cast<const char*>(ts) + 0x18);
                ServerConsoleLog(b);
            }
        }
        SetTop(L, saveTop);
        if (!quiet)
            ServerConsoleLog(ok ? (std::string("[offblox] ran: ") + code)
                                : (std::string("[offblox] FAILED: ") + code));
        return true;
    }

    static void* g_serverGlobal = nullptr;    // cached global_State of the live server VM
    static void* g_probed[24];                // VMs already probed (dedupe)
    static int   g_nprobed = 0;

    // ================= v10 pure-C++ property apply (main thread) =============
    // Client ships {guid64, prop, variant}. On the main thread we resolve guid64 to the
    // server instance (via a guid->instance map built by walking the DataModel with the
    // confirmed offsets), resolve the descriptor, and call the engine's setValue - so the
    // write happens through the engine and replicates. No Lua, no executor.
    struct GuidChange { unsigned long long guid; char prop[64]; unsigned char var[96]; int tries; };
    static std::deque<GuidChange> g_gcQueue;
    static std::mutex             g_gcMtx;
    static volatile long          g_gcApplied = 0, g_gcMiss = 0, g_gcMapSize = 0;

    // Called from the network thread (udp_relay). Thread-safe; wakes the main-thread drain.
    void EnqueueGuidChange(unsigned long long guid, const char* prop, int plen,
                           const unsigned char* var, int vlen)
    {
        /* if (!guid || plen <= 0 || plen >= 64 || vlen <= 0 || vlen > 96) return;
        GuidChange c; c.guid = guid; c.tries = 0;
        std::memcpy(c.prop, prop, plen); c.prop[plen] = 0;
        std::memset(c.var, 0, sizeof(c.var)); std::memcpy(c.var, var, vlen);
        { std::lock_guard<std::mutex> lk(g_gcMtx); if (g_gcQueue.size() >= 8192) g_gcQueue.pop_front(); g_gcQueue.push_back(c); }
        InterlockedExchange(&g_pending, 1);  */
    }

    // ---- engine memory helpers (C-only: SEH-legal, no unwindable objects) ----
    static const long kGuidOff = 0x30, kCDOff = 0x18, kPropArr = 0x40, kPropCnt = 0x48, kDescName = 0x08;
    static uintptr_t s_hostLo = 0, s_hostLen = 0;
    static bool InHost(uintptr_t p)
    {
        if (!s_hostLo)
        {
            s_hostLo = reinterpret_cast<uintptr_t>(GetModuleHandleW(nullptr));
            if (s_hostLo) { auto dos = reinterpret_cast<IMAGE_DOS_HEADER*>(s_hostLo);
                auto nt = reinterpret_cast<IMAGE_NT_HEADERS*>(s_hostLo + dos->e_lfanew);
                s_hostLen = nt->OptionalHeader.SizeOfImage; }
        }
        return s_hostLo && p >= s_hostLo && p < s_hostLo + s_hostLen;
    }
    static uintptr_t RdPtr(uintptr_t a) { __try { return *reinterpret_cast<uintptr_t*>(a); } __except (EXCEPTION_EXECUTE_HANDLER) { return 0; } }
    static unsigned long long RdGuid(uintptr_t inst)
    {
        __try { unsigned idx = *reinterpret_cast<unsigned*>(inst + kGuidOff);
                if (idx == 0xFFFFFFFFu) return 0;
                return *reinterpret_cast<unsigned long long*>(inst + kGuidOff); }
        __except (EXCEPTION_EXECUTE_HANDLER) { return 0; }
    }
    // children detection: field -> Instances* vector {begin,end,cap}; elements are
    // shared_ptr<Instance> (16B); element[0].ptr is an Instance with an in-host vtable.
    static long g_childrenOff = -1;
    static long DetectChildrenOff(uintptr_t inst)
    {
       /* __try {
            for (long off = 0x38; off <= 0x88; off += 8)
            {
                uintptr_t vec = *reinterpret_cast<uintptr_t*>(inst + off);
                if (vec < 0x10000 || (vec & 7)) continue;
                uintptr_t begin = *reinterpret_cast<uintptr_t*>(vec);
                uintptr_t end   = *reinterpret_cast<uintptr_t*>(vec + 8);
                if (begin < 0x10000 || end <= begin || (end - begin) % 16 || (end - begin) > 0x400000) continue;
                uintptr_t child = *reinterpret_cast<uintptr_t*>(begin);
                if (child > 0x10000 && InHost(*reinterpret_cast<uintptr_t*>(child))) return off;
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {}*/
        return -1;
    }
    static void* ResolveDescriptorS(void* instance, const char* propName)
    {
      /*  if (!instance || !propName) return nullptr;
        __try {
            uintptr_t cd = *reinterpret_cast<uintptr_t*>(reinterpret_cast<char*>(instance) + kCDOff);
            if (!cd) return nullptr;
            uintptr_t begin = *reinterpret_cast<uintptr_t*>(cd + kPropArr);
            uintptr_t count = *reinterpret_cast<uintptr_t*>(cd + kPropCnt);
            if (!begin || count == 0 || count > 8192) return nullptr;
            for (uintptr_t i = 0; i < count; ++i) {
                uintptr_t pd = *reinterpret_cast<uintptr_t*>(begin + i * 8);
                if (!pd) continue;
                const char* nm = *reinterpret_cast<const char**>(pd + kDescName);
                if (nm && std::strcmp(nm, propName) == 0) return reinterpret_cast<void*>(pd);
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {}*/
        return nullptr;
    }
    // setValue(descriptor, instance, notify, Variant*) @ host+0x13F6A60.
    typedef void (*SetVal_t)(void* desc, void* inst, unsigned char notify, void* variant);
    static bool CallSetValue(void* desc, void* inst, void* variant)
    {
        __try {
            // TEMPORARILY DISABLED. The client currently ships a VALUE-FIRST Variant
            // (getValue's Reflection::Variant: value at +0, type tag at the end), but
            // setValue @ host+0x13F6A60 wants a WIRE Variant {int typeIdx @ +0; value @ +8}.
            // Feeding the former to the latter makes setValue read value bytes as the type
            // index and, if they form a valid pointer-type index, copy/deref garbage ->
            // heap corruption that crashes past SEH. No index guard can make that safe. So
            // we do NOT call setValue until the client ships a correctly-built wire Variant
            // (needs the VARDUMP to locate the type tag + its index mapping). Resolution +
            // logging above still run, so the pipe is proven end-to-end meanwhile.
            (void)desc; (void)inst; (void)variant;
            return false;
            /* re-enable once the wire Variant is correct:
            unsigned typeIdx = *reinterpret_cast<unsigned*>(variant);
            if (typeIdx == 0 || typeIdx >= 256) return false;
            uintptr_t copyfn = *reinterpret_cast<uintptr_t*>(s_hostLo + 0x8b00430 + (uintptr_t)typeIdx * 8);
            uintptr_t dtorfn = *reinterpret_cast<uintptr_t*>(s_hostLo + 0x8affd80 + (uintptr_t)typeIdx * 8);
            uintptr_t lo = s_hostLo, hi = s_hostLo + 0x10000000;
            if (copyfn < lo || copyfn >= hi || dtorfn < lo || dtorfn >= hi) return false;
            SetVal_t fn = reinterpret_cast<SetVal_t>(s_hostLo + 0x13F6A60);
            fn(desc, inst, 1, variant); return true;
            */
        }
        __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
    }
    // Read 'game' -> DataModel Instance* (main thread; scratch thread borrows main gt).
    static void* GetGameInstance(void* L)
    {
        char* saveTop = Top(L);
        void* mt = MainThread(L);
        void* mainGT = *reinterpret_cast<void**>(reinterpret_cast<char*>(mt) + kOffGT);
        void* NL = g_newthread(L);
        if (!NL) { SetTop(L, saveTop); return nullptr; }
        *reinterpret_cast<void**>(reinterpret_cast<char*>(NL) + kOffGT) = mainGT;
        void* inst = nullptr;
        if (RawGetGlobal(NL, "game") > 0) {
            uintptr_t ud = RdPtr(reinterpret_cast<uintptr_t>(Top(NL)) - kTValSize);
            if (ud) { uintptr_t i = RdPtr(ud + 0x10); if (i && InHost(RdPtr(i))) inst = reinterpret_cast<void*>(i); }
        }
        SetTop(L, saveTop);
        return inst;
    }

    // Build the guid->instance map by iterative DataModel walk (capped, main thread).
    static std::unordered_map<unsigned long long, void*> g_guidMap;
    static ULONGLONG g_mapLastBuild = 0;
    static void BuildGuidMap(void* game)
    {
        if (!game) return;
        uintptr_t root = reinterpret_cast<uintptr_t>(game);
        if (g_childrenOff < 0) g_childrenOff = DetectChildrenOff(root);
        if (g_childrenOff < 0) return;
        g_guidMap.clear();
        std::deque<uintptr_t> stack; stack.push_back(root);
        int visited = 0;
        while (!stack.empty() && visited < 300000)
        {
            uintptr_t inst = stack.back(); stack.pop_back(); ++visited;
            unsigned long long g = RdGuid(inst);
            // Key by the INDEX (high 32) only: the scope (low 32) is mapped per-process so
            // it differs client<->server, but the index is preserved through replication.
            if (g) g_guidMap[g >> 32] = reinterpret_cast<void*>(inst);
            uintptr_t vec = RdPtr(inst + g_childrenOff);
            if (!vec) continue;
            uintptr_t begin = RdPtr(vec), end = RdPtr(vec + 8);
            if (!begin || end <= begin || (end - begin) % 16 || (end - begin) > 0x400000) continue;
            for (uintptr_t p = begin; p < end; p += 16)
            {
                uintptr_t child = RdPtr(p);
                if (child > 0x10000 && InHost(RdPtr(child))) stack.push_back(child);
            }
        }
        g_gcMapSize = (long)g_guidMap.size();
    }

    // Drain the change queue and apply on the main thread. The map is built once and
    // refreshed only on a miss (throttled) - NOT every tick - so a heavy script doesn't
    // rebuild a huge map continuously (which stalled the VM).
    static void ApplyGuidChanges(void* L)
    {
        /*
       bool have;
        { std::lock_guard<std::mutex> lk(g_gcMtx); have = !g_gcQueue.empty(); }
        if (!have) return;
        // Cache the DataModel pointer ONCE. GetGameInstance creates a Lua thread; doing that
        // on every rebuild (which the retry storm triggered several times a second) is unsafe
        // inside the resume hook (GC / stack realloc mid-execution) and was crashing the
        // server. The DataModel is stable for the session, so resolve it a single time.
        static void* g_gameInst = nullptr;
        if (!g_gameInst) g_gameInst = GetGameInstance(L);
        if (g_guidMap.empty() && g_gameInst)
        {
            InHost(0); BuildGuidMap(g_gameInst);
            g_mapLastBuild = GetTickCount64();
        }
        static int s_logged = 0;
        std::deque<GuidChange> retry;   // misses (instance not replicated yet) re-queued after the pass
        for (int budget = 0; budget < 128; ++budget)
        {
            GuidChange c;
            { std::lock_guard<std::mutex> lk(g_gcMtx); if (g_gcQueue.empty()) break; c = g_gcQueue.front(); g_gcQueue.pop_front(); }
            unsigned long long idxKey = c.guid >> 32;   // match on index (scope differs cross-process)
            auto it = g_guidMap.find(idxKey);
            if (it == g_guidMap.end())
            {
                ULONGLONG now = GetTickCount64();
                if (now - g_mapLastBuild > 750)   // throttled refresh (cached game ptr, no thread) then retry
                {
                    if (g_gameInst) BuildGuidMap(g_gameInst); g_mapLastBuild = now;
                    it = g_guidMap.find(idxKey);
                }
                if (it == g_guidMap.end())
                {
                    // The instance likely hasn't replicated to the server yet (client just
                    // created it, e.g. a Weld whose C0 is animated immediately). Re-queue and
                    // retry as the map catches up, rather than dropping the change.
                    if (c.tries < 60) { c.tries++; retry.push_back(c); }
                    else
                    {
                        static int s_missLog = 0;
                        if (s_missLog < 6) { s_missLog++;
                            unsigned long long sample = g_guidMap.empty() ? 0ull : g_guidMap.begin()->first;
                            char b[184]; _snprintf_s(b, sizeof(b), _TRUNCATE,
                                "[offblox] MISS(gaveup) clientGuid=0x%llX not in map(size=%ld childOff=+0x%lX) sampleMapGuid=0x%llX prop=%s",
                                (unsigned long long)c.guid, g_gcMapSize, (unsigned long)g_childrenOff,
                                (unsigned long long)sample, c.prop);
                            ServerConsoleLog(b); }
                        InterlockedIncrement(&g_gcMiss);
                    }
                    continue;
                }
            }
            void* inst = it->second;
            void* desc = ResolveDescriptorS(inst, c.prop);
            if (!desc) { InterlockedIncrement(&g_gcMiss);
                static int s_dLog = 0; if (s_dLog < 4) { s_dLog++; char b[128];
                    _snprintf_s(b, sizeof(b), _TRUNCATE, "[offblox] MISS-desc prop=%s inst=%p (guid resolved, descriptor not found)", c.prop, inst);
                    ServerConsoleLog(b); }
                continue; }
            // Log BEFORE setValue so if it faults, the last line names the culprit property.
            if (s_logged < 10) { s_logged++; char b[144];
                _snprintf_s(b, sizeof(b), _TRUNCATE, "[offblox] apply prop=%s guid=0x%llX inst=%p var0=%u",
                            c.prop, (unsigned long long)c.guid, inst, (unsigned)c.var[0]);
                ServerConsoleLog(b); }
            if (CallSetValue(desc, inst, c.var)) InterlockedIncrement(&g_gcApplied);
        }
        if (!retry.empty())
        {
            std::lock_guard<std::mutex> lk(g_gcMtx);
            for (auto& r : retry) { if (g_gcQueue.size() < 8192) g_gcQueue.push_back(r); }
            InterlockedExchange(&g_pending, 1);   // keep the drain scheduled until they resolve
        }
        static ULONGLONG hb = 0; ULONGLONG t = GetTickCount64();
        if (t - hb > 4000) { hb = t; char b[128];
            _snprintf_s(b, sizeof(b), _TRUNCATE, "[offblox] guid-apply: applied=%ld miss=%ld map=%ld childOff=+0x%lX",
                        g_gcApplied, g_gcMiss, g_gcMapSize, (unsigned long)g_childrenOff);
            ServerConsoleLog(b); }

    */
    }

    // Owns C++ objects (std::string), so it must NOT contain __try; the SEH
    // wrapper lives in Hook_resume, which has no unwindable objects.
    static void DrainAndRunAll(void* L)
    {
        void* g = *reinterpret_cast<void**>(reinterpret_cast<char*>(L) + kOffGlobal);

        // Only execute in the LIVE server DataModel's VM. Multiple VMs resume
        // through this hook (Studio/edit, CoreGui, server); the server one is the
        // DataModel whose Workspace has >1 child. Probe each VM AT MOST ONCE (a
        // probe is a full compile+run, so probing every resume would hammer the VM
        // and crash it). If this VM isn't the server, wait for a server-VM resume.
        if (!g_serverGlobal)
        {
            for (int i = 0; i < g_nprobed; ++i) if (g_probed[i] == g) return;  // already probed, skip
            if (g_nprobed < 24) g_probed[g_nprobed++] = g;

            double n = -1.0;
            RunSource(L, "return #workspace:GetChildren()", &n, false);
            if (n > 1.0)
            {
                g_serverGlobal = g;
                char b[88];
                _snprintf_s(b, sizeof(b), _TRUNCATE,
                            "[offblox] server VM locked: global=%p (workspace children=%d)",
                            g, (int)n);
                ServerConsoleLog(b);

                // DataModel is live now - safe to force FilteringEnabled OFF at the
                // C++ level (the getter is hardcoded true, so the property is a
                // no-op). Doing it this late avoids the startup crash that early
                // (DLL-load) patching caused, and it still lands before players
                // join. Every FE reader - including the replication filters - then
                // sees false, so client changes replicate to the server.
                ForceFilteringDisabled_Pub();
                // Also flip the FilteringEnabled getter (0x6FF1D0: mov al,1 -> mov al,0)
                // so every reader - including workspace.FilteringEnabled and the ~120
                // server replication-filter call sites - sees FE OFF. Without this the
                // accept patches let client items through but the getter still reports
                // true. Applied here (VM-lock) so it lands after the DataModel is live.
                ForceFilteringDisabledGetter_Pub();
            }
            else
            {
                char b[88];
                _snprintf_s(b, sizeof(b), _TRUNCATE,
                            "[offblox] probed VM global=%p (workspace children=%d) - not server",
                            g, (int)n);
                ServerConsoleLog(b);
                return;
            }
        }
        if (g != g_serverGlobal) return;

        std::string code;
        while (Dequeue(code))
            RunSource(L, code, nullptr, false);

        // v10 property-replication: pure-C++ apply on the main thread (no Lua/executor).
        //ApplyGuidChanges(L);
        
    }

    static int Hook_resume(void* L)
    {
        // Do the engine's real resume FIRST so L's coroutine completes normally,
        // then run queued lines. If g_origResume throws, we simply never reach the
        // drain (and g_inExec is untouched) - no leaked state. The g_inExec CAS
        // prevents our own g_pubResume(NL) from recursively draining.
        int r = g_origResume(L);

        if (g_pending &&
            InterlockedCompareExchange(&g_inExec, 1, 0) == 0)
        {
            __try { DrainAndRunAll(L); }
            __except (LogExFilter(GetExceptionInformation()))
            { LogC("[offblox] tick: FAULT (SEH caught)"); }
            InterlockedExchange(&g_inExec, 0);
        }
        return r;
    }

    void InstallLoadstringConsoleHook()
    {
        if (!IsStartServerTask_Pub())
        {
            ServerConsoleLog("[offblox] console hook: not StartServer task - skipped");
            return;
        }

        uintptr_t base = reinterpret_cast<uintptr_t>(GetModuleHandleW(nullptr));
        g_pubResume = reinterpret_cast<PubResume_t>(base + kPubResumeRva);
        g_newthread = reinterpret_cast<NewThread_t>(base + kNewThreadRva);
        g_getfield  = reinterpret_cast<GetField_t>(base + kGetFieldRva);
        g_rawget    = reinterpret_cast<RawGet_t>(base + kRawGetRva);
        g_newlstr   = reinterpret_cast<NewLStr_t>(base + kNewLStrRva);

        // Patch both loadstring policy jumps to NOPs so it compiles on the live
        // server DataModel (LoadStringEnabled off / RobloxScript context).
        auto patchGate = [](uintptr_t va, const unsigned char (&expect)[6], const char* tag)
        {
            unsigned char* g = reinterpret_cast<unsigned char*>(va);
            if (std::memcmp(g, expect, 6) == 0)
            {
                DWORD oldp = 0;
                if (VirtualProtect(g, 6, PAGE_EXECUTE_READWRITE, &oldp))
                {
                    std::memset(g, 0x90, 6);
                    VirtualProtect(g, 6, oldp, &oldp);
                    FlushInstructionCache(GetCurrentProcess(), g, 6);
                    ServerConsoleLog(std::string("[offblox] loadstring gate patched: ") + tag);
                }
                else ServerConsoleLog(std::string("[offblox] gate VirtualProtect failed: ") + tag);
            }
            else
            {
                char b[112];
                _snprintf_s(b, sizeof(b), _TRUNCATE,
                    "[offblox] gate mismatch %s (%02X %02X %02X %02X %02X %02X)",
                    tag, g[0], g[1], g[2], g[3], g[4], g[5]);
                ServerConsoleLog(b);
            }
        };
        {
            const unsigned char e1[6] = { 0x0F, 0x85, 0x01, 0x05, 0x00, 0x00 };
            const unsigned char e2[6] = { 0x0F, 0x84, 0xF6, 0x03, 0x00, 0x00 };
            patchGate(base + kLoadstrGate1Rva, e1, "RobloxScript-context");
            patchGate(base + kLoadstrGate2Rva, e2, "LoadStringEnabled");
        }

        unsigned char* rs = reinterpret_cast<unsigned char*>(base + kIntResumeRva);
        if (std::memcmp(rs, kResumePrologue, sizeof(kResumePrologue)) != 0)
        {
            char b[128];
            _snprintf_s(b, sizeof(b), _TRUNCATE,
                "[offblox] console hook: prologue mismatch @ %p (%02X %02X %02X %02X %02X)",
                (void*)rs, rs[0], rs[1], rs[2], rs[3], rs[4]);
            ServerConsoleLog(b);
            return;
        }

        if (InlineHookVA(base + kIntResumeRva,
                         reinterpret_cast<void*>(&Hook_resume),
                         reinterpret_cast<void**>(&g_origResume)))
        {
            ServerConsoleLog("[offblox] console hook: internal resume hooked OK");
        }
        else
        {
            ServerConsoleLog("[offblox] console hook: InlineHookVA FAILED");
        }
    }
}
