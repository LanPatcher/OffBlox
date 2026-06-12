/*
 * HookedWebserver.dll
 * ===================
 * 32-bit C++ DLL — load into Roblox Studio via Stud_PE import-table injection.
 * Starts an embedded HTTP (port 80) + HTTPS (port 443) server the moment the
 * host process loads the DLL.  Multiple instances of the same EXE can run
 * simultaneously — only the first to acquire the named mutex becomes the
 * active server; every other instance is a watchdog that polls /ping and
 * takes over the moment the server goes silent.
 *
 * ALL file paths are resolved RELATIVE TO THE DLL'S OWN DIRECTORY using
 * GetModuleFileName(g_hDll, ...).  Drop the DLL next to your www/, data/,
 * ssl/ folders and everything works regardless of where the host EXE lives.
 *
 * Layout expected next to the DLL:
 *   config.json          — optional overrides
 *   ssl\server.crt       — PEM X.509 certificate (copied from Apache certificats)
 *   ssl\server.key       — PEM private key     (copied from Apache certificats)
 *   www\                 — static files (images, pem, lua, etc.)
 *   data\                — runtime storage (datastores, persistence, SavedData)
 *
 * Build: MSVC  x86  /MT  /O2  /D_WIN32_WINNT=0x0501  (XP SP3 +)
 *        see Build.bat
 */

#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#define _WIN32_WINNT 0x0501
#define SECURITY_WIN32


#include <zlib.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <shlwapi.h>
#include <wincrypt.h>
#include <security.h>
#include <sspi.h>
#include <schannel.h>
/* winhttp.h and wininet.h conflict (both define INTERNET_SCHEME_HTTPS with
 * different values).  We now use WinHTTP exclusively, so wininet.h is gone. */
#include <winhttp.h>

#include <string>
#include <vector>
#include <mutex>
#include <map>
#include <algorithm>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <cctype>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "secur32.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "gdi32.lib")

/* WinHTTP constants that may be absent from older SDK headers */
#ifndef WINHTTP_OPTION_DECOMPRESSION
#  define WINHTTP_OPTION_DECOMPRESSION       118
#endif
#ifndef WINHTTP_DECOMPRESSION_FLAG_GZIP
#  define WINHTTP_DECOMPRESSION_FLAG_GZIP    0x00000001
#  define WINHTTP_DECOMPRESSION_FLAG_DEFLATE 0x00000002
#  define WINHTTP_DECOMPRESSION_FLAG_ALL     0x00000003
#endif
/* Security ignore-flags — same values in winhttp.h and wininet.h */
#ifndef SECURITY_FLAG_IGNORE_REVOCATION
#  define SECURITY_FLAG_IGNORE_REVOCATION        0x00000080
#  define SECURITY_FLAG_IGNORE_UNKNOWN_CA        0x00000100
#  define SECURITY_FLAG_IGNORE_CERT_CN_INVALID   0x00001000
#  define SECURITY_FLAG_IGNORE_CERT_DATE_INVALID 0x00002000
#endif

/* TLS 1.1 / 1.2 constants absent from older SDK headers */
#ifndef SP_PROT_TLS1_1_SERVER
#  define SP_PROT_TLS1_1_SERVER 0x00000100
#endif
#ifndef SP_PROT_TLS1_2_SERVER
#  define SP_PROT_TLS1_2_SERVER 0x00000400
#endif

/* ============================================================================
   Globals
   ========================================================================= */
static HMODULE   g_hDll         = NULL;
static char      g_dllDir[MAX_PATH] = {0};

static volatile BOOL g_shutdown  = FALSE;
static volatile BOOL g_isServer  = FALSE;
static HANDLE        g_hOwnerMutex = NULL;

static SOCKET    g_httpSock      = INVALID_SOCKET;
static SOCKET    g_httpsSock     = INVALID_SOCKET;

static CredHandle g_hCred;
static BOOL       g_credValid    = FALSE;
static PCCERT_CONTEXT g_pCert   = NULL;

static HCRYPTKEY  g_hSignKey     = NULL;
static HCRYPTPROV g_hSignProv    = NULL;
static BOOL       g_signKeyLoaded= FALSE;

/* config */
static int g_httpPort   = 80;
static int g_httpsPort  = 443;
static int g_wdInterval = 1000;
static int g_wdRetries  = 3;

/* identity — loaded from username.txt next to the DLL at startup */
static std::string g_username = "k643h20e48tNParker22";
static std::string g_userId   = "701953216";   /* string form for JSON */

/* ============================================================================
   SECTION 1 — DLL-relative paths
   ========================================================================= */
static void InitDllDir()
{
    char buf[MAX_PATH] = {0};
    GetModuleFileNameA(g_hDll, buf, MAX_PATH);
    PathRemoveFileSpecA(buf);
    lstrcpyA(g_dllDir, buf);
    int n = lstrlenA(g_dllDir);
    if (n > 0 && g_dllDir[n-1] != '\\') lstrcatA(g_dllDir, "\\");
}

static std::string DllPath(const char* rel)
{
    std::string s(g_dllDir);
    s += rel;
    return s;
}

std::string GzipDecompress(const std::string& input)
{
    z_stream zs = {};
    inflateInit2(&zs, 16 + MAX_WBITS); // gzip

    zs.next_in = (Bytef*)input.data();
    zs.avail_in = (uInt)input.size();

    std::string out;
    char buffer[16384];

    int ret;
    do
    {
        zs.next_out = (Bytef*)buffer;
        zs.avail_out = sizeof(buffer);

        ret = inflate(&zs, 0);

        if (out.size() < zs.total_out)
            out.append(buffer, zs.total_out - out.size());

    } while (ret == Z_OK);

    inflateEnd(&zs);

    return ret == Z_STREAM_END ? out : std::string();
}

/* gzip-compress (the inverse of GzipDecompress). Used to store place files on
 * disk compressed — Roblox ships them gzipped, so keeping ours gzipped saves a
 * lot of space vs. the plain .rbxl we used to write. Returns "" on failure. */
std::string GzipCompress(const std::string& input)
{
    z_stream zs = {};
    if (deflateInit2(&zs, Z_BEST_COMPRESSION, Z_DEFLATED,
                     16 + MAX_WBITS, 8, Z_DEFAULT_STRATEGY) != Z_OK)
        return std::string();

    zs.next_in  = (Bytef*)input.data();
    zs.avail_in = (uInt)input.size();

    std::string out;
    char buffer[16384];
    int ret;
    do {
        zs.next_out  = (Bytef*)buffer;
        zs.avail_out = sizeof(buffer);
        ret = deflate(&zs, Z_FINISH);
        if (out.size() < zs.total_out)
            out.append(buffer, zs.total_out - out.size());
    } while (ret == Z_OK);

    deflateEnd(&zs);
    return ret == Z_STREAM_END ? out : std::string();
}

/* gzip magic bytes 1F 8B. */
static inline bool IsGzip(const std::string& s)
{
    return s.size() >= 2 &&
           (unsigned char)s[0] == 0x1f && (unsigned char)s[1] == 0x8b;
}

/* Return raw bytes: decompress if gzipped, else pass through unchanged. Safe to
 * apply to any asset read — non-gzip data (PNG, mesh, XML, binary rbxl) is left
 * as-is. On a decompress failure the original bytes are returned. */
static std::string GunzipIfNeeded(const std::string& s)
{
    if (!IsGzip(s)) return s;
    std::string dec = GzipDecompress(s);
    return dec.empty() ? s : dec;
}

/* ============================================================================
   SECTION 2 — Minimal config.json reader
   ========================================================================= */
static std::string CfgStr(const std::string& json, const char* key)
{
    std::string k = "\""; k += key; k += "\"";
    size_t p = json.find(k);
    if (p == std::string::npos) return "";
    p += k.size();
    while (p < json.size() && (json[p]==' '||json[p]=='\t'||json[p]==':')) p++;
    if (p >= json.size()) return "";
    if (json[p] == '"') {
        p++;
        std::string v;
        while (p < json.size() && json[p] != '"') v += json[p++];
        return v;
    }
    std::string v;
    while (p < json.size() && json[p]!=',' && json[p]!='}' && json[p]!='\n') v += json[p++];
    while (!v.empty() && isspace((unsigned char)v.back())) v.pop_back();
    return v;
}

static void LoadConfig()
{
    std::string path = DllPath("config.json");
    FILE* f = fopen(path.c_str(), "rb");
    if (!f) return;
    fseek(f,0,SEEK_END); long sz=ftell(f); fseek(f,0,SEEK_SET);
    std::string buf(sz, '\0');
    fread(&buf[0], 1, sz, f); fclose(f);

    std::string v;
    v=CfgStr(buf,"port");             if(!v.empty()) g_httpPort  =atoi(v.c_str());
    v=CfgStr(buf,"httpsPort");        if(!v.empty()) g_httpsPort =atoi(v.c_str());
    v=CfgStr(buf,"watchdogIntervalMs");if(!v.empty()) g_wdInterval=atoi(v.c_str());
    v=CfgStr(buf,"watchdogRetries");  if(!v.empty()) g_wdRetries =atoi(v.c_str());
}

/* Reads username.txt next to the DLL.
 * Format (all lines optional):
 *   Line 1 — username   (e.g.  MyName)
 *   Line 2 — numeric user-id  (e.g.  701953216)
 * Missing lines keep the compiled-in defaults. */
/* Derives a stable numeric user ID from a username string.
 * Uses FNV-1a 32-bit, then maps the result into [10000000, 99999999]
 * so it always looks like a plausible 8-digit Roblox user ID.
 * Same username always produces the same number; different usernames
 * almost certainly produce different numbers. */
static std::string UserIdFromUsername(const std::string& name)
{
    uint32_t hash = 2166136261UL;   /* FNV-1a offset basis */
    for (size_t i = 0; i < name.size(); i++) {
        hash ^= (uint8_t)name[i];
        hash *= 16777619UL;         /* FNV prime */
    }
    /* Map into [10000000 .. 99999999] (8 digits) */
    uint32_t id = 10000000UL + (hash % 90000000UL);
    char buf[16];
    sprintf(buf, "%u", (unsigned)id);
    return std::string(buf);
}

static void LoadUsername()
{
    std::string path = DllPath("username.txt");
    FILE* f = fopen(path.c_str(), "rb");
    if (!f) return;
    fseek(f,0,SEEK_END); long sz=ftell(f); fseek(f,0,SEEK_SET);
    if (sz <= 0) { fclose(f); return; }
    std::string raw((size_t)sz, '\0');
    fread(&raw[0], 1, (size_t)sz, f); fclose(f);
    if (raw.empty()) return;

    /* split on first newline */
    size_t nl = raw.find('\n');
    std::string uline  = (nl != std::string::npos) ? raw.substr(0, nl) : raw;
    std::string idline = (nl != std::string::npos) ? raw.substr(nl + 1) : "";

    /* trim both lines */
    while (!uline.empty()  && (uline.back() =='\r'||uline.back() =='\n'||uline.back() ==' ')) uline.resize(uline.size()-1);
    while (!idline.empty() && (idline.back()=='\r'||idline.back()=='\n'||idline.back()==' ')) idline.resize(idline.size()-1);

    if (!uline.empty()) {
        g_username = uline;
        /* Derive userId from username — same name always gives same ID.
         * Line 2 of username.txt can override with an explicit number. */
        g_userId = UserIdFromUsername(g_username);
    }
    if (!idline.empty()) g_userId = idline;
}

/* Template substituion helper used by all JSON responses.
 * In a template string: {U} is replaced by g_username, {I} by g_userId.
 * Example: J("{\"name\":\"{U}\",\"id\":{I}}") */
static std::string J(const char* tmpl)
{
    std::string s(tmpl);
    for (size_t p; (p = s.find("{U}")) != std::string::npos;)
        s.replace(p, 3, g_username);
    for (size_t p; (p = s.find("{I}")) != std::string::npos;)
        s.replace(p, 3, g_userId);
    return s;
}

/* ============================================================================
   SECTION 3 — String / encoding utilities
   ========================================================================= */
static const char B64C[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static std::string Base64Encode(const unsigned char* d, size_t n)
{
    std::string o; o.reserve(((n+2)/3)*4);
    for (size_t i=0; i<n; i+=3) {
        unsigned int v = (unsigned int)d[i]<<16;
        if (i+1<n) v|=(unsigned int)d[i+1]<<8;
        if (i+2<n) v|=d[i+2];
        o += B64C[(v>>18)&63];
        o += B64C[(v>>12)&63];
        o += (i+1<n)?B64C[(v>>6)&63]:'=';
        o += (i+2<n)?B64C[v&63]:'=';
    }
    return o;
}

/* Compute base64(MD5(data)) — used for Content-MD5 response header */
static std::string ComputeMD5Base64(const std::string& body)
{
    HCRYPTPROV hProv = NULL;
    if (!CryptAcquireContextA(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
        return "";
    HCRYPTHASH hHash = NULL;
    std::string result;
    if (CryptCreateHash(hProv, CALG_MD5, 0, 0, &hHash)) {
        if (CryptHashData(hHash, (const BYTE*)body.data(), (DWORD)body.size(), 0)) {
            BYTE md5[16]; DWORD len = 16;
            if (CryptGetHashParam(hHash, HP_HASHVAL, md5, &len, 0))
                result = Base64Encode(md5, 16);
        }
        CryptDestroyHash(hHash);
    }
    CryptReleaseContext(hProv, 0);
    return result;
}

static std::string Base64UrlEncode(const unsigned char* d, size_t n)
{
    std::string s = Base64Encode(d, n);
    for (size_t i=0; i<s.size(); i++) {
        if      (s[i]=='+') s[i]='-';
        else if (s[i]=='/') s[i]='_';
        else if (s[i]=='=') { s.resize(i); break; }
    }
    return s;
}

static std::vector<unsigned char> Base64Decode(const std::string& s)
{
    static const signed char T[256] = {
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,62,-1,-1,-1,63,
        52,53,54,55,56,57,58,59,60,61,-1,-1,-1,-1,-1,-1,
        -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,
        15,16,17,18,19,20,21,22,23,24,25,-1,-1,-1,-1,-1,
        -1,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,
        41,42,43,44,45,46,47,48,49,50,51,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1
    };
    std::vector<unsigned char> out;
    int val=0, bits=-8;
    for (size_t i=0; i<s.size(); i++) {
        int c = T[(unsigned char)s[i]];
        if (c<0) continue;
        val = (val<<6)+c; bits+=6;
        if (bits>=0) { out.push_back((unsigned char)((val>>bits)&0xFF)); bits-=8; }
    }
    return out;
}

static std::string UrlDecode(const std::string& s)
{
    std::string o;
    for (size_t i=0; i<s.size(); i++) {
        if (s[i]=='%' && i+2<s.size()) {
            char h[3]={s[i+1],s[i+2],0};
            o+=(char)(unsigned char)strtol(h,NULL,16); i+=2;
        } else if (s[i]=='+') o+=' ';
        else o+=s[i];
    }
    return o;
}

static std::string UrlEncode(const std::string& s)
{
    static const char H[]="0123456789ABCDEF";
    std::string o;
    for (size_t i=0; i<s.size(); i++) {
        unsigned char c=(unsigned char)s[i];
        if (isalnum(c)||c=='-'||c=='_'||c=='.'||c=='~') o+=c;
        else { o+='%'; o+=H[c>>4]; o+=H[c&0xF]; }
    }
    return o;
}

static std::string ToLower(const std::string& s)
{
    std::string r=s;
    for (size_t i=0;i<r.size();i++) r[i]=(char)tolower((unsigned char)r[i]);
    return r;
}

static std::string MakeFakeJwt(const std::string& sub, const std::string& aud)
{
    time_t now=time(NULL);
    long iat=(long)now-5, exp_=iat+1800;
    char hdr[128], pay[2048];
    sprintf(hdr,"{\"alg\":\"ES256\",\"typ\":\"JWT\",\"kid\":\"hardcoded-key-1\"}");
    sprintf(pay,
        "{\"sub\":\"%s\",\"type\":\"User\","
        "\"iss\":\"http://localhost/oauth/\","
        "\"aud\":\"%s\",\"exp\":%ld,\"iat\":%ld,"
        "\"nonce\":\"id-roblox\","
        "\"name\":\"%s\","
        "\"nickname\":\"Dev\","
        "\"preferred_username\":\"%s\","
        "\"created_at\":1680000000,"
        "\"profile\":\"https://www.roblox.com/users/%s/profile\","
        "\"picture\":\"https://www.roblox.com/headshot-thumbnail/image"
            "?userId=%s&width=420&height=420\","
        "\"email\":\"dev@roblox.example\","
        "\"email_verified\":true,\"verified\":true,"
        "\"age_bracket\":\"18+\",\"premium\":true,"
        "\"roles\":[\"Developer\"],"
        "\"internal_user\":false,\"attributes\":{},"
        "\"banned\":false}",
        sub.c_str(), aud.c_str(), exp_, iat,
        g_username.c_str(), g_username.c_str(),
        g_userId.c_str(), g_userId.c_str());
    std::string h=Base64UrlEncode((const unsigned char*)hdr,strlen(hdr));
    std::string p=Base64UrlEncode((const unsigned char*)pay,strlen(pay));
    const char stub[]="hardcoded_signature";
    std::string sg=Base64UrlEncode((const unsigned char*)stub,strlen(stub));
    return h+"."+p+"."+sg;
}

/* ============================================================================
   SECTION 4 — File helpers
   ========================================================================= */
static std::string ReadFile(const std::string& path)
{
    FILE* f=fopen(path.c_str(),"rb");
    if(!f) return "";
    fseek(f,0,SEEK_END); long sz=ftell(f); fseek(f,0,SEEK_SET);
    if(sz<=0){fclose(f);return "";}
    std::string buf(sz,'\0');
    fread(&buf[0],1,sz,f); fclose(f);
    return buf;
}

static void WriteFile_(const std::string& path, const std::string& data)
{
    FILE* f=fopen(path.c_str(),"wb");
    if(!f) return;
    fwrite(data.c_str(),1,data.size(),f); fclose(f);
}

static void EnsureDir(const std::string& d)
{
    CreateDirectoryA(d.c_str(), NULL);
}

/* ============================================================================
   Universe persistence helpers
   Each universe is stored as data\universes\{universeId}.json next to the DLL.
   IDs start at LOCAL_ID_BASE (a huge number far beyond any real Roblox asset ID)
   and count upward.  Using positive IDs avoids the %2D URL-encoding problem that
   negative IDs caused (Studio encodes '-' as %2D in analytics/path segments).
   The next ID to issue is tracked in data\universes\next_id.txt.
   ========================================================================= */

/* Base value for locally-allocated universe and place IDs.
 * Must be larger than any real Roblox asset/universe ID in use, AND must fit
 * within JavaScript's Number.MAX_SAFE_INTEGER (2^53-1 = 9007199254740991) so
 * Studio's Chromium UI layer doesn't round the ID when it parses JSON.
 * Real Roblox universe IDs top out around 10^10-10^11; 9*10^12 is safely above
 * that and well below the JS precision limit. */
static const long long LOCAL_ID_BASE = 9000000000000LL;

static std::string UniversesDir()
{
    std::string d = DllPath("data\\universes\\");
    EnsureDir(d);
    return d;
}

/* Allocate and persist the next local universe ID.
 * IDs start at LOCAL_ID_BASE and increment by 2 each time (universe = even,
 * rootPlace = universe+1), keeping them well above any real Roblox ID. */
static std::string AllocUniverseId()
{
    std::string counterFile = UniversesDir() + "next_id.txt";
    std::string raw = ReadFile(counterFile);
    long long next = LOCAL_ID_BASE;
    if (!raw.empty()) {
        long long v = atoll(raw.c_str());
        if (v >= LOCAL_ID_BASE) next = v;
    }
    /* Persist the value after this one (+2 so rootPlaceId = universeId+1 stays distinct) */
    char nextBuf[32]; sprintf(nextBuf, "%lld", next + 2);
    WriteFile_(counterFile, nextBuf);
    char out[32]; sprintf(out, "%lld", next);
    return std::string(out);
}

/* Returns true if data\SavedData\{placeId} or {placeId}.rbxl (etc.) exists. */
static bool PlaceAssetExists(const std::string& placeId)
{
    std::string base = DllPath("data\\SavedData\\") + placeId;
    if (GetFileAttributesA(base.c_str()) != INVALID_FILE_ATTRIBUTES) return true;
    static const char* exts[] = { ".rbxl", ".rbxm", ".rbxlx", ".rbxmx", NULL };
    for (int i = 0; exts[i]; i++)
        if (GetFileAttributesA((base + exts[i]).c_str()) != INVALID_FILE_ATTRIBUTES) return true;
    return false;
}

/* Persist universe JSON to data\universes\{universeId}.json. */
static void SaveUniverseJson(const std::string& universeId, const std::string& json)
{
    WriteFile_(UniversesDir() + universeId + ".json", json);
}

/* ============================================================================
   Logging — writes to HookedWebserver.log next to the DLL
   ========================================================================= */
static CRITICAL_SECTION g_logCS;
static BOOL g_logCSInit = FALSE;

static void Log(const char* fmt, ...)
{
    if (!g_logCSInit) { InitializeCriticalSection(&g_logCS); g_logCSInit = TRUE; }
    char msg[1024];
    va_list va; va_start(va, fmt); _vsnprintf(msg, sizeof(msg)-1, fmt, va); va_end(va);
    msg[sizeof(msg)-1] = 0;

    SYSTEMTIME st; GetLocalTime(&st);
    char line[1200];
    _snprintf(line, sizeof(line)-1,
        "[%04d-%02d-%02d %02d:%02d:%02d] %s\r\n",
        st.wYear, st.wMonth, st.wDay,
        st.wHour, st.wMinute, st.wSecond, msg);
    line[sizeof(line)-1] = 0;

    EnterCriticalSection(&g_logCS);
    std::string logPath = DllPath("HookedWebserver.log");
    FILE* f = fopen(logPath.c_str(), "ab");
    if (f) { fputs(line, f); fclose(f); }
    LeaveCriticalSection(&g_logCS);

    OutputDebugStringA(line);  /* also visible in DebugView / VS debugger */
}

/* Update a single string field in a saved universe JSON file.
 * Reads the JSON, replaces "key":"oldvalue" with "key":"newvalue", writes back.
 * Creates the file if it doesn't exist yet. */
static void UpdateUniverseField(const std::string& universeId,
                                 const std::string& key,
                                 const std::string& newValue)
{
    std::string path = UniversesDir() + universeId + ".json";
    std::string raw  = ReadFile(path);
    if (raw.empty()) return;  /* no saved universe — nothing to update */

    /* Build search pattern: "key":"<anything>" */
    std::string kpat = "\"" + key + "\":";
    size_t kp = raw.find(kpat);
    if (kp == std::string::npos) {
        /* Field absent — append it as a quoted string just before the final }.
         * Lets us persist new settings (e.g. avatar config) that weren't part
         * of the universe JSON at creation time. */
        size_t close = raw.rfind('}');
        if (close == std::string::npos) return;
        std::string escaped;
        for (size_t i = 0; i < newValue.size(); i++) {
            if (newValue[i]=='"'||newValue[i]=='\\') escaped += '\\';
            escaped += newValue[i];
        }
        size_t p = close;
        while (p > 0 && (raw[p-1]==' '||raw[p-1]=='\t'||raw[p-1]=='\n'||raw[p-1]=='\r')) p--;
        std::string ins = (p > 0 && raw[p-1]=='{')           /* empty object? */
            ? "\"" + key + "\":\"" + escaped + "\""
            : ",\"" + key + "\":\"" + escaped + "\"";
        WriteFile_(path, raw.substr(0, close) + ins + raw.substr(close));
        Log("UpdateUniverseField: universe %s field '%s' appended -> '%s'",
            universeId.c_str(), key.c_str(), newValue.c_str());
        return;
    }

    /* Find where the value starts (skip optional whitespace) */
    size_t vs = kp + kpat.size();
    while (vs < raw.size() && (raw[vs]==' '||raw[vs]=='\t')) vs++;
    if (vs >= raw.size()) return;

    /* Value is either a quoted string or a bare literal */
    std::string newRaw;
    if (raw[vs] == '"') {
        /* quoted string — find the closing quote (handle \" escapes) */
        size_t ve = vs + 1;
        while (ve < raw.size()) {
            if (raw[ve] == '\\') { ve += 2; continue; }
            if (raw[ve] == '"') { ve++; break; }
            ve++;
        }
        /* escape newValue */
        std::string escaped;
        for (size_t i = 0; i < newValue.size(); i++) {
            if (newValue[i]=='"'||newValue[i]=='\\') escaped += '\\';
            escaped += newValue[i];
        }
        newRaw = raw.substr(0, kp) + kpat + "\"" + escaped + "\"" + raw.substr(ve);
    } else {
        /* bare literal (number / true / false / null) */
        size_t ve = vs;
        while (ve < raw.size() && raw[ve]!=',' && raw[ve]!='}') ve++;
        newRaw = raw.substr(0, kp) + kpat + newValue + raw.substr(ve);
    }

    WriteFile_(path, newRaw);
    Log("UpdateUniverseField: universe %s field '%s' -> '%s'",
        universeId.c_str(), key.c_str(), newValue.c_str());
}

/* Load universe JSON for the given ID.
 * Returns true and fills 'out' if the JSON file exists for this universe ID.
 * The place asset file is NOT required — universes are visible immediately
 * after creation, before the first upload. */
static bool LoadUniverseJson(const std::string& universeId, std::string& out)
{
    std::string raw = ReadFile(UniversesDir() + universeId + ".json");
    if (raw.empty()) return false;
    out = raw;
    return true;
}

/* Build a JSON array of all saved universes whose place assets exist. */
static std::string AllUniversesJson()
{
    std::string dir = UniversesDir();
    WIN32_FIND_DATAA fd;
    HANDLE hf = FindFirstFileA((dir + "*.json").c_str(), &fd);
    std::string arr = "[";
    bool first = true;
    if (hf != INVALID_HANDLE_VALUE) {
        do {
            if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
            std::string fname = fd.cFileName;
            if (fname.size() < 6) continue;
            std::string uid = fname.substr(0, fname.size() - 5);
            std::string raw = ReadFile(dir + fname);
            if (raw.empty()) continue;
            std::string rpid = CfgStr(raw, "rootPlaceId");
            if (rpid.empty()) rpid = uid;
            if (!PlaceAssetExists(rpid)) continue;
            if (!first) arr += ",";
            arr += raw;
            first = false;
        } while (FindNextFileA(hf, &fd));
        FindClose(hf);
    }
    arr += "]";
    return arr;
}

/* ============================================================================
   SECTION 5 — DataStore (file-based JSON, relative to DLL)
   ========================================================================= */
static std::string DsDir(const std::string& uid,
                          const std::string& scope,
                          const std::string& ds)
{
    std::string d=DllPath("data\\datastores\\");
    d+=uid+"\\";            EnsureDir(d);
    d+=UrlEncode(scope)+"\\"; EnsureDir(d);
    d+=UrlEncode(ds)+"\\";   EnsureDir(d);
    return d;
}

static std::string DsFile(const std::string& dir, const std::string& key)
{
    return dir+UrlEncode(key)+".json";
}

struct DsRec { std::string value; int version; std::string createdAt; };

static bool DsRead(const std::string& file, DsRec& out)
{
    std::string raw=ReadFile(file);
    if(raw.empty()) return false;
    out.version =atoi(CfgStr(raw,"version").c_str());
    out.createdAt=CfgStr(raw,"createdAt");
    /* extract value robustly — find "value": and grab until next top-level comma/} */
    size_t vp=raw.find("\"value\":");
    if(vp==std::string::npos){out.value="null";return true;}
    vp+=8;
    while(vp<raw.size()&&(raw[vp]==' '||raw[vp]=='\t')) vp++;
    size_t start=vp; int depth=0; bool inStr=false;
    for(size_t i=vp;i<raw.size();i++){
        char c=raw[i];
        if(inStr){if(c=='"'&&(i==0||raw[i-1]!='\\'))inStr=false;}
        else if(c=='"') inStr=true;
        else if(c=='{'||c=='['||c=='(') depth++;
        else if(c=='}'||c==']'||c==')'){if(depth==0){out.value=raw.substr(start,i-start);return true;}depth--;}
        else if(c==','&&depth==0){out.value=raw.substr(start,i-start);return true;}
    }
    out.value=raw.substr(start);
    return true;
}

static void DsWrite(const std::string& file, const std::string& value,
                    int ver, const std::string& createdAt)
{
    SYSTEMTIME st; GetLocalTime(&st);
    char ts[64];
    sprintf(ts,"%04d-%02d-%02dT%02d:%02d:%02dZ",
        st.wYear,st.wMonth,st.wDay,st.wHour,st.wMinute,st.wSecond);
    std::string j="{\"value\":"+value;
    char vb[32]; sprintf(vb,"%d",ver);
    j+=",\"version\":"; j+=vb;
    j+=",\"createdAt\":\""; j+=(createdAt.empty()?std::string(ts):createdAt);
    j+="\",\"updatedAt\":\""; j+=ts; j+="\"}";
    WriteFile_(file,j);
}

/* ============================================================================
   SECTION 6 — HTTP request / response structs
   ========================================================================= */
struct Req {
    std::string method, path, query, version, body;
    std::map<std::string,std::string> headers;
    std::map<std::string,std::string> qs;
};

struct Resp {
    int status;
    std::string statusText, contentType, body;
    std::map<std::string,std::string> hdrs;
};

static void ParseQS(const std::string& raw, std::map<std::string,std::string>& out)
{
    std::string k,v; bool inV=false;
    for(size_t i=0;i<=raw.size();i++){
        char c=(i<raw.size())?raw[i]:'&';
        if(c=='=') inV=true;
        else if(c=='&'){if(!k.empty())out[UrlDecode(k)]=UrlDecode(v);k.clear();v.clear();inV=false;}
        else{if(inV)v+=c;else k+=c;}
    }
}

static bool ParseHttp(const std::string& raw, Req& r)
{
    size_t le=raw.find("\r\n");
    if(le==std::string::npos) return false;
    std::string line=raw.substr(0,le); size_t pos=le+2;
    size_t s1=line.find(' '); if(s1==std::string::npos) return false;
    r.method=line.substr(0,s1);
    size_t s2=line.find(' ',s1+1); if(s2==std::string::npos) return false;
    std::string fp=line.substr(s1+1,s2-s1-1);
    r.version=line.substr(s2+1);
    size_t qp=fp.find('?');
    if(qp!=std::string::npos){r.path=fp.substr(0,qp);r.query=fp.substr(qp+1);}
    else r.path=fp;
    ParseQS(r.query, r.qs);
    while(pos<raw.size()){
        size_t le2=raw.find("\r\n",pos);
        if(le2==std::string::npos) break;
        if(le2==pos){pos+=2;break;}
        std::string hl=raw.substr(pos,le2-pos); pos=le2+2;
        size_t co=hl.find(':');
        if(co!=std::string::npos){
            std::string hk=ToLower(hl.substr(0,co));
            size_t vs=co+1; while(vs<hl.size()&&hl[vs]==' ')vs++;
            r.headers[hk]=hl.substr(vs);
        }
    }
    if(pos<raw.size()) r.body=raw.substr(pos);

    /* Studio gzip-compresses request bodies once they exceed a size threshold
     * (Content-Encoding: gzip).  If we don't decompress here, every handler
     * sees raw gzip bytes instead of the real payload — which is why large
     * SetAsync/UpdateAsync values were getting stored as binary garbage, and
     * why the gzipped check-permissions body looked empty.  Decompress once,
     * up front, so ALL downstream handlers get the true body.  Fall back to the
     * original bytes if it isn't actually valid gzip. */
    if(!r.body.empty() && r.headers.count("content-encoding")){
        const std::string& enc = r.headers["content-encoding"];
        if(enc.find("gzip")!=std::string::npos){
            std::string dec = GzipDecompress(r.body);
            if(!dec.empty()){
                r.body.swap(dec);
                r.headers.erase("content-encoding");   /* body is now plain */
            }
        }
    }

    if(r.method=="POST"&&r.headers.count("content-type")){
        std::string ct=r.headers["content-type"];
        if(ct.find("application/x-www-form-urlencoded")!=std::string::npos)
            ParseQS(r.body, r.qs);
    }
    return true;
}

static std::string QS(const Req& r, const char* k, const char* def="")
{
    std::map<std::string,std::string>::const_iterator it=r.qs.find(k);
    return it!=r.qs.end()?it->second:def;
}

static std::string BuildRaw(const Resp& r)
{
    std::string o;
    char buf[32]; sprintf(buf,"HTTP/1.1 %d ",r.status);
    o+=buf; o+=r.statusText.empty()?"OK":r.statusText; o+="\r\n";
    o+="Content-Type: "; o+=r.contentType; o+="\r\n";
    o+="Access-Control-Allow-Origin: *\r\n";
    o+="Access-Control-Allow-Methods: GET,POST,PUT,PATCH,DELETE,OPTIONS\r\n";
    o+="Access-Control-Allow-Headers: Authorization,Content-Type,"
       "Roblox-Place-Id,Roblox-Universe-Id,content-md5,x-api-key,"
       "Roblox-Object-Attributes,Roblox-Object-Userids\r\n";
    o+="Access-Control-Expose-Headers: Content-MD5,Roblox-Object-Version-Id,"
       "Roblox-Object-Created-Time,Roblox-Object-Version-Created-Time,"
       "Roblox-Object-Attributes,Roblox-Object-Userids,Roblox-Usn,ETag,Deleted\r\n";
    o+="Connection: close\r\n";
    for(auto it=r.hdrs.begin();it!=r.hdrs.end();++it)
        { o+=it->first; o+=": "; o+=it->second; o+="\r\n"; }
    char cl[24]; sprintf(cl,"%d",(int)r.body.size());
    o+="Content-Length: "; o+=cl; o+="\r\n\r\n";
    o+=r.body;
    return o;
}

static Resp RJson(const std::string& j, int st=200)
{
    Resp r; r.status=st;
    r.statusText=(st==200?"OK":st==204?"No Content":st==404?"Not Found":"Error");
    r.contentType="application/json; charset=utf-8"; r.body=j; return r;
}
static Resp RText(const std::string& t, int st=200)
{
    Resp r; r.status=st; r.statusText="OK";
    r.contentType="text/plain; charset=utf-8"; r.body=t; return r;
}
static Resp RHtml(const std::string& h)
{
    Resp r; r.status=200; r.statusText="OK";
    r.contentType="text/html; charset=utf-8"; r.body=h; return r;
}

/* ============================================================================
   SECTION 7 — RSA-SHA1 join-script signing via CryptoAPI (XP+)
   ========================================================================= */
static void LoadSignKey()
{
    std::string pem=ReadFile(DllPath("www\\game\\Join.ashx\\PrivateKey.pem"));
    if(pem.empty()) return;

    /* strip PEM headers — handle both PKCS#1 and PKCS#8 */
    static const char* H[]={"-----BEGIN RSA PRIVATE KEY-----","-----BEGIN PRIVATE KEY-----",0};
    static const char* F[]={"-----END RSA PRIVATE KEY-----","-----END PRIVATE KEY-----",0};
    std::string b64; bool pkcs8=false;
    for(int i=0;H[i];i++){
        size_t hs=pem.find(H[i]); if(hs==std::string::npos) continue;
        hs+=strlen(H[i]);
        size_t fe=pem.find(F[i],hs); if(fe==std::string::npos) continue;
        std::string raw=pem.substr(hs,fe-hs);
        std::string clean;
        for(size_t j=0;j<raw.size();j++) if(!isspace((unsigned char)raw[j])) clean+=raw[j];
        b64=clean; pkcs8=(i==1); break;
    }
    if(b64.empty()) return;

    std::vector<unsigned char> der=Base64Decode(b64);
    if(der.empty()) return;

    BYTE* pbBlob=NULL; DWORD cbBlob=0;
    if(pkcs8){
        /* Unwrap PKCS#8 envelope first */
        CRYPT_PRIVATE_KEY_INFO* pki=NULL; DWORD cbPki=0;
        if(!CryptDecodeObjectEx(X509_ASN_ENCODING, PKCS_PRIVATE_KEY_INFO,
                &der[0],(DWORD)der.size(),CRYPT_DECODE_ALLOC_FLAG,NULL,&pki,&cbPki)) return;
        CryptDecodeObjectEx(X509_ASN_ENCODING, PKCS_RSA_PRIVATE_KEY,
                pki->PrivateKey.pbData,pki->PrivateKey.cbData,
                CRYPT_DECODE_ALLOC_FLAG,NULL,&pbBlob,&cbBlob);
        LocalFree(pki);
    } else {
        CryptDecodeObjectEx(X509_ASN_ENCODING, PKCS_RSA_PRIVATE_KEY,
                &der[0],(DWORD)der.size(),CRYPT_DECODE_ALLOC_FLAG,NULL,&pbBlob,&cbBlob);
    }
    if(!pbBlob) return;

    if(!CryptAcquireContextA(&g_hSignProv,NULL,NULL,PROV_RSA_FULL,CRYPT_VERIFYCONTEXT))
        { LocalFree(pbBlob); return; }
    if(!CryptImportKey(g_hSignProv,pbBlob,cbBlob,0,0,&g_hSignKey))
        { LocalFree(pbBlob); CryptReleaseContext(g_hSignProv,0); return; }
    LocalFree(pbBlob);
    g_signKeyLoaded=TRUE;
}

static const char STUB_SIG[]=
    "--rbxsig%AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=% ";

static std::string SignScript(const std::string& script)
{
    if(!g_signKeyLoaded) return STUB_SIG+script;
    HCRYPTHASH hHash=NULL;
    if(!CryptCreateHash(g_hSignProv,CALG_SHA1,0,0,&hHash)) return STUB_SIG+script;
    CryptHashData(hHash,(const BYTE*)script.c_str(),(DWORD)script.size(),0);
    DWORD cbSig=0; CryptSignHash(hHash,AT_KEYEXCHANGE,NULL,0,NULL,&cbSig);
    std::vector<BYTE> sig(cbSig);
    if(!CryptSignHash(hHash,AT_KEYEXCHANGE,NULL,0,&sig[0],&cbSig))
        { CryptDestroyHash(hHash); return STUB_SIG+script; }
    CryptDestroyHash(hHash);
    std::reverse(sig.begin(),sig.end()); /* CryptoAPI = little-endian */
    return "--rbxsig%"+Base64Encode(&sig[0],sig.size())+"% "+script;
}

/* ============================================================================
   SECTION 8 — Static file serving from www\ (relative to DLL)
   ========================================================================= */
static const char* Mime(const char* ext)
{
    if(!ext) return "application/octet-stream";
    if(!lstrcmpiA(ext,".html")||!lstrcmpiA(ext,".htm")) return "text/html";
    if(!lstrcmpiA(ext,".css"))  return "text/css";
    if(!lstrcmpiA(ext,".js"))   return "application/javascript";
    if(!lstrcmpiA(ext,".json")) return "application/json";
    if(!lstrcmpiA(ext,".png"))  return "image/png";
    if(!lstrcmpiA(ext,".jpg")||!lstrcmpiA(ext,".jpeg")) return "image/jpeg";
    if(!lstrcmpiA(ext,".gif"))  return "image/gif";
    if(!lstrcmpiA(ext,".ico"))  return "image/x-icon";
    if(!lstrcmpiA(ext,".svg"))  return "image/svg+xml";
    if(!lstrcmpiA(ext,".txt")||!lstrcmpiA(ext,".pem")||!lstrcmpiA(ext,".lua"))
        return "text/plain";
    if(!lstrcmpiA(ext,".xml")) return "text/xml";
    return "application/octet-stream";
}

static bool ServeStatic(const std::string& urlPath, Resp& resp)
{
    std::string rel=urlPath;
    if(!rel.empty()&&rel[0]=='/') rel=rel.substr(1);
    for(size_t i=0;i<rel.size();i++) if(rel[i]=='/') rel[i]='\\';
    std::string fp=DllPath("www\\")+rel;
    /* never serve php files */
    if(fp.size()>=4 && ToLower(fp.substr(fp.size()-4))==".php") return false;
    DWORD attr=GetFileAttributesA(fp.c_str());
    if(attr==INVALID_FILE_ATTRIBUTES||attr&FILE_ATTRIBUTE_DIRECTORY) return false;
    std::string data=ReadFile(fp);
    const char* ext=PathFindExtensionA(fp.c_str());
    resp=RText(data);
    resp.contentType=Mime(ext);
    return true;
}

/* ============================================================================
   SECTION 9 — Feature flags (hardcoded blob)
   ========================================================================= */
static const char FFLAGS[]=
    "{\"FFlagCoreScriptShowVisibleAgeV2\":\"True\","
    "\"FFlagCoreScriptShowVisibleAge\":\"True\","
    "\"DFFlagFindFirstChildOfClassEnabled\":\"True\","
    "\"FFlagStudioCSGAssets\":\"True\",\"FFlagCSGLoadBlocking\":\"False\","
    "\"FFlagUsePGSSolver\":\"True\",\"FFlagNewInGameDevConsole\":\"True\","
    "\"FFlagTextFieldUTF8\":\"True\",\"FFlagLuaBasedBubbleChat\":\"True\","
    "\"FFlagConsoleCodeExecutionEnabled\":\"True\","
    "\"DFFlagCustomEmitterInstanceEnabled\":\"True\","
    "\"FFlagGlowEnabled\":\"True\",\"DFFlagUseNewFullscreenLogic\":\"True\","
    "\"FFlagRenderMaterialsOnMobile\":\"True\","
    "\"FFlagMaterialPropertiesEnabled\":\"True\","
    "\"FFlagSurfaceLightEnabled\":\"True\","
    "\"FFlagStudioPropertyErrorOutput\":\"True\","
    "\"DFFlagUseR15Character\":\"True\",\"DFFlagEnableHipHeight\":\"True\","
    "\"DFFlagUseStarterPlayerCharacter\":\"True\","
    "\"DFFlagFilteringEnabledDialogFix\":\"True\","
    "\"FFlagDebugDisableTelemetryV2\":\"True\","
    "\"FFlagClientABTestingEnabled\":\"False\","
    "\"FFlagStudioSmoothTerrainForNewPlaces\":\"True\","
    "\"FFlagFormFactorDeprecated\":\"False\","
    "\"FFlagStudioHandleErrors\":\"True\","
    "\"FFlagEnableRomarkStudioOperations\":\"True\","
    "\"FFlagStudioUseSrcAssets\":\"True\","
    "\"FFlagStudioUseSrcAssetsForPlugins\":\"True\","
    /* ----------------------------------------------------------------------
     * CRITICAL for DataStore GetAsync on this build.
     * The engine only reads the "Roblox-Object-Version-Id" response header
     * (and thus can format a v2 GetAsync result) when this flag is ON.
     * With it OFF — the default in this old client — the metadata extractor
     * skips the version header, the result can't be versioned, and Studio
     * reports: 504: response not formatted correctly.
     * Flag name is registered bare as "DataStore2NewVersionHeader"; serve it
     * under both the F and DF prefixes so whichever registry the client
     * routes to picks it up.  Restart Studio after changing this. */
    "\"DFFlagDataStore2NewVersionHeader\":\"True\","
    "\"FFlagDataStore2NewVersionHeader\":\"True\","
    /* Make the avatar parser read bodyColor3s (hex) instead of the legacy
     * bodyColors/headColorId (BrickColor IDs). With this OFF (the default) the
     * client ignores our hex colors entirely and the body comes in black.
     * Registered bare as "ClientAvatarUsesColor3sForBodyParts2"; serve both
     * prefixes. */
    "\"FFlagClientAvatarUsesColor3sForBodyParts2\":\"True\","
    "\"DFFlagClientAvatarUsesColor3sForBodyParts2\":\"True\"}";

/* ============================================================================
   SECTION 10 — Route handlers
   ========================================================================= */
#define STARTS(path, pfx) (path.compare(0, strlen(pfx), pfx) == 0)

/* ============================================================================
   HandleLuaDatastore — PHP-style endpoints used by the LocalDataStore Lua module
   ============================================================================
   getds.php    ?key={DS}_{KEY}              GET  → raw stored value (or "")
   setds.php    ?key={DS}_{KEY}              POST body = data → ""
   getorderedds.php ?dsname={DS}            GET  → JSON {key:number, ...}
   setorderedds.php ?dsname={DS}&key={KEY}  POST body = data → ""
   ============================================================================ */
static Resp HandleLuaDatastore(const Req& req)
{
    const std::string& P = req.path;
    std::string dir = DllPath("data\\localds\\");
    EnsureDir(dir);

    /* ------------------------------------------------------------------ */
    /* getds.php?key={DatastoreName}_{DataKey}                            */
    /* ------------------------------------------------------------------ */
    if (P.find("getds.php") != std::string::npos) {
        std::string key = QS(req, "key");
        if (key.empty()) return RText("");
        std::string val = ReadFile(dir + UrlEncode(key) + ".dat");
        return RText(val);                          /* empty string = nil in Lua */
    }

    /* ------------------------------------------------------------------ */
    /* setds.php?key={DatastoreName}_{DataKey}  (POST body = data)       */
    /* ------------------------------------------------------------------ */
    if (P.find("setds.php") != std::string::npos) {
        std::string key = QS(req, "key");
        if (key.empty()) return RText("");
        WriteFile_(dir + UrlEncode(key) + ".dat", req.body);
        Log("LocalDS set key=%s (%zu bytes)", key.c_str(), req.body.size());
        return RText("");
    }

    /* ------------------------------------------------------------------ */
    /* getorderedds.php?dsname={DatastoreName}                            */
    /* Returns {"DataKey":number,...} — Lua filters for numeric values.   */
    /* ------------------------------------------------------------------ */
    if (P.find("getorderedds.php") != std::string::npos) {
        std::string dsname = QS(req, "dsname");
        if (dsname.empty()) return RText("{}");

        /* All ordered-DS files are stored as {dsname}_{datakey}.dat.
         * We search with a wildcard; dsname is expected to be alphanumeric
         * (no %-encoding needed for the glob pattern). */
        std::string pattern = dir + UrlEncode(dsname) + "_*.dat";
        WIN32_FIND_DATAA fd;
        HANDLE hf = FindFirstFileA(pattern.c_str(), &fd);

        std::string json = "{";
        bool first = true;
        if (hf != INVALID_HANDLE_VALUE) {
            std::string encodedPrefix = UrlEncode(dsname) + "_";
            do {
                if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
                std::string fname = fd.cFileName;
                /* strip .dat extension */
                if (fname.size() < 5) continue;
                std::string noExt = fname.substr(0, fname.size() - 4);
                /* strip dsname_ prefix to get encoded DataKey */
                if (noExt.compare(0, encodedPrefix.size(), encodedPrefix) != 0) continue;
                std::string encKey = noExt.substr(encodedPrefix.size());
                std::string dataKey = UrlDecode(encKey);

                /* read stored value — ordered DS stores plain numeric strings */
                std::string val = ReadFile(dir + fname);
                if (val.empty()) continue;

                /* Attempt to parse as number; skip non-numeric entries */
                char* endp = NULL;
                double num = strtod(val.c_str(), &endp);
                if (!endp || endp == val.c_str()) continue; /* not a number */

                if (!first) json += ",";
                char nb[64]; sprintf(nb, "%.10g", num);
                json += "\"" + dataKey + "\":" + nb;
                first = false;
            } while (FindNextFileA(hf, &fd));
            FindClose(hf);
        }
        json += "}";
        return RText(json);
    }

    /* ------------------------------------------------------------------ */
    /* setorderedds.php?dsname={DS}&key={DataKey}  (POST body = data)    */
    /* ------------------------------------------------------------------ */
    if (P.find("setorderedds.php") != std::string::npos) {
        std::string dsname = QS(req, "dsname");
        std::string key    = QS(req, "key");
        if (dsname.empty() || key.empty()) return RText("");
        std::string combined = UrlEncode(dsname) + "_" + UrlEncode(key);
        WriteFile_(dir + combined + ".dat", req.body);
        Log("LocalDS ordered set dsname=%s key=%s", dsname.c_str(), key.c_str());
        return RText("");
    }

    return RText("");
}

static Resp HandleDatastore(const Req& req)
{
    std::string action=QS(req,"action");
    const std::string uid="1";
    char buf[512];

    if(action=="set"){
        std::string k=QS(req,"key"),nm=QS(req,"name");
        if(k.empty()||nm.empty()) return RJson("{\"errors\":[{\"code\":\"MissingParam\",\"message\":\"key and name required\"}]}",400);
        std::string scope=QS(req,"scope","global");
        std::string value=QS(req,"value","null");
        if(!req.body.empty()&&req.body[0]=='{') value=req.body;
        std::string dir=DsDir(uid,scope,nm), file=DsFile(dir,k);
        DsRec old; int ver=DsRead(file,old)?old.version+1:1;
        DsWrite(file,value,ver,old.createdAt);
        sprintf(buf,"{\"data\":{\"Value\":%s},\"version\":%d}",value.c_str(),ver);
        return RJson(buf);
    }
    if(action=="get"){
        std::string k=QS(req,"key"),nm=QS(req,"name");
        if(k.empty()||nm.empty()) return RJson("{\"data\":null}");
        std::string file=DsFile(DsDir(uid,QS(req,"scope","global"),nm),k);
        DsRec rec; if(!DsRead(file,rec)) return RJson("{\"data\":null}");
        sprintf(buf,"{\"data\":{\"Value\":%s},\"version\":%d}",rec.value.c_str(),rec.version);
        return RJson(buf);
    }
    if(action=="remove"){
        std::string k=QS(req,"key"),nm=QS(req,"name");
        DeleteFileA(DsFile(DsDir(uid,QS(req,"scope","global"),nm),k).c_str());
        return RJson("{\"data\":null}");
    }
    if(action=="increment"){
        std::string k=QS(req,"key"),nm=QS(req,"name");
        if(k.empty()||nm.empty()) return RJson("{\"data\":null}",400);
        std::string scope=QS(req,"scope","global");
        double delta=atof(QS(req,"value","1").c_str());
        std::string dir=DsDir(uid,scope,nm),file=DsFile(dir,k);
        DsRec old; double prev=0; int ver=1;
        if(DsRead(file,old)){prev=atof(old.value.c_str());ver=old.version+1;}
        double nv=prev+delta;
        char vb[64]; sprintf(vb,"%.10g",nv);
        DsWrite(file,vb,ver,old.createdAt);
        sprintf(buf,"{\"data\":{\"Value\":%.10g},\"version\":%d}",nv,ver);
        return RJson(buf);
    }
    return RJson("{\"errors\":[{\"code\":\"BadAction\",\"message\":\"Unknown action\"}]}",400);
}

static std::string BuildJoinScript(const std::string& user, const std::string& ip,
                                   const std::string& port, const std::string& id,
                                   const std::string& app)
{
    /* try template file first */
    std::string tpl=ReadFile(DllPath("www\\game\\Join.ashx\\joinguest.txt"));
    if(!tpl.empty()){
        auto repl=[](std::string& s,const std::string& f,const std::string& t){
            size_t p=0;
            while((p=s.find(f,p))!=std::string::npos){s.replace(p,f.size(),t);p+=t.size();}
        };
        repl(tpl,"%user%",user);repl(tpl,"%ip%",ip);
        repl(tpl,"%port%",port);repl(tpl,"%id%",id);repl(tpl,"%app%",app);
        return tpl;
    }
    std::string s;
    s+="nc=game:GetService(\"NetworkClient\")\n";
    s+="nc:PlayerConnect("+id+",\""+ip+"\","+port+",10)\n";
    s+="game:SetMessage(\"Connecting to server...\")\n";
    s+="plr=game.Players.LocalPlayer\n";
    s+="plr.Name=\""+user+"\"\n";
    s+="plr.CharacterAppearance=\""+app+"\"\n";
    s+="pcall(function() plr:SetMembershipType(Enum.MembershipType.TurboBuildersClub) end)\n";
    s+="pcall(function() plr:SetAccountAge(365) end)\n";
    s+="game:GetService(\"Visit\"):SetUploadUrl(\"\")\n";
    s+="game.Players:SetChatStyle(\"ClassicAndBubble\")\n";
    s+="nc.ConnectionAccepted:connect(function(peer,repl)\n";
    s+="  local mkr=repl:SendMarker()\n";
    s+="  mkr.Received:connect(function()\n";
    s+="    repl:RequestCharacter()\n";
    s+="    game:ClearMessage()\n";
    s+="  end)\n";
    s+="  repl.Disconnection:connect(function() game:SetMessage(\"Game shut down\") end)\n";
    s+="end)\n";
    s+="nc.ConnectionFailed:connect(function() game:SetMessage(\"Failed to connect\") end)\n";
    return s;
}

static Resp HandleJoin(const Req& req)
{
    std::string user=QS(req,"user","player"),ip=QS(req,"ip","127.0.0.1");
    std::string port=QS(req,"port","53640"),id=QS(req,"id","533");
    std::string app=QS(req,"app","http://localhost/v1.0/avatar-fetch?v1=true");
    return RText(SignScript(BuildJoinScript(user,ip,port,id,app)));
}

static Resp HandlePlaceLauncher(const Req& req)
{
    std::string ip=QS(req,"ip","127.0.0.1"),port=QS(req,"port","53640");
    std::string user=QS(req,"user"),id=QS(req,"id","533");
    std::string mem=QS(req,"membership","None"),app=QS(req,"app");
    std::string sd=DllPath("data\\SavedData\\"); EnsureDir(sd);
    if(!user.empty()){
        WriteFile_(sd+"user.ini",user);WriteFile_(sd+"id.ini",id);
        WriteFile_(sd+"membership.ini",mem);WriteFile_(sd+"app.ini",app);
        WriteFile_(sd+"ip.ini",ip);WriteFile_(sd+"port.ini",port);
    } else {
        user=ReadFile(sd+"user.ini");id=ReadFile(sd+"id.ini");
        ip=ReadFile(sd+"ip.ini");port=ReadFile(sd+"port.ini");
        mem=ReadFile(sd+"membership.ini");app=ReadFile(sd+"app.ini");
    }
    char buf[1024];
    sprintf(buf,
        "{\"jobId\":\"Test\",\"status\":2,"
        "\"joinScriptUrl\":\"http://localhost/game/Join.ashx?"
        "placeid=9991912465&ip=%s&port=%s&user=%s&id=%s&membership=%s&app=%s\","
        "\"authenticationUrl\":\"http://localhost/Login/Negotiate.ashx\","
        "\"authenticationTicket\":\"1\",\"message\":null}",
        ip.c_str(),port.c_str(),user.c_str(),id.c_str(),mem.c_str(),app.c_str());
    return RJson(buf);
}

static Resp HandleGlobal(const Req&)
{
    std::string s=
        "printidentity()\nwait(15)\n"
        "pcall(function() game:GetService(\"InsertService\"):SetFreeModelUrl("
          "\"http://localhost/Game/Tools/InsertAsset.ashx?type=fm&q=%s&pg=%d&rs=%d\") end)\n"
        "pcall(function() game:GetService(\"InsertService\"):SetFreeDecalUrl("
          "\"http://localhost/Game/Tools/InsertAsset.ashx?type=fd&q=%s&pg=%d&rs=%d\") end)\n"
        "game:GetService(\"ScriptInformationProvider\"):SetAssetUrl(\"http://localhost/asset/\")\n"
        "game:GetService(\"InsertService\"):SetBaseSetsUrl(\"http://localhost/Game/Tools/InsertAsset.ashx?nsets=10&type=base\")\n"
        "game:GetService(\"InsertService\"):SetUserSetsUrl(\"http://localhost/Game/Tools/InsertAsset.ashx?nsets=20&type=user&userid=%d\")\n"
        "game:GetService(\"InsertService\"):SetCollectionUrl(\"http://localhost/Game/Tools/InsertAsset.ashx?sid=%d\")\n"
        "game:GetService(\"InsertService\"):SetAssetUrl(\"http://localhost/asset/?id=%d\")\n"
        "game:GetService(\"InsertService\"):SetAssetVersionUrl(\"http://localhost/asset/?assetversionid=%d\")\n"
        "pcall(function() game:GetService(\"SocialService\"):SetFriendUrl("
          "\"http://localhost/Game/LuaWebService/HandleSocialRequest.ashx"
          "?method=IsFriendsWith&playerid=%d&userid=%d\") end)\n"
        "pcall(function() game:GetService(\"SocialService\"):SetBestFriendUrl("
          "\"http://localhost/Game/LuaWebService/HandleSocialRequest.ashx"
          "?method=IsBestFriendsWith&playerid=%d&userid=%d\") end)\n"
        "pcall(function() game:GetService(\"SocialService\"):SetGroupUrl("
          "\"http://localhost/Game/LuaWebService/HandleSocialRequest.ashx"
          "?method=IsInGroup&playerid=%d&groupid=%d\") end)\n"
        "pcall(function() game:GetService(\"SocialService\"):SetGroupRankUrl("
          "\"http://localhost/Game/LuaWebService/HandleSocialRequest.ashx"
          "?method=GetGroupRank&playerid=%d&groupid=%d\") end)\n"
        "local ScriptContext=game:GetService(\"ScriptContext\")\n";
    return RText(SignScript(s));
}

/* Signed Lua script Studio fetches on startup to configure all service URLs */
static Resp HandleStudioAshx(const Req&)
{
    std::string s =
        "printidentity()\n"
        "pcall(function() game:GetService(\"InsertService\"):SetFreeModelUrl("
          "\"http://localhost/Game/Tools/InsertAsset.ashx?type=fm&q=%s&pg=%d&rs=%d\") end)\n"
        "pcall(function() game:GetService(\"InsertService\"):SetFreeDecalUrl("
          "\"http://localhost/Game/Tools/InsertAsset.ashx?type=fd&q=%s&pg=%d&rs=%d\") end)\n"
        "game:GetService(\"ScriptInformationProvider\"):SetAssetUrl(\"http://localhost/asset/\")\n"
        "game:GetService(\"InsertService\"):SetBaseSetsUrl(\"http://localhost/Game/Tools/InsertAsset.ashx?nsets=10&type=base\")\n"
        "game:GetService(\"InsertService\"):SetUserSetsUrl(\"http://localhost/Game/Tools/InsertAsset.ashx?nsets=20&type=user&userid=%d\")\n"
        "game:GetService(\"InsertService\"):SetCollectionUrl(\"http://localhost/Game/Tools/InsertAsset.ashx?sid=%d\")\n"
        "game:GetService(\"InsertService\"):SetAssetUrl(\"http://localhost/asset/?id=%d\")\n"
        "game:GetService(\"InsertService\"):SetAssetVersionUrl(\"http://localhost/asset/?assetversionid=%d\")\n"
        "pcall(function() game:GetService(\"SocialService\"):SetFriendUrl("
          "\"http://localhost/Game/LuaWebService/HandleSocialRequest.ashx"
          "?method=IsFriendsWith&playerid=%d&userid=%d\") end)\n"
        "pcall(function() game:GetService(\"SocialService\"):SetBestFriendUrl("
          "\"http://localhost/Game/LuaWebService/HandleSocialRequest.ashx"
          "?method=IsBestFriendsWith&playerid=%d&userid=%d\") end)\n"
        "pcall(function() game:GetService(\"SocialService\"):SetGroupUrl("
          "\"http://localhost/Game/LuaWebService/HandleSocialRequest.ashx"
          "?method=IsInGroup&playerid=%d&groupid=%d\") end)\n"
        "pcall(function() game:GetService(\"SocialService\"):SetGroupRankUrl("
          "\"http://localhost/Game/LuaWebService/HandleSocialRequest.ashx"
          "?method=GetGroupRank&playerid=%d&groupid=%d\") end)\n"
        "pcall(function() game:GetService(\"SocialService\"):SetGroupRoleUrl("
          "\"http://localhost/Game/LuaWebService/HandleSocialRequest.ashx"
          "?method=GetGroupRole&playerid=%d&groupid=%d\") end)\n"
        "pcall(function() game:GetService(\"MarketplaceService\"):SetProductInfoUrl("
          "\"http://localhost/marketplace/productinfo?assetId=%d\") end)\n"
        "pcall(function() game:GetService(\"MarketplaceService\"):SetDevProductInfoUrl("
          "\"http://localhost/marketplace/productDetails?productId=%d\") end)\n"
        "pcall(function() game:GetService(\"MarketplaceService\"):SetPlayerOwnsAssetUrl("
          "\"http://localhost/ownership/hasasset?userId=%d&assetId=%d\") end)\n"
        "local result = pcall(function() game:GetService(\"ScriptContext\"):AddStarterScript(6001) end)\n"
        "if not result then\n"
        "  pcall(function() game:GetService(\"ScriptContext\"):AddCoreScript("
            "6001,game:GetService(\"ScriptContext\"),\"StarterScript\") end)\n"
        "end\n";
    return RText(SignScript(s));
}

/* OpenID Connect discovery document — returned for all metadata/discovery queries */
static const char* OPENID_DISCOVERY =
    "{\"issuer\":\"http://localhost/oauth/\","
    "\"authorization_endpoint\":\"http://localhost/oauth/v1/authorize\","
    "\"token_endpoint\":\"http://localhost/oauth/v1/token\","
    "\"introspection_endpoint\":\"http://localhost/oauth/v1/token/introspect\","
    "\"revocation_endpoint\":\"http://localhost/oauth/v1/token/revoke\","
    "\"resources_endpoint\":\"http://localhost/oauth/v1/token/resources\","
    "\"userinfo_endpoint\":\"http://localhost/oauth/v1/userinfo\","
    "\"jwks_uri\":\"http://localhost/oauth/v1/certs\","
    "\"registration_endpoint\":\"http://localhost/dashboard/credentials\","
    "\"service_documentation\":\"http://localhost/docs/reference/cloud\","
    "\"scopes_supported\":[\"openid\",\"profile\",\"email\","
      "\"verification\",\"credentials\",\"age\",\"premium\",\"roles\",\"attributes\"],"
    "\"response_types_supported\":[\"none\",\"code\"],"
    "\"subject_types_supported\":[\"public\"],"
    "\"id_token_signing_alg_values_supported\":[\"ES256\"],"
    "\"claims_supported\":[\"sub\",\"type\",\"iss\",\"aud\",\"exp\",\"iat\","
      "\"nonce\",\"name\",\"nickname\",\"preferred_username\","
      "\"created_at\",\"profile\",\"picture\",\"email\",\"email_verified\","
      "\"verified\",\"age_bracket\",\"premium\",\"roles\","
      "\"internal_user\",\"attributes\"],"
    "\"token_endpoint_auth_methods_supported\":[\"client_secret_post\",\"client_secret_basic\"]}";

static Resp HandleOAuth(const std::string& sub, const Req& req)
{
    time_t now=time(NULL);
    /* Discovery document — hit by AuthTokenManager on startup */
    if(sub.empty()||sub=="/"||
       STARTS(sub,"/.well-known")||
       STARTS(sub,"/v1/metadata")||
       STARTS(sub,"/metadata"))
        return RJson(OPENID_DISCOVERY);
    if(STARTS(sub,"/v1/authorize")){
        std::string redir=QS(req,"redirect_uri"),state=QS(req,"state");
        if(!redir.empty()){
            std::string loc=redir+(redir.find('?')!=std::string::npos?"&":"?");
            loc+="code=hardcoded_auth_code_2023";
            if(!state.empty()) loc+="&state="+UrlEncode(state);
            Resp r=RJson(""); r.status=302; r.statusText="Found";
            r.hdrs["Location"]=loc; r.body=""; return r;
        }
        return RJson("{\"code\":\"hardcoded_auth_code_2023\",\"state\":\"\"}");
    }
    if(STARTS(sub,"/v1/token/introspect")){
        char buf[512];
        sprintf(buf,"{\"active\":true,\"scope\":\"openid profile email\","
            "\"client_id\":\"roblox_studio_client\",\"token_type\":\"Bearer\","
            "\"exp\":%ld,\"iat\":%ld,\"sub\":\"%s\","
            "\"iss\":\"http://localhost/oauth/\"}",(long)now+3600,(long)now,
            g_userId.c_str());
        return RJson(buf);
    }
    if(STARTS(sub,"/v1/token/revoke"))    return RJson("{}");
    if(STARTS(sub,"/v1/token/resources")) return RJson("{\"resources\":[]}");
    if(STARTS(sub,"/v1/token")){
        std::string cid=QS(req,"client_id","roblox_studio_client");
        std::string jwt=MakeFakeJwt(g_userId,cid);
        return RJson("{\"access_token\":\"hardcoded_access_token\","
            "\"token_type\":\"Bearer\",\"expires_in\":1800,"
            "\"refresh_token\":\"hardcoded_refresh_token\","
            "\"scope\":\"openid credentials profile age roles premium\","
            "\"id_token\":\""+jwt+"\"}");
    }
    if(STARTS(sub,"/v1/userinfo")){
        char buf[1024];
        sprintf(buf,
            "{\"sub\":\"%s\",\"type\":\"User\","
            "\"iss\":\"http://localhost/oauth/\","
            "\"aud\":\"roblox_studio_client\","
            "\"exp\":%ld,\"iat\":%ld,\"nonce\":\"hardcoded_nonce\","
            "\"name\":\"%s\",\"nickname\":\"Dev\","
            "\"preferred_username\":\"%s\","
            "\"created_at\":1680000000,"
            "\"email\":\"dev@roblox.example\","
            "\"email_verified\":true,\"verified\":true,"
            "\"age_bracket\":\"18+\",\"premium\":true,"
            "\"roles\":[\"Developer\"],\"internal_user\":false,\"attributes\":{}}"
            ,g_userId.c_str(),(long)now+3600,(long)now,
            g_username.c_str(),g_username.c_str());
        return RJson(buf);
    }
    if(STARTS(sub,"/v1/certs"))
        return RJson("{\"keys\":[{\"kty\":\"EC\",\"crv\":\"P-256\","
            "\"use\":\"sig\",\"alg\":\"ES256\",\"kid\":\"hardcoded-key-1\","
            "\"x\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\","
            "\"y\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\"}]}");
    return RJson("{}");
}

static Resp HandlePersistence(const Req& req, const std::string& method)
{
    std::string scope=QS(req,"scope","u"),key=QS(req,"key");
    std::string dir=DllPath("data\\persistence\\"); EnsureDir(dir);
    std::string file=dir+UrlEncode(scope)+"_"+UrlEncode(key)+".json";
    if(method=="GET"){
        DsRec rec; if(!DsRead(file,rec)){Resp r=RText("");r.status=404;return r;}
        return RText(rec.value);
    }
    if(method=="POST"){ DsWrite(file,"\""+req.body+"\"",1,""); return RText(""); }
    return RJson("{\"errors\":[{\"code\":\"MethodNotAllowed\"}]}",405);
}

/* ============================================================================
   SECTION 11a — Asset delivery
   ========================================================================= */

/*
 * HandleAssetDelivery — serves /asset/, /v1/asset/, /v2/asset/ (and /Asset/)
 *
 * Priority:
 *   1. data\SavedData\{id}           — locally placed .rbxl / .rbxm etc.
 *   2. data\SavedData\{id}.rbxl      — with explicit extension
 *   3. 302 redirect to assetdelivery.roblox.com so Studio fetches from CDN
 *
 * Params (GET or POST):
 *   id             — numeric asset ID
 *   assetversionid — specific version (treated same as id for local lookup)
 *   hash           — CDN hash (redirect to rbxcdn if present)
 */
static Resp AssetRedirect(const std::string& url)
{
    Resp r; r.status=302; r.statusText="Found";
    r.hdrs["Location"]=url; r.contentType="text/plain"; r.body=""; return r;
}

/* ============================================================================
   Roblox login / cookie management
   ---------------------------------------------------------------------------
   The .ROBLOSECURITY cookie is stored DPAPI-encrypted in
   %USERPROFILE%\Documents\robloxcookie.dat. On first use we decrypt it and
   verify it against Roblox by fetching a known asset (Pal Hair, 63690008):
   a valid cookie yields HTTP 200, an invalid/expired one 403. If it's missing
   or invalid, a small login window pops up to paste a fresh cookie, which is
   re-validated and then saved encrypted.
   ========================================================================= */

/* MUST be an auth-gated endpoint: returns 200 only for a genuinely valid
 * .ROBLOSECURITY, 401 otherwise. A public asset URL (e.g. Pal Hair) is useless
 * here because it returns 200 for ANY cookie, valid or garbage. */
static const char* kCookieProbeUrl =
    "https://users.roblox.com/v1/users/authenticated";

static std::string CookieDatPath()  /* encrypted */
{
    char p[MAX_PATH] = {0};
    GetEnvironmentVariableA("USERPROFILE", p, sizeof(p));
    return p[0] ? std::string(p) + "\\Documents\\robloxcookie.dat" : "";
}
static std::string CookieTxtPath()  /* legacy plaintext (migrated on first valid use) */
{
    char p[MAX_PATH] = {0};
    GetEnvironmentVariableA("USERPROFILE", p, sizeof(p));
    return p[0] ? std::string(p) + "\\Documents\\robloxcookie.txt" : "";
}

static bool DpapiEncrypt(const std::string& plain, std::string& blob)
{
    DATA_BLOB in;  in.pbData = (BYTE*)plain.data(); in.cbData = (DWORD)plain.size();
    DATA_BLOB out; out.pbData = NULL; out.cbData = 0;
    if (!CryptProtectData(&in, L"OffBlox Roblox cookie", NULL, NULL, NULL, 0, &out))
        return false;
    blob.assign((const char*)out.pbData, out.cbData);
    LocalFree(out.pbData);
    return true;
}
static bool DpapiDecrypt(const std::string& blob, std::string& plain)
{
    if (blob.empty()) return false;
    DATA_BLOB in;  in.pbData = (BYTE*)blob.data(); in.cbData = (DWORD)blob.size();
    DATA_BLOB out; out.pbData = NULL; out.cbData = 0;
    if (!CryptUnprotectData(&in, NULL, NULL, NULL, NULL, 0, &out))
        return false;
    plain.assign((const char*)out.pbData, out.cbData);
    LocalFree(out.pbData);
    return true;
}

static void CookieTrim(std::string& s)
{
    while (!s.empty() && (s.back()=='\r'||s.back()=='\n'||s.back()==' '||s.back()=='\t'))
        s.pop_back();
    size_t b = s.find_first_not_of(" \t\r\n");
    if (b == std::string::npos) s.clear(); else if (b) s = s.substr(b);
}

/* Normalize whatever was pasted/stored into a proper Cookie header value:
 * ".ROBLOSECURITY=<token>". Accepts a bare token, ".ROBLOSECURITY=<token>", or a
 * full cookie jar that contains it. Without the ".ROBLOSECURITY=" NAME the header
 * is meaningless to Roblox and every authenticated request gets a 401. */
static std::string CookieNormalize(const std::string& in)
{
    std::string s = in; CookieTrim(s);
    if (s.empty()) return s;
    const char* key = ".ROBLOSECURITY=";
    std::string token;
    size_t p = s.find(key);
    if (p != std::string::npos) {                 /* pull the value out of a jar */
        size_t vs = p + (size_t)strlen(key);
        size_t ve = s.find(';', vs);
        token = (ve == std::string::npos) ? s.substr(vs) : s.substr(vs, ve - vs);
    } else {
        token = s;                                /* whole string is the raw token */
    }
    while (!token.empty() && (token.front()==' '||token.front()=='\t')) token.erase(token.begin());
    while (!token.empty() && (token.back()==' '||token.back()=='\t'||token.back()=='\r'||token.back()=='\n')) token.pop_back();
    if (token.empty()) return "";
    return std::string(".ROBLOSECURITY=") + token;
}

static std::string LoadStoredCookie()
{
    std::string plain;
    if (DpapiDecrypt(ReadFile(CookieDatPath()), plain)) return CookieNormalize(plain);
    return CookieNormalize(ReadFile(CookieTxtPath()));   /* plaintext fallback */
}
static void SaveCookieEncrypted(const std::string& cookie)
{
    std::string blob;
    if (DpapiEncrypt(cookie, blob)) WriteFile_(CookieDatPath(), blob);
}

/* Minimal WinHTTP GET that returns only the HTTP status (0 on transport error).
 * Used to validate a candidate cookie without disturbing FetchUrl's state. */
static DWORD CookieProbeStatus(const std::string& url, const std::string& cookie)
{
    BOOL isHttps = (url.compare(0, 8, "https://") == 0);
    size_t hs = url.find("://"); if (hs == std::string::npos) return 0; hs += 3;
    size_t ps = url.find('/', hs);
    std::string hostPort = (ps != std::string::npos) ? url.substr(hs, ps-hs) : url.substr(hs);
    std::string path     = (ps != std::string::npos) ? url.substr(ps) : "/";
    std::string host = hostPort; INTERNET_PORT port = (INTERNET_PORT)(isHttps?443:80);
    size_t cp = hostPort.rfind(':');
    if (cp != std::string::npos && cp > 0) { host = hostPort.substr(0,cp); port=(INTERNET_PORT)atoi(hostPort.substr(cp+1).c_str()); }
    std::wstring wHost(host.begin(), host.end()), wPath(path.begin(), path.end());

    HINTERNET hS = WinHttpOpen(L"OffBlox", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                               WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hS) return 0;
    DWORD status = 0;
    HINTERNET hC = WinHttpConnect(hS, wHost.c_str(), port, 0);
    if (hC) {
        HINTERNET hR = WinHttpOpenRequest(hC, L"GET", wPath.c_str(), NULL,
            WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, isHttps ? WINHTTP_FLAG_SECURE : 0);
        if (hR) {
            if (isHttps) { DWORD sf = SECURITY_FLAG_IGNORE_UNKNOWN_CA|SECURITY_FLAG_IGNORE_CERT_DATE_INVALID|
                                       SECURITY_FLAG_IGNORE_CERT_CN_INVALID|SECURITY_FLAG_IGNORE_REVOCATION;
                           WinHttpSetOption(hR, WINHTTP_OPTION_SECURITY_FLAGS, &sf, sizeof(sf)); }
            std::wstring hdrs = L"Accept: */*\r\n";
            if (!cookie.empty()) {
                int n = MultiByteToWideChar(CP_UTF8,0,cookie.c_str(),-1,NULL,0);
                std::vector<wchar_t> wc(n>0?n:1);
                if (n>0) MultiByteToWideChar(CP_UTF8,0,cookie.c_str(),-1,&wc[0],n);
                hdrs += L"Cookie: "; hdrs += &wc[0]; hdrs += L"\r\n";
            }
            WinHttpAddRequestHeaders(hR, hdrs.c_str(), (DWORD)hdrs.size(), WINHTTP_ADDREQ_FLAG_ADD);
            if (WinHttpSendRequest(hR, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0) &&
                WinHttpReceiveResponse(hR, NULL)) {
                DWORD sz = sizeof(status);
                WinHttpQueryHeaders(hR, WINHTTP_QUERY_STATUS_CODE|WINHTTP_QUERY_FLAG_NUMBER,
                                    WINHTTP_HEADER_NAME_BY_INDEX, &status, &sz, WINHTTP_NO_HEADER_INDEX);
            }
            WinHttpCloseHandle(hR);
        }
        WinHttpCloseHandle(hC);
    }
    WinHttpCloseHandle(hS);
    return status;
}
static bool CookieIsValid(const std::string& cookie)
{
    if (cookie.empty()) return false;
    DWORD st = CookieProbeStatus(kCookieProbeUrl, cookie);
    Log("Roblox cookie probe (users/authenticated): HTTP %lu -> %s", st, st == 200 ? "valid" : "invalid");
    return st == 200;
}

/* ---- Login popup (paste .ROBLOSECURITY) ---- */
static std::string g_cookieInput;
static HWND        g_cookieEdit = NULL;

static LRESULT CALLBACK CookieWndProc(HWND h, UINT m, WPARAM w, LPARAM l)
{
    if (m == WM_COMMAND) {
        if (LOWORD(w) == 1) {           /* Log In */
            int len = GetWindowTextLengthW(g_cookieEdit);
            std::wstring wb(len + 1, L'\0');
            GetWindowTextW(g_cookieEdit, &wb[0], len + 1); wb.resize(len);
            int u = WideCharToMultiByte(CP_UTF8, 0, wb.c_str(), -1, NULL, 0, NULL, NULL);
            std::string s(u > 1 ? u - 1 : 0, '\0');
            if (u > 1) WideCharToMultiByte(CP_UTF8, 0, wb.c_str(), -1, &s[0], u, NULL, NULL);
            g_cookieInput = CookieNormalize(s);
            DestroyWindow(h); return 0;
        }
        if (LOWORD(w) == 2) { g_cookieInput.clear(); DestroyWindow(h); return 0; }  /* Cancel */
    }
    if (m == WM_CLOSE)   { g_cookieInput.clear(); DestroyWindow(h); return 0; }
    if (m == WM_DESTROY) { PostQuitMessage(0); return 0; }
    return DefWindowProcW(h, m, w, l);
}

static std::string PromptForCookie(bool retry)
{
    g_cookieInput.clear();
    HINSTANCE hInst = GetModuleHandleW(NULL);
    const wchar_t* cls = L"OffBloxCookieLogin";
    static bool reg = false;
    if (!reg) {
        WNDCLASSW wc; ZeroMemory(&wc, sizeof(wc));
        wc.lpfnWndProc = CookieWndProc; wc.hInstance = hInst; wc.lpszClassName = cls;
        wc.hCursor = LoadCursorW(NULL, (LPCWSTR)IDC_ARROW);
        wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
        reg = RegisterClassW(&wc) != 0;
    }
    int W = 560, H = 340;
    int sx = (GetSystemMetrics(SM_CXSCREEN) - W) / 2;
    int sy = (GetSystemMetrics(SM_CYSCREEN) - H) / 2;
    HWND h = CreateWindowExW(WS_EX_TOPMOST, cls,
        retry ? L"OffBlox — Roblox login (that cookie was invalid)"
              : L"OffBlox — Roblox login",
        WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU, sx, sy, W, H, NULL, NULL, hInst, NULL);
    if (!h) return "";
    HFONT font = (HFONT)GetStockObject(DEFAULT_GUI_FONT);
    HWND lbl = CreateWindowExW(0, L"STATIC",
        L"Paste your Roblox .ROBLOSECURITY cookie, then click Log In.\r\n"
        L"It is validated against Roblox and saved encrypted (Windows DPAPI) on "
        L"THIS PC only — it is never uploaded anywhere.\r\n\r\n"
        L"Don't trust it with your main account? Log in with an ALT account's "
        L"cookie instead.\r\n\r\n"
        L"You can also click Skip — but assets (avatars, images, audio, etc.) "
        L"will not load and a lot of features will break.",
        WS_CHILD | WS_VISIBLE, 12, 10, 530, 110, h, NULL, hInst, NULL);
    g_cookieEdit = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
        WS_CHILD | WS_VISIBLE | WS_VSCROLL | ES_MULTILINE | ES_AUTOVSCROLL,
        12, 126, 530, 110, h, NULL, hInst, NULL);
    HWND okb = CreateWindowExW(0, L"BUTTON", L"Log In",
        WS_CHILD | WS_VISIBLE | BS_DEFPUSHBUTTON, 360, 248, 85, 30, h, (HMENU)1, hInst, NULL);
    HWND cnb = CreateWindowExW(0, L"BUTTON", L"Skip",
        WS_CHILD | WS_VISIBLE, 457, 248, 85, 30, h, (HMENU)2, hInst, NULL);
    SendMessageW(lbl,         WM_SETFONT, (WPARAM)font, TRUE);
    SendMessageW(g_cookieEdit, WM_SETFONT, (WPARAM)font, TRUE);
    SendMessageW(okb,         WM_SETFONT, (WPARAM)font, TRUE);
    SendMessageW(cnb,         WM_SETFONT, (WPARAM)font, TRUE);
    ShowWindow(h, SW_SHOW); SetForegroundWindow(h); SetFocus(g_cookieEdit);

    MSG msg;
    while (GetMessageW(&msg, NULL, 0, 0) > 0) {
        if (!IsDialogMessageW(h, &msg)) { TranslateMessage(&msg); DispatchMessageW(&msg); }
    }
    return g_cookieInput;
}

/* Returns a validated .ROBLOSECURITY cookie (prompting if needed). Run once. */
static std::string EnsureRobloxCookie()
{
    /* 1) ALWAYS test whatever is stored against Roblox on startup. */
    std::string cookie = LoadStoredCookie();
    if (!cookie.empty() && CookieIsValid(cookie)) {
        if (ReadFile(CookieDatPath()).empty()) SaveCookieEncrypted(cookie); /* migrate plaintext */
        Log("Roblox cookie: loaded & valid");
        return cookie;
    }
    Log(cookie.empty() ? "Roblox cookie: none stored -> showing login"
                       : "Roblox cookie: stored cookie INVALID -> showing login");

    /* 2) Prompt until we get one that validates, saves, and re-validates from
     *    the saved encrypted copy. Invalid input re-opens the popup. */
    for (int i = 0; i < 8; i++) {
        std::string entered = PromptForCookie(i > 0);
        if (entered.empty()) { Log("Roblox login skipped/cancelled by user"); break; }

        if (!CookieIsValid(entered)) {
            Log("Roblox cookie: entered cookie failed validation -> re-prompting");
            continue;
        }
        /* Save, then re-load the SAVED (DPAPI-encrypted) copy and validate THAT,
         * so we never keep a cookie that didn't round-trip through encryption. */
        SaveCookieEncrypted(entered);
        std::string roundtrip = LoadStoredCookie();
        if (!roundtrip.empty() && CookieIsValid(roundtrip)) {
            Log("Roblox cookie: login OK, saved encrypted & re-verified");
            return roundtrip;
        }
        Log("Roblox cookie: saved copy failed re-verification -> re-prompting");
    }
    return "";  /* no valid cookie (skipped or gave up) -> auth'd features off */
}
static const std::string& GetRobloxCookie()
{
    static std::string s = EnsureRobloxCookie();   /* validated once, thread-safe */
    return s;
}
/* Kick the one-time validate/login on a worker thread (so the listener keeps
 * running). Any asset fetch that races it blocks harmlessly on the same init. */
/* Signaled (manual-reset) once the cookie prompt has been completed or skipped.
 * Request handling blocks on this so Studio's launch waits for the user. */
static HANDLE g_cookieReadyEvent = NULL;
static DWORD WINAPI CookieWarmupThread(LPVOID)
{
    GetRobloxCookie();                                 // blocks on the login prompt if needed
    if (g_cookieReadyEvent) SetEvent(g_cookieReadyEvent);
    return 0;
}

/* Fetches a URL via WinHTTP (Win8.1+ auto-decompression for gzip/deflate).
 * - Reads %USERPROFILE%\Documents\robloxcookie.txt once and sends it as
 *   the Cookie header, matching the original PHP server behaviour exactly.
 * - WINHTTP_OPTION_DECOMPRESSION is set so gzip/deflate responses are
 *   transparently inflated before we see the bytes — no Cabinet API needed.
 * - SSL cert errors are suppressed so CDN HTTPS works without a valid cert.
 * - WinHTTP follows HTTP 301/302 redirects automatically by default.
 * Returns true and populates out on success, false on any error.
 */
static bool FetchUrlEx(const std::string& url, std::string& out, DWORD* statusOut)
{
    if (statusOut) *statusOut = 0;
    /* Cookie: decrypted + validated once on first use; if it's missing or
     * expired a login window pops up to paste a fresh one (see GetRobloxCookie). */
    const std::string& s_cookie = GetRobloxCookie();

    /* ---------- Parse URL manually (avoids WINHTTP_URL_COMPONENTS SDK issues) ----------
     * Handles: https://host[:port]/path?query  and  http://host[:port]/path?query */
    BOOL isHttps = (url.compare(0, 8, "https://") == 0);
    size_t schemeEnd = url.find("://");
    if (schemeEnd == std::string::npos) {
        Log("FetchUrl: malformed URL %s", url.c_str()); return false;
    }
    size_t hostStart = schemeEnd + 3;
    size_t pathStart = url.find('/', hostStart);
    std::string hostPort = (pathStart != std::string::npos)
                           ? url.substr(hostStart, pathStart - hostStart)
                           : url.substr(hostStart);
    std::string pathQuery = (pathStart != std::string::npos)
                            ? url.substr(pathStart) : "/";

    std::string host; INTERNET_PORT port;
    size_t colonPos = hostPort.rfind(':');
    if (colonPos != std::string::npos && colonPos > 0) {
        host = hostPort.substr(0, colonPos);
        port = (INTERNET_PORT)atoi(hostPort.substr(colonPos + 1).c_str());
    } else {
        host = hostPort;
        port = (INTERNET_PORT)(isHttps ? 443 : 80);
    }

    /* Convert host and path to wide strings for WinHTTP */
    int hlen = MultiByteToWideChar(CP_UTF8, 0, host.c_str(), -1, NULL, 0);
    int plen = MultiByteToWideChar(CP_UTF8, 0, pathQuery.c_str(), -1, NULL, 0);
    if (hlen <= 0 || plen <= 0) {
        Log("FetchUrl: wide-convert failed for %s", url.c_str()); return false;
    }
    std::vector<wchar_t> wHost(hlen), wPath(plen);
    MultiByteToWideChar(CP_UTF8, 0, host.c_str(),      -1, &wHost[0], hlen);
    MultiByteToWideChar(CP_UTF8, 0, pathQuery.c_str(), -1, &wPath[0], plen);

    /* ---------- Open WinHTTP session ---------- */
    HINTERNET hSession = WinHttpOpen(
        L"Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        L"AppleWebKit/537.36 (KHTML, like Gecko) "
        L"Chrome/135.0.0.0 Safari/537.36 OPR/120.0.0.0",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) {
        Log("FetchUrl: WinHttpOpen failed (err=%lu)", GetLastError());
        return false;
    }

    /* Auto-decompress gzip / deflate responses (Win 8.1+, option 118).
     * If the OS is older and doesn't know the option, SetOption returns FALSE
     * and we silently continue — responses may still arrive uncompressed
     * because we don't advertise Accept-Encoding. */
    DWORD decompFlags = WINHTTP_DECOMPRESSION_FLAG_ALL;
    WinHttpSetOption(hSession, WINHTTP_OPTION_DECOMPRESSION,
                     &decompFlags, sizeof(decompFlags));

    /* ---------- Connect ---------- */
    HINTERNET hConnect = WinHttpConnect(hSession, &wHost[0], port, 0);
    if (!hConnect) {
        Log("FetchUrl: WinHttpConnect failed (err=%lu)", GetLastError());
        WinHttpCloseHandle(hSession);
        return false;
    }

    /* ---------- Open request ---------- */
    DWORD reqFlags = isHttps ? WINHTTP_FLAG_SECURE : 0;
    HINTERNET hRequest = WinHttpOpenRequest(
        hConnect, L"GET", &wPath[0],
        NULL, WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES, reqFlags);
    if (!hRequest) {
        Log("FetchUrl: WinHttpOpenRequest failed (err=%lu)", GetLastError());
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return false;
    }

    /* Ignore SSL cert issues (self-signed CDN certs etc.) */
    if (isHttps) {
        DWORD secFlags = SECURITY_FLAG_IGNORE_UNKNOWN_CA      |
                         SECURITY_FLAG_IGNORE_CERT_DATE_INVALID |
                         SECURITY_FLAG_IGNORE_CERT_CN_INVALID   |
                         SECURITY_FLAG_IGNORE_REVOCATION;
        WinHttpSetOption(hRequest, WINHTTP_OPTION_SECURITY_FLAGS,
                         &secFlags, sizeof(secFlags));
    }

    /* ---------- Build and add request headers ---------- */
    std::wstring wHdrs = L"Accept: */*\r\n";
    if (!s_cookie.empty()) {
        /* Convert cookie string (narrow) to wide */
        int clen = MultiByteToWideChar(CP_UTF8, 0, s_cookie.c_str(), -1, NULL, 0);
        std::vector<wchar_t> wcookie(clen);
        MultiByteToWideChar(CP_UTF8, 0, s_cookie.c_str(), -1, &wcookie[0], clen);
        wHdrs += L"Cookie: ";
        wHdrs += &wcookie[0];
        wHdrs += L"\r\n";
    }
    WinHttpAddRequestHeaders(hRequest, wHdrs.c_str(), (DWORD)wHdrs.size(),
                             WINHTTP_ADDREQ_FLAG_ADD);

    /* ---------- Send request ---------- */
    if (!WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                            WINHTTP_NO_REQUEST_DATA, 0, 0, 0)) {
        Log("FetchUrl: WinHttpSendRequest failed (err=%lu)", GetLastError());
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return false;
    }

    /* ---------- Receive response ---------- */
    if (!WinHttpReceiveResponse(hRequest, NULL)) {
        Log("FetchUrl: WinHttpReceiveResponse failed (err=%lu)", GetLastError());
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return false;
    }

    /* Check HTTP status — non-200 is treated as failure */
    DWORD status = 0, statusSize = sizeof(status);
    WinHttpQueryHeaders(hRequest,
        WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
        WINHTTP_HEADER_NAME_BY_INDEX, &status, &statusSize,
        WINHTTP_NO_HEADER_INDEX);
    if (statusOut) *statusOut = status;
    if (status != 200) {
        Log("FetchUrl: HTTP %lu for %s", status, url.c_str());
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return false;
    }

    /* ---------- Read response body ---------- */
    out.clear();
    char buf[16384];
    DWORD read = 0;
    while (WinHttpReadData(hRequest, buf, sizeof(buf), &read) && read > 0)
        out.append(buf, read);

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);

    if (out.empty()) {
        Log("FetchUrl: empty response for %s", url.c_str());
        return false;
    }
    return true;
}

/* Convenience wrapper that ignores the HTTP status code. */
static bool FetchUrl(const std::string& url, std::string& out)
{
    return FetchUrlEx(url, out, NULL);
}

/* Rewrites any roblox.com asset URLs in content to point at localhost,
 * mirroring the PHP rewrite_asset_urls() function.
 * Handles the two CDN patterns:
 *   https?://(www.|assetdelivery.)?roblox.com/(v1/)?asset/?id=NNN...
 * Both are replaced with http://localhost/asset/?id=NNN
 *
 * Gzip-compressed content (magic bytes 1F 8B) is decompressed first using
 * Windows' cabinet decompressor so rewriting works on CDN-sourced assets too.
 */
static std::string RewriteAssetUrls(const std::string& in)
{
    /* ---- Gzip decompression via RtlDecompressBuffer (XPRESS/LZNT1 only on XP)
     * For true gzip we use the Cabinet API (fdi) — but that's heavy.
     * In practice SavedData files are already plain-text/binary; the gzip path
     * is only hit for live CDN content.  We attempt a simple inflate by skipping
     * the 10-byte gzip header and passing the deflate stream to the compressapi.
     * On systems where compressapi is unavailable we fall through and rewrite as-is.
     * ---- */
    std::string body = in;

    if (body.size() >= 10 &&
        (unsigned char)body[0] == 0x1f &&
        (unsigned char)body[1] == 0x8b)
    {
        /* Skip gzip header: 10 fixed bytes + optional extras */
        size_t hdrLen = 10;
        unsigned char flags = (unsigned char)body[2]; /* FLG byte */
        if (hdrLen < body.size()) {
            if (flags & 0x04) { /* FEXTRA */
                if (hdrLen + 2 <= body.size()) {
                    size_t xlen = (unsigned char)body[hdrLen] |
                                  ((unsigned char)body[hdrLen+1] << 8);
                    hdrLen += 2 + xlen;
                }
            }
            if (flags & 0x08) { /* FNAME - null-terminated */
                while (hdrLen < body.size() && body[hdrLen] != '\0') hdrLen++;
                hdrLen++;
            }
            if (flags & 0x10) { /* FCOMMENT - null-terminated */
                while (hdrLen < body.size() && body[hdrLen] != '\0') hdrLen++;
                hdrLen++;
            }
            if (flags & 0x02) hdrLen += 2; /* FHCRC */
        }

        /* Last 4 bytes of gzip stream = original size (little-endian) */
        DWORD origSize = 0;
        if (body.size() >= 4) {
            const unsigned char* tail =
                (const unsigned char*)body.c_str() + body.size() - 4;
            origSize = (DWORD)tail[0] | ((DWORD)tail[1]<<8) |
                       ((DWORD)tail[2]<<16) | ((DWORD)tail[3]<<24);
        }

        /* No zlib linked and Windows has no built-in raw-deflate API on XP.
         * SavedData files are never gzip-compressed in practice, so fall through
         * and rewrite as-is.  If you need live CDN gzip support, link zlib and
         * call inflate() here before the URL rewrite. */
    }

    /* ---- URL rewrite ----
     * Matches PHP pattern:
     *   http(s)://(www.|assetdelivery.)?roblox.com/(v1/)?asset/?id=NNN[&query...]
     * Replaced with: http://localhost/asset/?id=NNN
     */
    static const char* PREFIXES[] = {
        "https://assetdelivery.roblox.com/v1/asset/?id=",
        "https://assetdelivery.roblox.com/asset/?id=",
        "https://www.roblox.com/v1/asset/?id=",
        "https://www.roblox.com/asset/?id=",
        "http://assetdelivery.roblox.com/v1/asset/?id=",
        "http://assetdelivery.roblox.com/asset/?id=",
        "http://www.roblox.com/v1/asset/?id=",
        "http://www.roblox.com/asset/?id=",
        "https://roblox.com/v1/asset/?id=",
        "https://roblox.com/asset/?id=",
        "http://roblox.com/v1/asset/?id=",
        "http://roblox.com/asset/?id=",
        NULL
    };

    std::string out;
    out.reserve(body.size());
    size_t i = 0;
    const size_t n = body.size();
    const char*  s = body.c_str();

    while (i < n) {
        /* Only bother checking when we see 'h' (start of http) */
        bool matched = false;
        if (s[i] == 'h') {
            for (int p = 0; PREFIXES[p] && !matched; p++) {
                size_t plen = strlen(PREFIXES[p]);
                if (i + plen > n) continue;
                if (strncmp(s + i, PREFIXES[p], plen) != 0) continue;

                /* Matched a prefix — consume the numeric id that follows */
                size_t idStart = i + plen;
                size_t idEnd   = idStart;
                while (idEnd < n && isdigit((unsigned char)s[idEnd])) idEnd++;
                if (idEnd > idStart) {           /* at least one digit */
                    out += "http://localhost/asset/?id=";
                    out.append(s + idStart, idEnd - idStart);
                    i = idEnd;
                    /* Drop any remaining &key=val query params before a
                     * delimiter (space / quote / angle-bracket) */
                    while (i < n && s[i] == '&') {
                        size_t j = i;
                        while (j < n &&
                               s[j] != '"'  && s[j] != '\'' &&
                               s[j] != '<'  && s[j] != '>' &&
                               !isspace((unsigned char)s[j])) j++;
                        i = j;
                    }
                    matched = true;
                }
            }
        }
        if (!matched) out += s[i++];
    }
    return out;
}

/* ============================================================================
   SECTION 11b — Roblox mesh format downconverter (realtime, in-memory)
   ============================================================================
   Converts any mesh version served through this proxy to binary v4.01,
   which is what 2023 Studio (v0.578) expects.

   Version routing:
     version 1.x  / 2.00  (ASCII)         → pass-through (Studio reads natively)
     version 3.x  (binary, rare)           → 4.01
     version 4.00 (binary)                 → 4.01
     version 4.01 (binary)                 → pass-through (already target)
     version 4.1+ (extended header)        → 4.01 (strips extra header fields)
     version 5.00 (extended + LOD table)   → 4.01 (strips LODs)
     version 6.x  (extended + skin data)   → 4.01 (strips skin/LOD chunks)
     non-mesh data                         → pass-through unchanged

   Binary v4.01 layout:
     "version 4.01\n"          13 bytes
     MeshHeader (12 bytes):
       uint16  sizeof_MeshHeader = 12
       uint16  sizeof_Vertex     = 40
       uint32  sizeof_Face       = 12
     uint32  VertexCount
     uint32  FaceCount
     Vertices  (VertexCount * 40 bytes each):
       float32[3]  position (x,y,z)
       float32[3]  normal   (nx,ny,nz)
       float32[3]  uv       (u,v,0)
       int8[4]     tangent  (tx,ty,tz,tsign)
       uint8[4]    color    (r,g,b,a)
     Faces     (FaceCount * 12 bytes each):
       uint32[3]   vertex indices (a,b,c)
   ========================================================================== */

#pragma pack(push, 1)
struct MeshHeader401 {
    uint16_t sizeof_MeshHeader;   /* = 12 */
    uint16_t sizeof_Vertex;       /* = 40 */
    uint32_t sizeof_Face;         /* = 12 */
};
struct MeshVertex401 {
    float    px, py, pz;
    float    nx, ny, nz;
    float    tu, tv, tw;
    int8_t   tx, ty, tz, tsgn;
    uint8_t  cr, cg, cb, ca;
};
struct MeshFace401 {
    uint32_t a, b, c;
};
#pragma pack(pop)



/* ---- ASCII v1/v2 vertex parser ----------------------------------------- */
static bool MeshParseVec3(const char*& p, float& x, float& y, float& z)
{
    while (*p && *p != '[') p++;
    if (!*p) return false;
    p++;
    x = (float)strtod(p, const_cast<char**>(&p));
    while (*p == ',' || *p == ' ') p++;
    y = (float)strtod(p, const_cast<char**>(&p));
    while (*p == ',' || *p == ' ') p++;
    z = (float)strtod(p, const_cast<char**>(&p));
    while (*p && *p != ']') p++;
    if (*p) p++;
    return true;
}

/* Converts ASCII mesh (v1.x or v2.00-style) → binary 4.01 */
static std::string AsciiMeshToBinary401(const std::string& src)
{
    std::vector<MeshVertex401> verts;
    std::vector<MeshFace401>   faces;
    verts.reserve(512);
    faces.reserve(512);

    const char* p = src.c_str();
    /* skip version line */
    while (*p && *p != '\n') p++;
    if (*p) p++;
    /* skip face-count line */
    while (*p && *p != '\n') p++;
    if (*p) p++;

    while (*p) {
        while (*p == '\r' || *p == '\n' || *p == ' ' || *p == '\t') p++;
        if (!*p) break;

        /* check this line has a '[' */
        const char* q = p;
        bool hasVec = false;
        while (*q && *q != '\n') { if (*q == '[') { hasVec = true; break; } q++; }
        if (!hasVec) { p = q; continue; }

        uint32_t base = (uint32_t)verts.size();
        bool ok = true;
        for (int vi = 0; vi < 3 && ok; vi++) {
            MeshVertex401 v = {};
            v.ca = 255; v.cr = 255; v.cg = 255; v.cb = 255;
            v.tsgn = 1;
            float dummy;
            ok  = MeshParseVec3(p, v.px, v.py, v.pz);
            ok &= MeshParseVec3(p, v.nx, v.ny, v.nz);
            ok &= MeshParseVec3(p, v.tu, v.tv, dummy);
            if (ok) verts.push_back(v);
        }
        while (*p && *p != '\n') p++;
        if (*p) p++;

        if (ok) {
            MeshFace401 f = { base, base+1, base+2 };
            faces.push_back(f);
        }
    }

    if (faces.empty()) return src;

    std::string out;
    out.reserve(13 + sizeof(MeshHeader401) + 8 +
                verts.size() * sizeof(MeshVertex401) +
                faces.size() * sizeof(MeshFace401));

    out += "version 4.01\n";

    MeshHeader401 mh;
    mh.sizeof_MeshHeader = sizeof(MeshHeader401);
    mh.sizeof_Vertex     = sizeof(MeshVertex401);
    mh.sizeof_Face       = sizeof(MeshFace401);
    out.append(reinterpret_cast<const char*>(&mh), sizeof(mh));

    uint32_t vc = (uint32_t)verts.size();
    uint32_t fc = (uint32_t)faces.size();
    out.append(reinterpret_cast<const char*>(&vc), 4);
    out.append(reinterpret_cast<const char*>(&fc), 4);
    out.append(reinterpret_cast<const char*>(verts.data()), vc * sizeof(MeshVertex401));
    out.append(reinterpret_cast<const char*>(faces.data()), fc * sizeof(MeshFace401));
    return out;
}

/* Converts any binary mesh (v3.x / v4.00 / v4.1+ / v5.x / v6.x) → binary 4.01.
 * headerLineEnd = byte offset just past the trailing '\n' of "version X.YY\n". */
static std::string BinaryMeshTo401(const std::string& src, size_t headerLineEnd)
{
    const uint8_t* raw = reinterpret_cast<const uint8_t*>(src.data());
    const size_t   n   = src.size();

    if (headerLineEnd + 2 > n) return src;

    /* The first uint16 of the binary section = sizeof_MeshHeader.
     * This tells us exactly where the header ends, regardless of version. */
    uint16_t headerSz;
    memcpy(&headerSz, raw + headerLineEnd, 2);

    size_t afterHeader = headerLineEnd + headerSz;
    if (afterHeader + 8 > n) return src;

    /* For v5.00+ the header is 16 bytes and is followed by a LOD offset table.
     * Bytes 12-13 = sizeof_LOD, bytes 14-15 = numLODs (both uint16).
     * We must skip past the LOD table to reach VertexCount. */
    size_t countOffset = afterHeader;
    if (headerSz >= 16) {
        if (headerLineEnd + 16 > n) return src;
        uint16_t szLod, numLODs;
        memcpy(&szLod,   raw + headerLineEnd + 12, 2);
        memcpy(&numLODs, raw + headerLineEnd + 14, 2);
        countOffset = afterHeader + (size_t)szLod * (size_t)numLODs;
    }

    if (countOffset + 8 > n) return src;

    uint32_t vc, fc;
    memcpy(&vc, raw + countOffset,     4);
    memcpy(&fc, raw + countOffset + 4, 4);

    /* Sanity bounds */
    if (vc > 4000000 || fc > 4000000) return src;

    size_t vertStart = countOffset + 8;
    size_t vertBytes = (size_t)vc * sizeof(MeshVertex401);
    size_t faceStart = vertStart + vertBytes;
    size_t faceBytes = (size_t)fc * sizeof(MeshFace401);

    if (faceStart + faceBytes > n) return src;

    std::string out;
    out.reserve(13 + sizeof(MeshHeader401) + 8 + vertBytes + faceBytes);

    out += "version 4.01\n";

    MeshHeader401 mh;
    mh.sizeof_MeshHeader = sizeof(MeshHeader401);
    mh.sizeof_Vertex     = sizeof(MeshVertex401);
    mh.sizeof_Face       = sizeof(MeshFace401);
    out.append(reinterpret_cast<const char*>(&mh), sizeof(mh));

    out.append(reinterpret_cast<const char*>(&vc), 4);
    out.append(reinterpret_cast<const char*>(&fc), 4);

    /* Vertex and face layout is identical across all binary versions —
     * copy the raw bytes verbatim (no precision loss). */
    out.append(reinterpret_cast<const char*>(raw + vertStart), vertBytes);
    out.append(reinterpret_cast<const char*>(raw + faceStart), faceBytes);

    return out;
}

/* Top-level dispatcher — called for every asset before it is sent to Studio */
static std::string DownconvertMeshIfNeeded(const std::string& data)
{
    if (data.size() < 13) return data;
    if (data.compare(0, 8, "version ") != 0) return data;

    size_t nl = data.find('\n');
    if (nl == std::string::npos || nl < 8) return data;

    /* Extract version string, e.g. "4.01", "5.00", "2.00" */
    std::string verStr = data.substr(8, nl - 8);
    while (!verStr.empty() && (verStr.back() == '\r' || verStr.back() == ' '))
        verStr.pop_back();

    float verNum = (float)atof(verStr.c_str());

    /* v1.x and v2.x ASCII — Studio 2023 reads natively, no conversion */
    if (verNum < 3.0f) return data;

    /* Already the target format */
    if (verStr == "4.01") return data;

    /* Determine ASCII vs binary.
     * The first byte after the version line in a binary mesh is the low byte
     * of sizeof_MeshHeader (always a small integer like 12 or 16), so it will
     * be a non-printable control byte.  ASCII meshes start with a digit. */
    if (nl + 1 < data.size()) {
        unsigned char firstByte = (unsigned char)data[nl + 1];
        bool probablyAscii = (firstByte >= 0x20 && firstByte < 0x80);
        if (probablyAscii)
            return AsciiMeshToBinary401(data);
    }

    return BinaryMeshTo401(data, nl + 1);
}

/* ============================================================================
   End of mesh downconverter
   ========================================================================== */

static Resp AssetServe(const std::string& data)
{
    /* Roblox place/model files start with "<roblox" (binary or XML).
     * Skip all transforms — RewriteAssetUrls corrupts binary .rbxl data. */
    bool isPlaceOrModel = (data.size() >= 7 &&
                           data.compare(0, 7, "<roblox") == 0);
    if (isPlaceOrModel) {
        Resp r;
        r.status      = 200;
        r.statusText  = "OK";
        r.contentType = "application/octet-stream";
        r.body        = data;
        return r;
    }

    std::string processed = RewriteAssetUrls(data);
    processed = DownconvertMeshIfNeeded(processed);

    bool isMesh = (processed.size() >= 8 &&
                   processed.compare(0, 8, "version ") == 0);

    Resp r;
    r.status      = 200;
    r.statusText  = "OK";
    r.contentType = isMesh ? "application/octet-stream" : "text/plain";
    r.body        = std::move(processed);
    return r;
}

static Resp HandleAssetDelivery(const Req& req)
{
    /* Resolve the asset identifier - prefer id, fall back to assetversionid */
    std::string id  = QS(req,"id");
    std::string ver = QS(req,"assetversionid");
    std::string hsh = QS(req,"hash");

    /* CDN hash path - redirect directly */
    if (!hsh.empty())
        return AssetRedirect("https://t3.rbxcdn.com/" + hsh);

    std::string key = !id.empty() ? id : ver;

    if (key.empty())
        return RJson("{\"errors\":[{\"code\":400,\"message\":\"Missing id\"}]}", 400);

    /* Check 1: local file in www\asset\ next to DLL (mirrors PHP ./{id}).
     * GunzipIfNeeded decompresses on the fly if the stored file is gzip. */
    {
        std::string f = DllPath("www\\asset\\") + key;
        std::string d = GunzipIfNeeded(ReadFile(f));
        if (!d.empty()) return AssetServe(d);
    }

    /* Check 2: data\SavedData\{key} with or without extension. Place files are
     * stored gzip-compressed (see Upload.ashx); detect and decompress before
     * serving so Studio still receives a plain .rbxl. */
    {
        std::string dir = DllPath("data\\SavedData\\");
        std::string f   = dir + key;
        std::string d   = GunzipIfNeeded(ReadFile(f));
        if (!d.empty()) return AssetServe(d);

        static const char* exts[] = { ".rbxl", ".rbxm", ".rbxlx", ".rbxmx",
                                       ".png",  ".jpg",  ".ogg",   ".mp3",
                                       ".lua",  ".mesh", NULL };
        for (int i=0; exts[i]; i++) {
            d = GunzipIfNeeded(ReadFile(f + exts[i]));
            if (!d.empty()) return AssetServe(d);
        }
    }

    /* Check 3: id is itself a URL - redirect straight to it */
    if (key.find("http") != std::string::npos)
        return AssetRedirect(key);

    /* Check 4: id contains "1111111" sentinel — extract real id and force version=1.
     * Mirrors PHP exactly:
     *   if (strstr($id, '1111111'))
     *       $url = ".../v1/asset/?id=" . explode("1111111",$id)[1] . "&version=1";
     *   else
     *       $url = ".../v1/asset/?id=" . $id;
     *   $content = fetch_asset($url, $cookie);   // single direct fetch with auth cookie
     */
    std::string assetId;
    std::string fetchUrl;
    size_t sep = key.find("1111111");
    if (sep != std::string::npos) {
        assetId  = key.substr(sep + 7);
        fetchUrl = "https://assetdelivery.roblox.com/v1/asset/?id=" + assetId + "&version=1";
    } else {
        assetId  = !id.empty() ? id : ver;
        fetchUrl = "https://assetdelivery.roblox.com/v1/asset/?id=" + assetId;
    }

    /* Direct fetch — WinHTTP follows the CDN redirect automatically.
     * The cookie loaded from robloxcookie.txt is sent by FetchUrl. */
    {
        std::string assetData;
        if (FetchUrl(fetchUrl, assetData)) {
            Log("Asset %s fetched OK (%zu bytes)", assetId.c_str(), assetData.size());
            return AssetServe(assetData);
        }
        Log("Asset %s: fetch failed, falling back to redirect", assetId.c_str());
    }

    /* All else failed — let Studio handle it directly */
    return AssetRedirect(fetchUrl);
}

/* ============================================================================
   SECTION 11 — Master router
   ========================================================================= */

/* Hardcoded groups/roles list — returned for ANY /v2/users/{id}/groups/roles */
static const char* GROUPS_ROLES_JSON =
    "{\"data\":["
    "{\"group\":{\"id\":13538101,\"name\":\"GC' Sus Games\",\"memberCount\":11,\"hasVerifiedBadge\":false},"
     "\"role\":{\"id\":77381526,\"name\":\"Member\",\"rank\":1}},"
    "{\"group\":{\"id\":391929292,\"name\":\"FilteringEnabled=false\",\"memberCount\":6,\"hasVerifiedBadge\":false},"
     "\"role\":{\"id\":700687000,\"name\":\"Owner\",\"rank\":255}},"
    "{\"group\":{\"id\":4347428,\"name\":\"The State of Mind\",\"memberCount\":416796,\"hasVerifiedBadge\":false},"
     "\"role\":{\"id\":29322544,\"name\":\"\xe2\xad\x90\xef\xb8\x8f Important Member\",\"rank\":1}},"
    "{\"group\":{\"id\":33142130,\"name\":\"Legence Clothes\",\"memberCount\":6,\"hasVerifiedBadge\":false},"
     "\"role\":{\"id\":101719466,\"name\":\"\xf0\x9f\x8e\x80\xf0\x9f\x93\x9d Love\xf0\x9f\x93\x9d\",\"rank\":1}},"
    "{\"group\":{\"id\":13273531,\"name\":\"_RARE NAMES_\",\"memberCount\":11049,\"hasVerifiedBadge\":false},"
     "\"role\":{\"id\":76113545,\"name\":\"Incredible names\",\"rank\":45}},"
    "{\"group\":{\"id\":5995136,\"name\":\"- Old Roblox Accounts -\",\"memberCount\":62907,\"hasVerifiedBadge\":false},"
     "\"role\":{\"id\":93679233,\"name\":\"2006 / 2007\",\"rank\":170}},"
    "{\"group\":{\"id\":32818995,\"name\":\"(Project Aincrad SAO)\",\"memberCount\":1901,\"hasVerifiedBadge\":false},"
     "\"role\":{\"id\":100005741,\"name\":\"(Beta Tester)\",\"rank\":10}},"
    "{\"group\":{\"id\":14131124,\"name\":\"CNP Foundation\",\"memberCount\":339771,\"hasVerifiedBadge\":false},"
     "\"role\":{\"id\":80344347,\"name\":\"\xe2\x9a\x94\xef\xb8\x8f\xe3\x80\xa2Player\",\"rank\":1}},"
    "{\"group\":{\"id\":35850331,\"name\":\"Luckiest Game Studio\",\"memberCount\":19,\"hasVerifiedBadge\":false},"
     "\"role\":{\"id\":350844049,\"name\":\"Weird Otaku\",\"rank\":255}},"
    "{\"group\":{\"id\":2782840,\"name\":\"Chillz Studios\",\"memberCount\":17557193,\"hasVerifiedBadge\":true},"
     "\"role\":{\"id\":22745106,\"name\":\"\xf0\x9f\x8c\x9fRoyal Member\xf0\x9f\x8c\x9f\",\"rank\":150}}"
    "]}";

/* Common version blob */
static const char* VERSION_JSON =
    "{\"version\":\"0.578.0.5780566\","
    "\"clientVersionUpload\":\"version-f0b439683245446c\","
    "\"bootstrapperVersion\":\"1.0.0.0\","
    "\"nextClientVersion\":\"0.578.0.5780566\","
    "\"nextClientVersionUpload\":\"version-f0b439683245446c\","
    "\"flagOnly\":true}";

/* Common user identity blob — built at call time from g_username / g_userId */
static std::string UserJson()
{
    return J("{\"ageBracket\":0,\"countryCode\":\"US\",\"isPremium\":true,"
             "\"id\":{I},\"name\":\"{U}\",\"displayName\":\"{U}\","
             "\"AccountAgeInDays\":1324354}");
}

/* Returns universe JSON for the given ID.
 * If a saved universe JSON file exists, returns it.
 * Otherwise falls back to the hardcoded mock (for the default 9991912465 case). */
static std::string UniverseJsonForId(const std::string& universeId)
{
    std::string saved;
    if (LoadUniverseJson(universeId, saved)) return saved;
    /* Mock fallback — Baseplate is NOT owned by the local player */
    return "{\"id\":9991912465,\"name\":\"Baseplate\",\"description\":\"\","
           "\"isArchived\":false,\"rootPlaceId\":9991912465,\"isActive\":true,"
           "\"privacyType\":\"Public\",\"creatorType\":\"User\","
           "\"creatorTargetId\":998796,\"creatorName\":\"Roblox\","
           "\"price\":null,\"playing\":0,\"visits\":0,\"maxPlayers\":10,"
           "\"studioAccessToApisAllowed\":true,"
           "\"genre\":\"All\",\"isAllGenre\":true,"
           "\"created\":\"2022-05-11T13:27:09.897Z\","
           "\"updated\":\"2022-06-19T07:23:39.03Z\"}";
}

/* Common universe blob — built at call time from g_username / g_userId */
static std::string UniverseJson()
{
    return UniverseJsonForId("9991912465");
}

/* Open-Cloud datastore handler for /v2/persistence/{uid}/datastores/... */
static Resp HandleOpenCloudDs(const Req& req)
{
    const std::string& P = req.path;
    const std::string  M = req.method;

    /* Extract universeId */
    std::string uid;
    const char* marker = "/v2/persistence/";
    size_t mpos = P.find(marker);
    if (mpos == std::string::npos) return HandleDatastore(req);
    size_t start = mpos + strlen(marker);
    size_t slash = P.find('/', start);
    uid = (slash == std::string::npos) ? P.substr(start) : P.substr(start, slash - start);

    std::string ds  = QS(req,"datastore");
    std::string obj = QS(req,"objectKey");
    std::string scope = "global";
    std::string key   = obj;
    size_t sp = obj.find('/');
    if (sp != std::string::npos) { scope = obj.substr(0, sp); key = obj.substr(sp+1); }

    if (key.empty()) return RJson("{\"objects\":[],\"nextPageCursor\":null}");

    std::string dsBase  = std::string("data\\datastores\\") + uid;
    std::string dsScope = dsBase + "\\" + UrlEncode(scope);
    std::string dsDs    = dsScope + "\\" + UrlEncode(ds) + "\\";
    std::string dir     = DllPath(dsDs.c_str());
    std::string file    = dir + UrlEncode(key) + ".json";
    EnsureDir(DllPath(dsBase.c_str()));
    EnsureDir(DllPath(dsScope.c_str()));
    EnsureDir(dir);

    if (M == "GET") {
        /* v2 GetAsync — CORRECT WIRE FORMAT
         * ---------------------------------
         * The engine does NOT expect a JSON wrapper here.  For the standard
         * (non-ordered) v2 persistence GET, the HTTP *body* IS the raw stored
         * value (the JSON-serialized Lua value), and ALL metadata is returned
         * in response HEADERS — the engine parses the version via
         * parseObjectVersionFromResponse() reading "Roblox-Object-Version-Id".
         *
         * Wrapping the value in {"value":...,"version":...} is exactly what
         * makes the engine fail with:
         *     504: Data store request successful, but response not formatted
         *          correctly.
         * because it tries to deserialize the whole wrapper object AS the value
         * and the round-trip / version parse fails.
         *
         * The version-descriptor fields (version, deleted, contentLength,
         * createdTime, objectCreatedTime) belong to SetAsync / ListVersions
         * responses — NOT to GetAsync. That is why SetAsync already works with
         * that JSON shape and GetAsync must not reuse it in the body.
         *
         * 404 -> engine interprets as nil (key not found).
         */
        DsRec rec;
        /* If nothing is saved for this key, DON'T 404.  Instead return the
         * exact same 200 + headers format with a body of `null`.  Studio
         * deserializes `null` to nil, so GetAsync returns nil for an unset
         * key — the documented behaviour — without any 404 handling/retries
         * tripping on the engine side. */
        if (!DsRead(file, rec)) {
            rec.value     = "null";
            rec.version   = 0;
            rec.createdAt = "";
        }
        Resp r;
        r.status = 200; r.statusText = "OK";
        /* Body is the raw value; advertise it as JSON since stored values are
         * JSON (strings, numbers, booleans, tables all serialize to JSON). */
        r.contentType = "application/json; charset=utf-8";

        /* verBuf: Roblox internal version-id format for the response header.
         * (08DB + 12 hex digits + '.' + 10 decimal digits)                    */
        char verBuf[64];
        sprintf(verBuf, "08DB%012X.0000000000", (unsigned)rec.version);
        std::string ts = rec.createdAt.empty() ? "2023-01-01T00:00:00.000Z" : rec.createdAt;

        /* THE BODY IS THE VALUE ITSELF — nothing more.
         * rec.value already holds the exact JSON that was stored, whether that
         * is a string ("aaa"), a number, a bool, or a table ([...]/{...}). */
        r.body = rec.value.empty() ? std::string("null") : rec.value;

        /* All metadata travels in headers.  The engine's response-metadata
         * extractor reads exactly this set: Roblox-Usn, ETag,
         * Roblox-Object-Version-Id (only when DataStore2NewVersionHeader is
         * ON), Roblox-Object-Attributes, Roblox-Object-Created-Time,
         * Roblox-Object-Version-Created-Time, Roblox-Object-Userids,
         * Content-MD5, Content-Length, Deleted.  We supply all of them.
         * ETag mirrors the version id (old builds read the version from ETag
         * when the new-version-header flag is off). */
        r.hdrs["Roblox-Object-Version-Id"]           = verBuf;
        r.hdrs["ETag"]                               = verBuf;
        r.hdrs["Roblox-Object-Created-Time"]         = ts;
        r.hdrs["Roblox-Object-Version-Created-Time"] = ts;
        r.hdrs["Roblox-Object-Attributes"]           = "{}";
        r.hdrs["Roblox-Object-Userids"]              = "[]";
        r.hdrs["Roblox-Usn"]                         = "1";
        r.hdrs["Deleted"]                            = "false";

        /* Content-MD5: base64(MD5(body)) — engine validates the value bytes
         * against this header, so it must be computed over the raw value. */
        std::string md5b64 = ComputeMD5Base64(r.body);
        if (!md5b64.empty()) r.hdrs["Content-MD5"] = md5b64;
        return r;
    }
    if (M == "POST" || M == "PUT") {
        DsWrite(file, req.body.empty() ? "null" : req.body, 1, "");
        return RJson("{\"version\":\"1\",\"deleted\":false,\"contentLength\":0,"
                     "\"createdTime\":\"2023-01-01T00:00:00Z\","
                     "\"objectCreatedTime\":\"2023-01-01T00:00:00Z\"}");
    }
    if (M == "DELETE") {
        DeleteFileA(file.c_str());
        return RJson("{}", 204);
    }
    return RJson("{}");
}

/* Ensure every universe JSON object has both "id" and "universeId" fields.
 * Old saved files only have "universeId"; Studio reads "id" for follow-up
 * requests like /v1/universes/{id}/permissions. Missing "id" resolves to 0 -> crash. */
static std::string NormalizeUniverseJson(const std::string& raw)
{
    if (raw.find("\"id\":") != std::string::npos) return raw;
    size_t up = raw.find("\"universeId\":");
    if (up == std::string::npos) return raw;
    size_t vstart = up + 13;
    while (vstart < raw.size() && (raw[vstart]==' '||raw[vstart]=='\t')) vstart++;
    size_t vend = vstart;
    while (vend < raw.size() && (raw[vend]=='-'||isdigit((unsigned char)raw[vend]))) vend++;
    if (vend == vstart) return raw;
    std::string idVal = raw.substr(vstart, vend - vstart);
    std::string out = raw.substr(0, up);
    out += "\"id\":" + idVal + ",";
    out += raw.substr(up);
    return out;
}

/* The editable avatar settings persisted per universe. */
static const char* kAvatarStringFields[] = {
    "universeAvatarType", "universeScaleType", "universeAnimationType",
    "universeCollisionType", "universeBodyType", "universeJointPositioningType", NULL
};

/* Read a field from a saved-universe JSON, or return a default. */
static std::string UniField(const std::string& saved, const char* key, const char* def)
{
    std::string v = CfgStr(saved, key);
    return v.empty() ? std::string(def) : v;
}

/* Build the /v2/universes/{id}/configuration response from a saved universe.
 * Includes the avatar min/max scale objects (Studio's Game Settings -> Avatar
 * page indexes universeAvatarMinScales.height etc.; if they're missing the
 * page errors with "attempt to index nil with 'height'").  Editable dropdown
 * settings are read back from the universe JSON so they round-trip. */
static std::string BuildUniverseConfigJson(const std::string& univId,
                                           const std::string& saved)
{
    std::string name  = UniField(saved, "name", "Place");
    std::string avT   = UniField(saved, "universeAvatarType", "MorphToR15");
    std::string scT   = UniField(saved, "universeScaleType", "AllScales");
    std::string anT   = UniField(saved, "universeAnimationType", "PlayerChoice");
    std::string coT   = UniField(saved, "universeCollisionType", "OuterBox");
    std::string boT   = UniField(saved, "universeBodyType", "Standard");
    std::string joT   = UniField(saved, "universeJointPositioningType", "ArtistIntent");
    /* per-dimension min/max scales (persisted as flat fields, default = full range) */
    std::string mnH=UniField(saved,"avatarMinHeight","0.9"),   mxH=UniField(saved,"avatarMaxHeight","1.05");
    std::string mnW=UniField(saved,"avatarMinWidth","0.7"),    mxW=UniField(saved,"avatarMaxWidth","1");
    std::string mnD=UniField(saved,"avatarMinHead","0.95"),    mxD=UniField(saved,"avatarMaxHead","1");
    std::string mnP=UniField(saved,"avatarMinProportion","0"), mxP=UniField(saved,"avatarMaxProportion","1");
    std::string mnB=UniField(saved,"avatarMinBodyType","0"),   mxB=UniField(saved,"avatarMaxBodyType","1");

    std::string o = "{\"allowPrivateServers\":true,\"privateServerPrice\":null,";
    o += "\"id\":" + (univId.empty()?std::string("9991912465"):univId) + ",";
    o += "\"name\":\"" + name + "\",";
    o += "\"universeAvatarType\":\"" + avT + "\",";
    o += "\"universeScaleType\":\"" + scT + "\",";
    o += "\"universeAnimationType\":\"" + anT + "\",";
    o += "\"universeCollisionType\":\"" + coT + "\",";
    o += "\"universeBodyType\":\"" + boT + "\",";
    o += "\"universeJointPositioningType\":\"" + joT + "\",";
    o += "\"universeAvatarAssetOverrides\":[],";
    o += "\"universeAvatarMinScales\":{\"height\":" + mnH + ",\"width\":" + mnW
       + ",\"head\":" + mnD + ",\"proportion\":" + mnP + ",\"bodyType\":" + mnB + "},";
    o += "\"universeAvatarMaxScales\":{\"height\":" + mxH + ",\"width\":" + mxW
       + ",\"head\":" + mxD + ",\"proportion\":" + mxP + ",\"bodyType\":" + mxB + "},";
    o += "\"isArchived\":false,\"isFriendsOnly\":false,\"genre\":\"All\",";
    o += "\"playableDevices\":[\"Computer\",\"Phone\",\"Tablet\"],";
    o += "\"isForSale\":false,\"price\":0,\"isStudioAccessToApisAllowed\":true,";
    o += "\"privacyType\":\"Public\"}";
    return o;
}

/* Persist avatar-related settings sent in a configuration PATCH body. */
static void PersistAvatarConfig(const std::string& univId, const std::string& body)
{
    if (univId.empty()) return;
    for (int i = 0; kAvatarStringFields[i]; i++) {
        std::string v = CfgStr(body, kAvatarStringFields[i]);
        if (!v.empty()) UpdateUniverseField(univId, kAvatarStringFields[i], v);
    }
    /* min/max scales arrive nested under universeAvatarMinScales / MaxScales;
     * pull each dimension out of the right sub-object and store it flat. */
    struct { const char* obj; const char* dim; const char* field; } S[] = {
        {"universeAvatarMinScales","height","avatarMinHeight"},
        {"universeAvatarMinScales","width","avatarMinWidth"},
        {"universeAvatarMinScales","head","avatarMinHead"},
        {"universeAvatarMinScales","proportion","avatarMinProportion"},
        {"universeAvatarMinScales","bodyType","avatarMinBodyType"},
        {"universeAvatarMaxScales","height","avatarMaxHeight"},
        {"universeAvatarMaxScales","width","avatarMaxWidth"},
        {"universeAvatarMaxScales","head","avatarMaxHead"},
        {"universeAvatarMaxScales","proportion","avatarMaxProportion"},
        {"universeAvatarMaxScales","bodyType","avatarMaxBodyType"},
        {NULL,NULL,NULL}
    };
    for (int i = 0; S[i].obj; i++) {
        size_t op = body.find(std::string("\"") + S[i].obj + "\"");
        if (op == std::string::npos) continue;
        size_t oend = body.find('}', op);
        std::string sub = (oend==std::string::npos) ? body.substr(op) : body.substr(op, oend-op);
        std::string v = CfgStr(sub, S[i].dim);
        if (!v.empty()) UpdateUniverseField(univId, S[i].field, v);
    }
}

/* Resolve the avatar rig ("R6"/"R15") for a place from its universe's
 * universeAvatarType setting.  /v1/avatar-fetch returns this, and it's what
 * actually decides the rig you spawn with — hardcoding R6 here is why R15
 * settings had no effect in-game. */
static std::string ResolveAvatarType(const std::string& placeId)
{
    std::string saved;
    bool found = (!placeId.empty() && LoadUniverseJson(placeId, saved));
    if (!found && !placeId.empty()) {
        /* placeId is usually the rootPlaceId, not the universeId — search. */
        std::string dir = UniversesDir();
        WIN32_FIND_DATAA fd;
        HANDLE hf = FindFirstFileA((dir + "*.json").c_str(), &fd);
        if (hf != INVALID_HANDLE_VALUE) {
            do {
                if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
                std::string raw = ReadFile(dir + fd.cFileName);
                if (raw.empty()) continue;
                if (CfgStr(raw, "rootPlaceId") == placeId) { saved = raw; found = true; break; }
            } while (FindNextFileA(hf, &fd));
            FindClose(hf);
        }
    }
    std::string t = CfgStr(saved, "universeAvatarType");
    if (t == "MorphToR6")  return "R6";
    if (t == "MorphToR15") return "R15";
    /* PlayerChoice / unknown -> default to R15 (matches the config default). */
    return "R15";
}

/* ===========================================================================
   Avatar appearance pipeline
   ---------------------------------------------------------------------------
   Appearance is a list of asset IDs (as in Appearence.ini:
     http://localhost/asset/?id=N;http://localhost/asset/?id=N;...
   with animation IDs carrying the "1111111" sentinel prefix).  We compile that
   into the avatar-fetch JSON.  Each asset's assetTypeId is resolved from
   Roblox's economy API (cached); the animation slot is taken DIRECTLY from the
   animation asset's type:
     48=climb 50=fall 51=idle 52=jump 53=run 54=swim 55=walk
   Stored per-userId in memory only (never written to disk).
   ========================================================================== */
static std::mutex                        g_avMutex;
struct AssetInfo { int type; std::string name; };           /* economy details (cached) */
static std::map<long long, AssetInfo>    g_assetCache;       /* assetId  -> {type,name}   */
static std::map<std::string, std::string> g_userAppearance; /* userId   -> raw appearance */
static std::map<std::string, std::string> g_avatarCache;    /* userId   -> compiled JSON  */

/* Extract a JSON string value, returning the source bytes verbatim (they are
 * already JSON-escaped, so they can be re-emitted inside quotes as-is). */
static std::string JsonGetString(const std::string& s, const char* key)
{
    std::string pat = std::string("\"") + key + "\":\"";
    size_t p = s.find(pat);
    if (p == std::string::npos) return "";
    p += pat.size();
    std::string out;
    while (p < s.size()) {
        char c = s[p];
        if (c == '\\' && p + 1 < s.size()) { out.push_back(c); out.push_back(s[p+1]); p += 2; continue; }
        if (c == '"') break;
        out.push_back(c); ++p;
    }
    return out;
}

/* Extract a JSON number value (first match of "key":). */
static long long JsonGetNumber(const std::string& s, const char* key)
{
    std::string pat = std::string("\"") + key + "\":";
    size_t p = s.find(pat);
    if (p == std::string::npos) return 0;
    p += pat.size();
    while (p < s.size() && (s[p]==' '||s[p]=='\t')) ++p;
    bool neg = (p < s.size() && s[p]=='-'); if (neg) ++p;
    long long v = 0; bool any = false;
    while (p < s.size() && s[p] >= '0' && s[p] <= '9') { v = v*10 + (s[p]-'0'); ++p; any = true; }
    return any ? (neg ? -v : v) : 0;
}

/* asset-type cache persisted to disk (so each asset is resolved once, ever). */
static std::string AssetCachePath() { return DllPath("asset_type_cache.tsv"); }

static void LoadAssetCacheLocked()   /* call with g_avMutex held */
{
    static bool loaded = false; if (loaded) return; loaded = true;
    std::string d = ReadFile(AssetCachePath());
    size_t pos = 0;
    while (pos < d.size()) {
        size_t nl = d.find('\n', pos);
        std::string line = (nl==std::string::npos) ? d.substr(pos) : d.substr(pos, nl-pos);
        pos = (nl==std::string::npos) ? d.size() : nl+1;
        size_t t1 = line.find('\t'); if (t1==std::string::npos) continue;
        size_t t2 = line.find('\t', t1+1);
        long long id = _atoi64(line.substr(0,t1).c_str());
        int type = atoi(line.substr(t1+1, (t2==std::string::npos?line.size():t2)-(t1+1)).c_str());
        std::string name = (t2==std::string::npos) ? "" : line.substr(t2+1);
        if (id > 0 && type > 0) { AssetInfo ai; ai.type=type; ai.name=name; g_assetCache[id]=ai; }
    }
}
static void AppendAssetCacheToDisk(long long id, const AssetInfo& info)
{
    std::string name = info.name;
    for (size_t i=0;i<name.size();++i) if (name[i]=='\n'||name[i]=='\r'||name[i]=='\t') name[i]=' ';
    char hdr[48]; sprintf(hdr, "%lld\t%d\t", id, info.type);
    FILE* f = fopen(AssetCachePath().c_str(), "ab");
    if (f) { fputs(hdr, f); fwrite(name.data(),1,name.size(),f); fputc('\n', f); fclose(f); }
}

/* Resolve MANY assets in ONE authenticated develop.roblox.com call. This is the
 * ONLY type resolver — it needs the .ROBLOSECURITY cookie (attached by FetchUrl)
 * and returns id/typeId/name per asset, so a whole avatar resolves in one request
 * instead of dozens of rate-limited economy calls. Caches every success to disk. */
static void BatchResolveAssets(const std::vector<long long>& ids)
{
    for (size_t off = 0; off < ids.size(); off += 50) {
        size_t end = (off + 50 < ids.size()) ? off + 50 : ids.size();
        std::string url = "https://develop.roblox.com/v1/assets?assetIds=";
        for (size_t i = off; i < end; ++i) { char b[24]; sprintf(b,"%lld",ids[i]); if (i>off) url+=","; url+=b; }
        std::string body; DWORD st = 0;
        if (!FetchUrlEx(url, body, &st)) {
            Log("Avatar: batch lookup failed (HTTP %lu) for %u ids", st, (unsigned)(end-off));
            continue;
        }
        int got = 0;
        size_t dp = body.find("\"data\""); if (dp==std::string::npos) continue;
        size_t as = body.find('[', dp);   if (as==std::string::npos) continue;
        int bd=0; size_t ae=as;
        for (size_t k=as;k<body.size();++k){ if(body[k]=='[')++bd; else if(body[k]==']'){ if(--bd==0){ae=k;break;} } }
        size_t i = as + 1;
        while (i < ae) {
            size_t ob = body.find('{', i); if (ob==std::string::npos || ob>=ae) break;
            int d2=0; size_t j=ob;
            for (; j<body.size(); ++j){ if(body[j]=='{')++d2; else if(body[j]=='}'){ if(--d2==0){ ++j; break; } } }
            std::string obj = body.substr(ob, j-ob); i = j;
            long long id = JsonGetNumber(obj, "id");        /* top-level "id" comes first  */
            int type = (int)JsonGetNumber(obj, "typeId");   /* top-level "typeId" before creator.typeId */
            std::string name = JsonGetString(obj, "name");
            if (id > 0 && type > 0) {
                std::lock_guard<std::mutex> lk(g_avMutex);
                if (g_assetCache.find(id)==g_assetCache.end()) {
                    AssetInfo ai; ai.type=type; ai.name=name;
                    g_assetCache[id]=ai; AppendAssetCacheToDisk(id, ai);
                }
                ++got;
            }
        }
        Log("Avatar: batch resolved %d/%u assets", got, (unsigned)(end-off));
    }
}

/* Resolve one asset's type+name. Cache hit (mem/disk) is instant; a miss is
 * resolved via the same authenticated develop batch endpoint (single id). No
 * economy fallback -> no 429 bursts. Failures stay uncached so they retry. */
static AssetInfo ResolveAssetInfo(long long assetId)
{
    {
        std::lock_guard<std::mutex> lk(g_avMutex);
        LoadAssetCacheLocked();
        std::map<long long,AssetInfo>::iterator it = g_assetCache.find(assetId);
        if (it != g_assetCache.end() && it->second.type > 0) return it->second;
    }
    BatchResolveAssets(std::vector<long long>(1, assetId));
    {
        std::lock_guard<std::mutex> lk(g_avMutex);
        std::map<long long,AssetInfo>::iterator it = g_assetCache.find(assetId);
        if (it != g_assetCache.end()) return it->second;
    }
    AssetInfo miss; miss.type = -1; return miss;
}

/* Roblox BrickColor name -> RGB hex (lowercase, no '#'). Default = Medium
 * stone grey when the name isn't known. */
static const std::map<std::string,std::string>& BrickMap()
{
    static const std::map<std::string,std::string> M = {
        {"white","f2f3f3"},{"institutional white","f8f8f8"},{"black","1b2a35"},
        {"really black","111111"},{"mid gray","cdcdcd"},{"medium stone grey","a3a2a5"},
        {"dark stone grey","635f62"},{"light stone grey","c7c1b7"},{"grey","8d8d8d"},
        {"dark grey","6d6e6c"},{"smoky grey","91807c"},
        {"pastel brown","ffcc99"},{"light orange","eab892"},{"nougat","cc8e69"},
        {"brick yellow","d7c59a"},{"reddish brown","694028"},{"dark orange","a05f35"},
        {"brown","7c5c46"},{"dirt brown","564236"},{"cocoa","562424"},{"tan","e8bac8"},
        {"sand red","d36055"},{"burlap","b08e57"},{"light brown","7c503a"},
        {"bright red","c4281c"},{"really red","ff0000"},{"crimson","790e1a"},
        {"maroon","760a0a"},{"salmon","ff9494"},{"pink","ffc0cb"},{"light reddish violet","e8bbd0"},
        {"pastel violet","cdbedb"},{"hot pink","ff00bf"},{"carnation pink","ff98dc"},
        {"magenta","aa00aa"},{"bright orange","da8541"},{"neon orange","d5733d"},
        {"deep orange","ff6600"},{"bright yellow","f5cd30"},{"new yeller","ffff00"},
        {"cool yellow","f0db4f"},{"pastel yellow","ffffcc"},{"daisy orange","f8d96d"},
        {"bright green","4b974b"},{"dark green","287f47"},{"lime green","00ff00"},
        {"slime green","506d54"},{"camo","3a7d15"},{"sea green","348e40"},{"earth green","3f5031"},
        {"bright bluish green","008f9c"},{"teal","008080"},{"toothpaste","00ffff"},
        {"bright blue","0d69ac"},{"navy blue","002060"},{"really blue","0000ff"},
        {"deep blue","2154b9"},{"cyan","04afec"},{"pastel blue","80bbdb"},
        {"steel blue","527cae"},{"electric blue","0989cf"},{"medium blue","5b9a4c"},
        {"bright violet","6b327c"},{"royal purple","6225d1"},{"lilac","a75e9b"},
        {"lavender","8c5b9f"},{"purple","a64dd1"},{"alder","a787b4"},{"plum","843a3a"},
        {"gold","dba640"},{"bright bluish violet","4b48a3"}
    };
    return M;
}
static std::string BrickColorToHex(const std::string& nameIn)
{
    std::string n; n.reserve(nameIn.size());
    for (size_t i = 0; i < nameIn.size(); ++i) { char c = nameIn[i]; if (c>='A'&&c<='Z') c+=32; n.push_back(c); }
    /* trim */
    while (!n.empty() && (n.back()==' '||n.back()=='\r'||n.back()=='\n'||n.back()=='\t')) n.pop_back();
    size_t b = n.find_first_not_of(" \r\n\t"); if (b!=std::string::npos) n = n.substr(b); else n.clear();
    const std::map<std::string,std::string>& M = BrickMap();
    std::map<std::string,std::string>::const_iterator it = M.find(n);
    return (it != M.end()) ? it->second : std::string("a3a2a5");
}

/* Pull every digit-run that follows an "id=" (falls back to any digit run). The
 * 1111111 animation sentinel is part of the digits and is preserved here. */
static std::vector<std::string> ParseAppearanceIds(const std::string& raw)
{
    std::vector<std::string> out;
    size_t p = 0;
    while ((p = raw.find("id=", p)) != std::string::npos) {
        p += 3; size_t e = p;
        while (e < raw.size() && raw[e] >= '0' && raw[e] <= '9') e++;
        if (e > p) out.push_back(raw.substr(p, e - p));
        p = e;
    }
    if (!out.empty()) return out;
    size_t i = 0;
    while (i < raw.size()) {
        if (raw[i] >= '0' && raw[i] <= '9') {
            size_t e = i; while (e < raw.size() && raw[e] >= '0' && raw[e] <= '9') e++;
            out.push_back(raw.substr(i, e - i)); i = e;
        } else i++;
    }
    return out;
}

static const char* AnimSlotForType(int t)
{
    switch (t) {
        case 48: return "climb"; case 50: return "fall"; case 51: return "idle";
        case 52: return "jump";  case 53: return "run";  case 54: return "swim";
        case 55: return "walk";  default: return 0;
    }
}

/* Compile an appearance into the full avatar-fetch JSON.  Input is the asset
 * URL/ID list, optionally followed by "|COLORS|head;torso;leftArm;rightArm;
 * leftLeg;rightLeg" (BrickColor names).  Asset routing by economy type:
 *   48-55  -> animationAssetIds (slot)
 *   61     -> emotes[] (with name + 1-based position)
 *   else   -> assetAndAssetTypeIds */
static std::string CompileAvatarJson(const std::string& rig, const std::string& rawIn,
                                     bool* outComplete)
{
    if (outComplete) *outComplete = true;
    /* split off the optional |COLORS| trailer */
    std::string assetsRaw = rawIn, colorsRaw;
    size_t cp = rawIn.find("|COLORS|");
    if (cp != std::string::npos) { assetsRaw = rawIn.substr(0, cp); colorsRaw = rawIn.substr(cp + 8); }

    std::vector<std::string> toks = ParseAppearanceIds(assetsRaw);

    /* Resolve every (uncached) asset id in ONE batched develop.roblox.com call
     * first, so the loop below hits the cache instead of firing dozens of
     * rate-limited per-asset economy requests (the 429 burst). */
    {
        std::vector<long long> need;
        for (size_t k = 0; k < toks.size(); k++) {
            std::string tok = toks[k]; size_t sp = tok.find("1111111");
            std::string rid = (sp!=std::string::npos && tok.size()>sp+7) ? tok.substr(sp+7) : tok;
            long long aid = _atoi64(rid.c_str());
            if (aid <= 0) continue;
            bool cached;
            { std::lock_guard<std::mutex> lk(g_avMutex); LoadAssetCacheLocked();
              std::map<long long,AssetInfo>::iterator it = g_assetCache.find(aid);
              cached = (it != g_assetCache.end() && it->second.type > 0); }
            if (!cached) need.push_back(aid);
        }
        if (!need.empty()) BatchResolveAssets(need);
    }

    std::string assets, anims, emotes;
    int emotePos = 0;
    for (size_t k = 0; k < toks.size(); k++) {
        std::string tok = toks[k];
        std::string realId = tok;
        size_t sp = tok.find("1111111");
        if (sp != std::string::npos && tok.size() > sp + 7) realId = tok.substr(sp + 7);
        long long aid = _atoi64(realId.c_str());
        if (aid <= 0) continue;
        AssetInfo info = ResolveAssetInfo(aid);
        int type = info.type;
        if (type <= 0 && outComplete) *outComplete = false;   /* unresolved -> don't cache result */
        const char* slot = AnimSlotForType(type);
        if (slot) {
            if (!anims.empty()) anims += ",";
            anims += "\"" + std::string(slot) + "\":" + realId;
        } else if (type == 61) {                 /* EmoteAnimation */
            ++emotePos;
            char head[64]; sprintf(head, "{\"assetId\":%lld,\"assetName\":\"", aid);
            char tail[48]; sprintf(tail, "\",\"position\":%d}", emotePos);
            if (!emotes.empty()) emotes += ",";
            emotes += std::string(head) + info.name + tail;
        } else if (type > 0) {
            if (!assets.empty()) assets += ",";
            char buf[96]; sprintf(buf, "{\"assetId\":%lld,\"assetTypeId\":%d}", aid, type);
            assets += buf;
        }
    }

    /* body colors: head, torso, leftArm, rightArm, leftLeg, rightLeg */
    std::string col[6] = { "a3a2a5","a3a2a5","a3a2a5","a3a2a5","a3a2a5","a3a2a5" };
    if (!colorsRaw.empty()) {
        size_t s = 0; int ci = 0;
        while (ci < 6) {
            size_t e = colorsRaw.find(';', s);
            std::string v = (e == std::string::npos) ? colorsRaw.substr(s) : colorsRaw.substr(s, e - s);
            if (!v.empty()) col[ci] = BrickColorToHex(v);
            ci++;
            if (e == std::string::npos) break;
            s = e + 1;
        }
    }

    return "{\"resolvedAvatarType\":\"" + rig + "\","
        "\"equippedGearVersionIds\":[],\"backpackGearVersionIds\":[],"
        "\"assetAndAssetTypeIds\":[" + assets + "],"
        "\"animationAssetIds\":{" + anims + "},"
        "\"bodyColor3s\":{"
        "\"headColor3\":\""     + col[0] + "\",\"torsoColor3\":\""    + col[1] + "\","
        "\"rightArmColor3\":\"" + col[3] + "\",\"leftArmColor3\":\""  + col[2] + "\","
        "\"rightLegColor3\":\"" + col[5] + "\",\"leftLegColor3\":\""  + col[4] + "\"},"
        "\"scales\":{\"height\":1.0,\"width\":1.0,\"head\":1.0,\"depth\":1.0,"
        "\"proportion\":0.0,\"bodyType\":0.0},"
        "\"emotes\":[" + emotes + "]}";
}

/* Store a relayed client's appearance, keyed by the userId reconstructed from
 * their username.  Session-only (in memory).  Also keyed under the configured
 * local g_userId when it's the local user (handles an overridden user id). */
static void SetUserAppearance(const std::string& username, const std::string& appearance)
{
    std::string uid = UserIdFromUsername(username);
    std::lock_guard<std::mutex> lk(g_avMutex);
    g_userAppearance[uid] = appearance;  g_avatarCache.erase(uid);
    if (username == g_username) { g_userAppearance[g_userId] = appearance; g_avatarCache.erase(g_userId); }
    Log("Avatar: stored appearance for '%s' (userId %s, %d chars)",
        username.c_str(), uid.c_str(), (int)appearance.size());
}

/* Read the local BodyColors\<part>Color.txt files (BrickColor names) next to
 * the DLL and format them as the "|COLORS|h;t;la;ra;ll;rl" trailer that
 * CompileAvatarJson understands. Empty string if none are present. */
static std::string ReadLocalBodyColorsTrailer()
{
    static const char* files[6] = {
        "HeadColor.txt", "TorsoColor.txt", "LeftArmColor.txt",
        "RightArmColor.txt", "LeftLegColor.txt", "RightLegColor.txt" };
    std::string vals[6]; bool any = false;
    for (int i = 0; i < 6; i++) {
        std::string v = ReadFile(DllPath((std::string("BodyColors\\") + files[i]).c_str()));
        if (v.empty()) v = ReadFile(DllPath((std::string("Settings\\BodyColors\\") + files[i]).c_str()));
        while (!v.empty() && (v.back()=='\r'||v.back()=='\n'||v.back()==' '||v.back()=='\t')) v.pop_back();
        vals[i] = v; if (!v.empty()) any = true;
    }
    if (!any) return "";
    return "|COLORS|" + vals[0] + ";" + vals[1] + ";" + vals[2] + ";" +
           vals[3] + ";" + vals[4] + ";" + vals[5];
}

/* Build the /v1/avatar-fetch response for a specific userId. */
static std::string AvatarFetchJson(const std::string& placeId, const std::string& userId)
{
    std::string rig = ResolveAvatarType(placeId);

    /* cached compiled JSON? */
    {
        std::lock_guard<std::mutex> lk(g_avMutex);
        std::map<std::string,std::string>::iterator c = g_avatarCache.find(userId);
        if (c != g_avatarCache.end()) return c->second;
    }

    /* find this user's raw appearance: relayed store, else Appearence.ini for
     * the local user, else nothing. */
    std::string raw;
    {
        std::lock_guard<std::mutex> lk(g_avMutex);
        std::map<std::string,std::string>::iterator a = g_userAppearance.find(userId);
        if (a != g_userAppearance.end()) raw = a->second;
    }
    if (raw.empty() && (userId.empty() || userId == g_userId)) {
        raw = ReadFile(DllPath("Appearence.ini"));
        if (raw.empty()) raw = ReadFile(DllPath("Appearance.ini"));
        if (raw.empty()) raw = ReadFile(DllPath("Settings\\Appearence.ini"));
        /* No relayed colors on this local fallback -> use the local BodyColors. */
        if (!raw.empty() && raw.find("|COLORS|") == std::string::npos)
            raw += ReadLocalBodyColorsTrailer();
    }

    std::string json;
    bool complete = true;
    if (!raw.empty()) {
        json = CompileAvatarJson(rig, raw, &complete);  /* may block on asset fetches */
    } else {
        /* No appearance known -> minimal default (blocky R15). */
        json = "{\"resolvedAvatarType\":\"" + rig + "\","
            "\"equippedGearVersionIds\":[],\"backpackGearVersionIds\":[],"
            "\"assetAndAssetTypeIds\":[],\"animationAssetIds\":{},"
            "\"bodyColor3s\":{\"headColor3\":\"A3A2A5\",\"torsoColor3\":\"A3A2A5\","
            "\"rightArmColor3\":\"A3A2A5\",\"leftArmColor3\":\"A3A2A5\","
            "\"rightLegColor3\":\"A3A2A5\",\"leftLegColor3\":\"A3A2A5\"},"
            "\"scales\":{\"height\":1.0,\"width\":1.0,\"head\":1.0,\"depth\":1.0,"
            "\"proportion\":0.0,\"bodyType\":0.0},\"emotes\":[]}";
    }
    /* Only cache a result that fully resolved. If some asset types couldn't be
     * resolved (e.g. a transient fetch failure), leave it uncached so the next
     * request retries instead of locking in a half-loaded avatar. */
    if (complete) {
        std::lock_guard<std::mutex> lk(g_avMutex);
        g_avatarCache[userId] = json;
    }
    return json;
}

static Resp Route(const Req& req)
{
    const std::string& P = req.path;
    const std::string  M = req.method;

    /* ---- CORS preflight ---- */
    if (M == "OPTIONS") {
        Resp r; r.status=204; r.statusText="No Content";
        r.contentType="text/plain"; r.body=""; return r;
    }

    /* ---- Log every request except /ping (watchdog polls it constantly) ---- */
    if (P != "/ping" && !STARTS(P, "/ping")) {
        if (req.query.empty())
            Log(">> %s %s", M.c_str(), P.c_str());
        else
            Log(">> %s %s?%s", M.c_str(), P.c_str(), req.query.c_str());
    }

    /* ---- Root / health ---- */
    if (P == "/" || P.empty())
        return RHtml("<center><h2>HookedWebserver running</h2></center>");
    if (P == "/ping" || STARTS(P,"/ping"))
        return RText("OK");
    if (P == "/validate" || STARTS(P,"/validate/"))
        return RText("true");

    /* ---- OffBlox: relayed avatar appearance ----
     * The host-side RobloxStudioPatcher POSTs each joining client's appearance
     * here (received over the magic packet). Body = the raw Appearence.ini
     * asset-list; ?username= identifies the client. We reconstruct their userId
     * (UserIdFromUsername) and stash the appearance in memory for avatar-fetch. */
    if (STARTS(P,"/offblox/appearance")) {
        std::string uname = QS(req,"username");
        if (!uname.empty() && !req.body.empty()) {
            SetUserAppearance(uname, req.body);
            return RJson("{\"ok\":true}");
        }
        return RJson("{\"ok\":false,\"error\":\"need ?username and a body\"}", 400);
    }
    if (P == "/info" || STARTS(P,"/info/"))
        return RJson("{\"role\":\"server\",\"dll\":\"HookedWebserver\","
                     "\"version\":\"1.0\",\"isServer\":true}");
    if (STARTS(P,"/protocol-handler-launch"))
        return RText("true");

    /* ---- PointsService (GetUserPointBalanceInUniverse / GetPointBalance /
            GetGamePointBalance / AwardPoints) ----------------------------------
       PointsService uses /v1/universes/{universeId}/users/{userId}/... :
           GET  /v1/universes/{u}/users/{user}/all-time   GetUserPointBalanceInUniverse
           POST /v1/universes/{u}/users/{user}/           AwardPoints
       The engine parses the JSON response into an unordered_map and then does
       map.at("userTotalBalance") / map.at("userBalanceInGame") / etc.  If those
       keys are missing it throws std::out_of_range, which Studio surfaces as:
           ... failed because invalid unordered_map<K, T> key
       Without this stub these requests fall through to the generic
       /v1/universes/{id} handler, which returns the universe object (no balance
       fields) -> the map lookup throws.  We match ANY /v1/universes/.../users/...
       path (both the GET balance and the POST award) and answer with a JSON
       object holding every field any of the point methods read; extra keys are
       harmless.  Balances are stubbed at 0. */
    {
        std::string lp = ToLower(P);
        bool isPoints = STARTS(lp,"/v1/universes/")
                        && lp.find("/users/") != std::string::npos;
        if (isPoints || lp.find("point") != std::string::npos) {
            Log("PointsService stub hit: %s %s", M.c_str(), P.c_str());
            return RJson("{\"userTotalBalance\":0,\"userBalanceInGame\":0,"
                         "\"pointsAwarded\":0,\"allTimeScore\":0}");
        }
    }

    /* ---- TeamCreate status — force-disabled, in the EXACT shapes the engine
            parses --------------------------------------------------------------
       THE "Loading game (attempt #N)" BUG (only after creating a NEW place):
       After publishing a brand-new place, Studio flips the open document into
       TeamCreate / cloud-edit mode and shows the TeamCreate connect dialog
       (localization key Studio.App.TeamCreate.LoadingGameWithAttemptCount1),
       then loops forever trying to reach a TeamCreate RCC that doesn't exist
       locally.  Studio decides TC state from these endpoints, and its parsers
       read SPECIFIC fields:
         - per-universe settings  GET /v1/universes/{id}/teamcreate
              -> {isActivating,isArchived,teamCreateEnabled,activeUsersCount,activeUsers}
         - multiget               GET /v1/universes/multiget/teamcreate?ids=...
              -> {data:[{universeId,isEnabled}]}
       The old reply was {"isEnabled":false} for everything — the wrong shape,
       so the engine never actually saw teamCreateEnabled=false and stayed in
       the connect loop.  Answer every teamcreate path with the correct shape
       and TC disabled, which makes Studio drop cloud-edit and open locally. */
    {
        std::string lp = ToLower(P);
        if (lp.find("teamcreate")  != std::string::npos ||
            lp.find("team-create") != std::string::npos) {
            Log("TeamCreate stub (disabled): %s %s", M.c_str(), P.c_str());

            /* active session / member / user lists -> empty */
            if (lp.find("active_session") != std::string::npos ||
                lp.find("/members")       != std::string::npos ||
                lp.find("/sessions")      != std::string::npos)
                return RJson("{\"data\":[]}");

            /* multiget -> one entry per requested id, all disabled.
             * Studio reads ids from the query as ?ids=A&ids=B&...  (ParseQS
             * keeps only the last one, so walk the raw query string here). */
            if (lp.find("multiget") != std::string::npos) {
                std::string out = "{\"data\":[";
                const std::string& q = req.query;
                bool first = true; size_t pos = 0;
                while ((pos = q.find("ids=", pos)) != std::string::npos) {
                    pos += 4;
                    size_t e = q.find('&', pos);
                    std::string id = (e==std::string::npos) ? q.substr(pos)
                                                            : q.substr(pos, e-pos);
                    if (!id.empty()) {
                        if (!first) out += ",";
                        out += "{\"universeId\":" + id +
                               ",\"isEnabled\":false,\"teamCreateEnabled\":false}";
                        first = false;
                    }
                    pos = (e==std::string::npos) ? q.size() : e;
                }
                out += "]}";
                return RJson(out);
            }

            /* per-universe / per-place TeamCreate settings -> disabled, full
             * shape so the engine's parser finds teamCreateEnabled=false. */
            return RJson("{\"isActivating\":false,\"isArchived\":false,"
                         "\"teamCreateEnabled\":false,\"isEnabled\":false,"
                         "\"activeUsersCount\":0,\"activeUsers\":[]}");
        }
    }

    /* ---- Asset permissions (asset-permissions-api) ------------------------
       THE "Overwrite existing game hangs forever" BUG.
       When you pick an existing game and hit Overwrite, Studio first POSTs:
         POST /asset-permissions-api/v1/assets/check-permissions
         body: {"requests":[{"action":"Edit","subjectType":"User",
                             "subjectId":"<uid>","assetId":<placeId>}]}
       and BLOCKS until it gets a grant.  Studio parses an array of
       {assetId, action, status} where status must be "HasPermission"
       (other values: "NoPermission","AssetNotFound").  With no handler the
       request fell through to asset delivery and 400'd ("Missing id"), so the
       publish sat there forever.  We grant permission by echoing every object
       in the request array back with "status":"HasPermission" added, so the
       assetId/action/subject fields line up with what Studio asked for. */
    if (P.find("/asset-permissions-api") != std::string::npos) {
        if (P.find("check-permissions") != std::string::npos ||
            P.find("check-actions")     != std::string::npos) {
            /* Body is already gunzipped by ParseHttp if it arrived gzip-encoded. */
            const std::string& b = req.body;
            /* Iterate the request objects inside the first [...] array and copy
             * each one, injecting status:"HasPermission" before its closing }. */
            std::string out = "{\"results\":[";
            bool first = true;
            size_t arr  = b.find('[');
            size_t aEnd = b.rfind(']');
            if (arr != std::string::npos && aEnd != std::string::npos && aEnd > arr) {
                size_t i = arr + 1;
                while (i < aEnd) {
                    if (b[i] != '{') { i++; continue; }
                    /* find matching close brace (respect strings/escapes) */
                    int depth = 0; bool inStr = false; size_t start = i, j = i;
                    for (; j < aEnd; j++) {
                        char c = b[j];
                        if (inStr) { if (c == '"' && b[j-1] != '\\') inStr = false; }
                        else if (c == '"') inStr = true;
                        else if (c == '{') depth++;
                        else if (c == '}') { depth--; if (depth == 0) { j++; break; } }
                    }
                    std::string obj = b.substr(start, j - start);   /* {...} */
                    size_t close = obj.rfind('}');
                    if (close != std::string::npos) {
                        std::string inner = obj.substr(0, close);
                        /* avoid double-comma for an empty object {} */
                        bool hasField = inner.find(':') != std::string::npos;
                        if (!first) out += ",";
                        out += inner;
                        out += hasField ? ",\"status\":\"HasPermission\"}"
                                        : "\"status\":\"HasPermission\"}";
                        first = false;
                    }
                    i = j;
                }
            }
            out += "]}";
            if (first) {            /* no per-asset objects parsed — grant nothing-to-check */
                Log("asset-permissions check (empty/grant-all): %s body=[%s] querystring=[%s]",
                    P.c_str(), req.body.c_str(), req.query.c_str());
                for (std::map<std::string,std::string>::const_iterator it = req.headers.begin();
                     it != req.headers.end(); ++it)
                    Log("  asset-perms Header [%s]: %s", it->first.c_str(), it->second.c_str());
                return RJson("{\"results\":[]}");
            }
            Log("asset-permissions check granted: %s", P.c_str());
            return RJson(out);
        }
        /* Any other asset-permissions path (e.g. /assets/{id}/permissions) -> ok */
        return RJson("{\"results\":[],\"data\":[]}");
    }

    /* ---- OpenID discovery (queried by AuthTokenManager at startup) ---- */
    if (STARTS(P,"/.well-known"))
        return RJson(OPENID_DISCOVERY);

    /* ---- Feature flags ---- */
    if (STARTS(P,"/fflags"))
        return RJson(FFLAGS);

    /* ---- Currency (top-level) ---- */
    if (STARTS(P,"/currency"))
        return RJson("{\"robux\":9999999999}");

    /* ---- /places/{id}/settings (Studio "place settings" / entity settings;
            CoreGui fetchExperienceName + Game Explorer load this) ---- */
    if (STARTS(P,"/places")) {
        /* Extract place ID from path: /places/{id}/settings or /places/{id} */
        std::string placeId;
        {
            size_t idStart = strlen("/places/");
            if (P.size() > idStart) {
                size_t idEnd = P.find('/', idStart);
                placeId = (idEnd == std::string::npos) ? P.substr(idStart) : P.substr(idStart, idEnd - idStart);
            }
        }
        /* Try to find the universe that owns this place */
        if (!placeId.empty()) {
            /* 1. Try direct universe JSON (placeId == universeId) */
            std::string saved;
            bool found = LoadUniverseJson(placeId, saved);
            /* 2. Try finding by rootPlaceId */
            if (!found) {
                std::string dir2 = UniversesDir();
                WIN32_FIND_DATAA fd2;
                HANDLE hf2 = FindFirstFileA((dir2 + "*.json").c_str(), &fd2);
                if (hf2 != INVALID_HANDLE_VALUE) {
                    do {
                        if (fd2.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
                        std::string raw2 = ReadFile(dir2 + fd2.cFileName);
                        if (raw2.empty()) continue;
                        if (CfgStr(raw2, "rootPlaceId") == placeId) { saved = raw2; found = true; break; }
                    } while (FindNextFileA(hf2, &fd2));
                    FindClose(hf2);
                }
            }
            if (found && !saved.empty()) {
                std::string uid3    = CfgStr(saved, "universeId");
                std::string rpid3   = CfgStr(saved, "rootPlaceId");
                std::string uname3  = CfgStr(saved, "name");
                if (uid3.empty())  uid3  = placeId;
                if (rpid3.empty()) rpid3 = placeId;
                if (uname3.empty()) uname3 = "Local Place";
                char buf[1536]; _snprintf(buf,sizeof(buf)-1,
                    "{\"id\":%s,\"placeId\":%s,\"Id\":%s,\"PlaceId\":%s,\"TargetId\":%s,"
                    "\"rootPlaceId\":%s,\"RootPlaceId\":%s,\"universeRootPlaceId\":%s,"
                    "\"universeId\":%s,\"UniverseId\":%s,\"placeVersion\":1,"
                    "\"name\":\"%s\",\"description\":\"\",\"isActive\":true,\"isAllGenresAllowed\":true,"
                    "\"genre\":\"All\",\"maxPlayerCount\":50,\"allowCopying\":false,"
                    "\"currentSavedVersion\":1,\"isStudioAccessToApisAllowed\":true,"
                    "\"playableDevices\":[\"Computer\",\"Phone\",\"Tablet\"],"
                    "\"socialSlotType\":\"Automatic\",\"customSocialSlotsCount\":null,"
                    "\"createVipServersAllowed\":false,\"creatorType\":\"User\","
                    "\"creatorTargetId\":%s,\"creatorName\":\"%s\"}",
                    rpid3.c_str(), rpid3.c_str(), rpid3.c_str(), rpid3.c_str(), rpid3.c_str(),
                    rpid3.c_str(), rpid3.c_str(), rpid3.c_str(),
                    uid3.c_str(), uid3.c_str(),
                    uname3.c_str(),
                    g_userId.c_str(), g_username.c_str());
                return RJson(buf);
            }
        }
        /* Fallback: hardcoded Baseplate — NOT owned by the local player */
        return RJson("{\"id\":9991912465,\"placeId\":9991912465,\"universeId\":9991912465,\"name\":\"Baseplate\","
            "\"description\":\"\",\"isActive\":true,\"isAllGenresAllowed\":true,"
            "\"genre\":\"All\",\"maxPlayerCount\":50,\"allowCopying\":false,"
            "\"currentSavedVersion\":1,\"isStudioAccessToApisAllowed\":true,"
            "\"playableDevices\":[\"Computer\",\"Phone\",\"Tablet\"],"
            "\"socialSlotType\":\"Automatic\",\"customSocialSlotsCount\":null,"
            "\"createVipServersAllowed\":false,\"creatorType\":\"User\","
            "\"creatorTargetId\":998796,\"creatorName\":\"Roblox\"}");
    }

    /* ---- Legacy datastore ---- */
    if (STARTS(P,"/datastore")) {
        if (P.find(".php") != std::string::npos)
            return HandleLuaDatastore(req);
        return HandleDatastore(req);
    }

    if (STARTS(P,"/universes/v1/universes/create")){
        /* Log the full request so we can see exactly what Studio sends */
        Log("Universe create: method=%s body=[%s]", M.c_str(), req.body.c_str());
        for (auto it = req.headers.begin(); it != req.headers.end(); ++it)
            Log("  Header [%s]: %s", it->first.c_str(), it->second.c_str());
        Log("  QueryString: %s", req.query.c_str());

        std::string uid  = AllocUniverseId();
        /* rootPlaceId = universeId + 1 (stays within JS safe-integer range) */
        long long uidNum = atoll(uid.c_str());
        char rpidBuf[32]; sprintf(rpidBuf, "%lld", uidNum + 1);
        std::string rpidStr = rpidBuf;

        /* Grab name from POST body - try every field name Studio might use */
        std::string placeName = CfgStr(req.body, "name");
        if (placeName.empty()) placeName = CfgStr(req.body, "gameName");
        if (placeName.empty()) placeName = CfgStr(req.body, "universeName");
        if (placeName.empty()) placeName = CfgStr(req.body, "title");
        if (placeName.empty()) placeName = QS(req, "name");
        if (placeName.empty()) placeName = QS(req, "gameName");
        if (placeName.empty()) placeName = "Untitled Place";

        /* Grab description similarly */
        std::string placeDesc = CfgStr(req.body, "description");
        if (placeDesc.empty()) placeDesc = CfgStr(req.body, "gameDescription");
        if (placeDesc.empty()) placeDesc = QS(req, "description");
        /* escape stray quotes/backslashes to keep JSON valid */
        for (size_t qi = 0; qi < placeDesc.size(); qi++)
            if (placeDesc[qi] == '"' || placeDesc[qi] == '\\') { placeDesc.insert(qi, 1, '\\'); qi++; }
        for (size_t qi = 0; qi < placeName.size(); qi++)
            if (placeName[qi] == '"' || placeName[qi] == '\\') { placeName.insert(qi, 1, '\\'); qi++; }

        char json[1024];
        _snprintf(json, sizeof(json)-1,
            "{"
            "\"id\":%s,"
            "\"universeId\":%s,"
            "\"rootPlaceId\":%s,"
            "\"name\":\"%s\","
            "\"description\":\"%s\","
            "\"isArchived\":false,"
            "\"isActive\":true,"
            "\"privacyType\":\"Private\","
            "\"creatorType\":\"User\","
            "\"creatorTargetId\":%s,"
            "\"creatorName\":\"%s\","
            "\"price\":0,"
            "\"playing\":0,"
            "\"visits\":0,"
            "\"maxPlayers\":10,"
            "\"studioAccessToApisAllowed\":true,"
            "\"genre\":\"All\","
            "\"isAllGenre\":true,"
            "\"isFavoritedByUser\":false,"
            "\"favoritedCount\":0,"
            "\"created\":\"2022-05-11T13:27:09.897Z\","
            "\"updated\":\"2022-05-11T13:27:09.897Z\""
            "}",
            uid.c_str(), uid.c_str(), rpidStr.c_str(), placeName.c_str(), placeDesc.c_str(),
            g_userId.c_str(), g_username.c_str());
        SaveUniverseJson(uid, json);
        return RJson(json);
    }



    /* ---- /ide/places/*  (create-as-new publish flow) ---- *
     *
     * POST /ide/places/createV2?templatePlaceIdToUse=X&universeId=Y
     *   Studio reads placeId from this response to know where to upload.
     *   Without a 200 it dereferences a null placeId and crashes.
     *
     * POST /ide/places/{id}/updatesettings  — just acknowledge
     * GET  /ide/places/defaultsettings       — default place settings
     */
    if (STARTS(P,"/ide/places")) {
        if (P.find("createV2") != std::string::npos) {
            /* Studio sends universeId= in the query string — look up the rootPlaceId
             * from the saved universe JSON and return that.  Fall back to allocating
             * a fresh ID only if we have no record for this universe. */
            std::string univId = QS(req,"universeId");
            if (!univId.empty()) {
                std::string saved;
                if (LoadUniverseJson(univId, saved)) {
                    std::string rpid = CfgStr(saved, "rootPlaceId");
                    if (!rpid.empty()) {
                        char buf[64]; _snprintf(buf,sizeof(buf)-1,"{\"placeId\":%s}",rpid.c_str());
                        return RJson(buf);
                    }
                }
                /* Universe known but no place file yet — derive rootPlaceId the same way
                 * AllocUniverseId does: universeId + 1 */
                long long uid2 = atoll(univId.c_str());
                if (uid2 >= LOCAL_ID_BASE) {
                    char buf[64]; _snprintf(buf,sizeof(buf)-1,"{\"placeId\":%lld}",uid2+1);
                    return RJson(buf);
                }
            }
            /* No universe context — fall back to the default test place */
            return RJson("{\"placeId\":9991912465}");
        }
        if (P.find("updatesettings") != std::string::npos) {
            Log("updatesettings body=[%s] query=[%s]", req.body.c_str(), req.query.c_str());
            for (auto it = req.headers.begin(); it != req.headers.end(); ++it)
                Log("  updatesettings Header [%s]: %s", it->first.c_str(), it->second.c_str());
            /* Find universe by placeId and persist name/description */
            {
                size_t a = P.find("/ide/places/");
                if (a != std::string::npos) {
                    a += 12;
                    size_t b = P.find('/', a);
                    std::string pid2 = (b==std::string::npos)?P.substr(a):P.substr(a,b-a);
                    /* find universe owning this place */
                    std::string uid2 = pid2;
                    std::string ts2; bool found2 = LoadUniverseJson(uid2,ts2);
                    if (!found2) {
                        std::string dir2=UniversesDir(); WIN32_FIND_DATAA fd2;
                        HANDLE hf2=FindFirstFileA((dir2+"*.json").c_str(),&fd2);
                        if (hf2!=INVALID_HANDLE_VALUE) {
                            do {
                                if (fd2.dwFileAttributes&FILE_ATTRIBUTE_DIRECTORY) continue;
                                std::string r2=ReadFile(dir2+fd2.cFileName);
                                if (CfgStr(r2,"rootPlaceId")==pid2) {
                                    std::string fn2=fd2.cFileName;
                                    uid2=fn2.substr(0,fn2.size()-5); found2=true; break;
                                }
                            } while (FindNextFileA(hf2,&fd2));
                            FindClose(hf2);
                        }
                    }
                    if (found2) {
                        std::string nm2=CfgStr(req.body,"name");
                        if (nm2.empty()) nm2=CfgStr(req.body,"Name");
                        std::string ds2=CfgStr(req.body,"description");
                        if (ds2.empty()) ds2=CfgStr(req.body,"Description");
                        if (!nm2.empty()) UpdateUniverseField(uid2,"name",nm2);
                        if (!ds2.empty()) UpdateUniverseField(uid2,"description",ds2);
                    }
                }
            }
            return RJson("{\"success\":true}");
        }
        if (P.find("defaultsettings") != std::string::npos)
            return RJson("{\"maxPlayerCount\":50,\"allowCopying\":false,"
                         "\"socialSlotType\":\"Automatic\","
                         "\"customSocialSlotsCount\":null}");
        return RJson("{\"success\":true}");
    }

    /* ---- /persistence/* (legacy non-cloud persistence) ---- */
    if (STARTS(P,"/persistence")) {
        std::string sub = P.substr(12);
        /* get-versioned-value / set-versioned-value / increment-versioned-value /
           remove-versioned-value / sorted-list */
        if (STARTS(sub,"/increment-versioned-value")) {
            std::string scope=QS(req,"scope","u"),key=QS(req,"key");
            std::string dir=DllPath("data\\persistence\\"); EnsureDir(dir);
            std::string file=dir+UrlEncode(scope)+"_"+UrlEncode(key)+".json";
            DsRec rec; if(!DsRead(file,rec)){ rec.value="0"; rec.version=0; }
            long long val=0;
            try{ val=std::stoll(rec.value); } catch(...){}
            std::string incStr=QS(req,"value","1");
            long long inc=0; try{ inc=std::stoll(incStr); } catch(...){}
            val+=inc;
            char vbuf[64]; _snprintf(vbuf,sizeof(vbuf)-1,"%lld",val);
            DsWrite(file,std::string(vbuf),rec.version+1,"");
            return RText(std::string(vbuf));
        }
        if (STARTS(sub,"/remove-versioned-value")) {
            std::string scope=QS(req,"scope","u"),key=QS(req,"key");
            std::string dir=DllPath("data\\persistence\\");
            std::string file=dir+UrlEncode(scope)+"_"+UrlEncode(key)+".json";
            DeleteFileA(file.c_str());
            return RText("");
        }
        if (STARTS(sub,"/sorted-list"))
            return RJson("{\"data\":[]}");
        /* get-versioned-value and set-versioned-value */
        return HandlePersistence(req, M);
    }

    /* ---- /game/* ---- */
    if (STARTS(P,"/game")) {
        std::string sub = P.substr(5);
        if (STARTS(sub,"/Join.ashx") || STARTS(sub,"/join") || STARTS(sub,"/newjoin"))
            return HandleJoin(req);
        if (STARTS(sub,"/placelauncher.ashx") || STARTS(sub,"/start-launcher.ashx") ||
            STARTS(sub,"/startlauncher.ashx") || STARTS(sub,"/startlauncher/"))
            return HandlePlaceLauncher(req);
        if (STARTS(sub,"/load-place-info"))
            return RJson("{\"CreatorId\":1,\"CreatorType\":\"User\",\"PlaceVersion\":1,"
                         "\"GameId\":9991912465,\"IsRobloxPlace\":true,"
                         "\"StudioAccessToApisAllowed\":true}");
        if (STARTS(sub,"/global.ashx"))
            return HandleGlobal(req);
        if (STARTS(sub,"/LuaWebService")) {
            std::string m = QS(req,"method");
            if (m=="IsFriendsWith"||m=="IsBestFriendsWith") return RText("true");
            if (m=="IsInGroup")   return RText("false");
            if (m=="GetGroupRank") return RText("0");
            return RText("Guest");
        }
        if (STARTS(sub,"/Start-RCCService"))
            return RText("Started RCCService at 127.0.0.1|53640.");
        if (STARTS(sub,"/studio.ashx") || STARTS(sub,"/oldstudio.ashx"))
            return HandleStudioAshx(req);
        if (STARTS(sub,"/host.lua") || STARTS(sub,"/join.lua")) {
            std::string data = ReadFile(DllPath("www\\game\\join.lua"));
            return data.empty() ? RText("") : RText(data);
        }
        if (STARTS(sub,"/players/"))
            return RJson("{\"success\":true}");
        return RJson("{\"success\":true}");
    }

    /* ---- OAuth ---- */
    if (STARTS(P,"/oauth"))
        return HandleOAuth(P.substr(6), req);

    /* ---- /my/settings/json (lowercase, queried by Studio on startup) ---- */
    if (ToLower(P).find("/my/settings") != std::string::npos)
        return RJson(J("{\"UserId\":{I},\"UserName\":\"{U}\","
            "\"DisplayName\":\"{U}\",\"RobuxBalance\":9999999999,"
            "\"IsEmailVerified\":true,\"IsPremiumUser\":true,"
            "\"AgeBracket\":0,\"CountryCode\":\"US\","
            "\"Roles\":[\"Developer\",\"Soothsayer\"],"
            "\"AccountAgeInDays\":1324354}"));

    /* ---- /My/* and /my/* ---- */
    if (STARTS(P,"/My") || STARTS(P,"/my")) {
        std::string sub = P.substr(3);
        std::string subL = ToLower(sub);
        if (STARTS(subL,"/accountinfo"))
            return RJson(J("{\"UserId\":{I},\"UserName\":\"{U}\","
                           "\"RobuxBalance\":9999999999,\"IsEmailVerified\":true,"
                           "\"AgeBracket\":0,\"Roles\":[\"Developer\"]}"));
        if (STARTS(subL,"/getauthenticationticket"))
            return RJson("{\"authenticationTicket\":\"hardcoded_auth_ticket_2023\"}");
        /* /My/ root — current user info */
        return RJson(J("{\"UserId\":{I},\"UserName\":\"{U}\","
            "\"DisplayName\":\"{U}\",\"RobuxBalance\":9999999999,"
            "\"ThumbnailUrl\":\"http://localhost/Thumbs/Avatar.ashx\","
            "\"IsEmailVerified\":true,\"IsPremiumUser\":true,"
            "\"AgeBracket\":0,\"CountryCode\":\"US\"}"));
    }

    /* ---- /Login/* ---- */
    if (STARTS(P,"/Login"))
        return RJson("{\"success\":true}");

    /* ---- /Setting/* ---- */
    if (STARTS(P,"/Setting")) {
        /* ClientAppSettings / ClientSharedSettings — return fflags wrapped in applicationSettings */
        if (P.find("ClientAppSettings")!=std::string::npos ||
            P.find("ClientSharedSettings")!=std::string::npos) {
            /* Return all fflags wrapped in the applicationSettings envelope */
            std::string body = "{\"applicationSettings\":";
            body += FFLAGS;
            body += "}";
            return RJson(body.c_str());
        }
        return RJson("{\"applicationSettings\":{}}");
    }

    /* ---- Thumbnails ---- */
    if (STARTS(P,"/avatar-thumbnail")) {
        std::string data = ReadFile(DllPath("www\\avatar-thumbnail\\image\\img.png"));
        if (!data.empty()) {
            Resp r; r.status=200; r.statusText="OK";
            r.contentType="image/png"; r.body=data; return r;
        }
        return RText("");
    }
    if (STARTS(P,"/Thumbs")) {
        /* Try to serve the img.png for any thumbnail request */
        std::string imgPath;
        if (P.find("Avatar")!=std::string::npos)
            imgPath = DllPath("www\\Thumbs\\Avatar.ashx\\img.png");
        else if (P.find("gameicon")!=std::string::npos || P.find("Asset")!=std::string::npos)
            imgPath = DllPath("www\\Thumbs\\gameicon.ashx\\img.png");
        else
            imgPath = DllPath("www\\Thumbs\\Asset.ashx\\img.png");
        std::string data = ReadFile(imgPath);
        if (!data.empty()) {
            Resp r; r.status=200; r.statusText="OK";
            r.contentType="image/png"; r.body=data; return r;
        }
        return RText("");
    }
    if (STARTS(P,"/asset-thumbnail"))
        return RJson("{\"Url\":\"http://localhost/Thumbs/gameicon.ashx\","
                     "\"Final\":true,\"SubstitutionType\":0}");

    /* ---- /version ---- */
    if (STARTS(P,"/version"))
        return RJson(VERSION_JSON);

    /* ---- /ownership & /marketplace ---- */
    if (STARTS(P,"/ownership"))
        return RText("true");
    if (STARTS(P,"/marketplace")) {
        std::string sub = P.substr(12);
        if (STARTS(sub,"/purchase") || STARTS(sub,"/submitpurchase"))
            return RJson("{\"success\":true,\"status\":\"AlreadyOwned\"}");
        if (STARTS(sub,"/validatepurchase"))
            return RJson("{\"success\":true}");
        if (STARTS(sub,"/ownership") || STARTS(sub,"/productDetails"))
            return RText("true");
        /* productinfo / game-pass-product-info */
        std::string aid = QS(req,"assetId");
        if (aid.empty()) aid = QS(req,"assetid");
        if (aid.empty()) aid = "93722443";
        char buf[512];
        _snprintf(buf,sizeof(buf)-1,
            "{\"AssetId\":%s,\"ProductId\":13831621,\"Name\":\"place.rbxl\","
            "\"AssetTypeId\":19,\"Creator\":{\"Id\":1,\"Name\":\"ROBLOX\","
            "\"CreatorType\":\"User\",\"CreatorTargetId\":1},"
            "\"PriceInRobux\":null,\"IsForSale\":true,"
            "\"IsPublicDomain\":false,\"IsLimited\":false,"
            "\"MinimumMembershipLevel\":0}",aid.c_str());
        return RJson(buf);
    }

    /* ---- /moderation ---- */
    if (STARTS(P,"/moderation")) {
        /* echo text back (filtertext) */
        std::string text = QS(req,"text");
        if (text.empty()) {
            /* try POST body form field */
            text = QS(req,"text"); /* already checked */
            /* raw body as text if all else fails */
            if (text.empty()) text = req.body;
        }
        char buf[2048];
        _snprintf(buf,sizeof(buf)-1,
            "{\"success\":true,\"message\":\"\","
            "\"data\":{\"AgeUnder13\":\"%s\",\"Age13OrOver\":\"%s\"}}",
            text.c_str(), text.c_str());
        return RJson(buf);
    }

    /* ---- /device ---- */
    if (STARTS(P,"/device"))
        return RJson("{\"browserTrackerId\":1,\"appDeviceIdentifier\":1}");

    /* ---- /presence ---- */
    if (STARTS(P,"/presence"))
        return RJson("{\"userPresences\":[]}");

    /* ---- /timespent ---- */
    if (STARTS(P,"/timespent"))
        return RJson("{}");

    /* ---- /guac-v2 ---- */
    if (STARTS(P,"/guac-v2"))
        return RJson("{\"version\":\"1\",\"bundle\":"
            "{\"name\":\"studio\",\"configurations\":{},\"experiments\":{}}}");

    /* ---- /ecsv2 / analytics beacon ---- */
    if (STARTS(P,"/ecsv2") || STARTS(P,"/ecsv3"))
        return RText("OK");

    /* ---- /game-auth ---- */
    if (STARTS(P,"/game-auth"))
        return RText("Guest:-538474545");

    /* ---- /asset / /Asset (top-level asset delivery) ---- */
    if (STARTS(P,"/asset") || STARTS(P,"/Asset")) {
        /* Batch sub-paths return empty arrays */
        if (P.find("/batch")!=std::string::npos ||
            P.find("/Batch")!=std::string::npos)
            return RJson("{\"data\":[]}");
        /* AssetSaving — accept the POST silently */
        if (P.find("AssetSaving")!=std::string::npos ||
            P.find("assetsaving")!=std::string::npos)
            return RJson("{\"success\":true}");
        return HandleAssetDelivery(req);
    }

    /* ---- /universes/* (legacy non-versioned) ---- */
    if (STARTS(P,"/universes")) {
        std::string sub = P.substr(10);
        if (STARTS(sub,"/rc"))
            return RText("true");
        if (sub.find("/permissions") != std::string::npos) {
            /* Deny publish/manage for the hardcoded Baseplate universe so Studio
             * opens "Publish to new place" instead of overwriting it. */
            bool isBaseplate = (sub.find("9991912465") != std::string::npos);
            if (isBaseplate)
                return RJson("{\"canManage\":false,\"canCloudEdit\":false,\"canPublish\":false,\"canView\":true,\"isPublic\":true}");
            /* Team Create / cloud-edit disabled by default: canCloudEdit:false makes
               Studio open owned cloud places as a plain editable download (Save/Publish
               still work via canManage/canPublish) instead of a live cloud-edit session,
               which otherwise hangs at "Loading game (attempt #N)" with no edit RCC. */
            return RJson("{\"canManage\":true,\"canCloudEdit\":false,\"canPublish\":true,\"canView\":true,\"isPublic\":false}");
        }

        /* Helper: find a saved universe whose rootPlaceId equals pid */
        auto findByPlaceId = [](const std::string& pid) -> std::string {
            std::string dir = UniversesDir();
            WIN32_FIND_DATAA fd2; std::string found;
            HANDLE hf2 = FindFirstFileA((dir + "*.json").c_str(), &fd2);
            if (hf2 != INVALID_HANDLE_VALUE) {
                do {
                    if (fd2.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
                    std::string raw2 = ReadFile(dir + fd2.cFileName);
                    if (raw2.empty()) continue;
                    if (CfgStr(raw2, "rootPlaceId") == pid) { found = raw2; break; }
                } while (FindNextFileA(hf2, &fd2));
                FindClose(hf2);
            }
            return found;
        };

        if (STARTS(sub,"/get-universe-containing-place")) {
            std::string pid = QS(req,"placeId","9991912465");
            std::string found = findByPlaceId(pid);
            if (!found.empty()) return RJson(found);
            return RJson(UniverseJson());
        }
        if (STARTS(sub,"/get-info")) {
            std::string pid = QS(req,"placeId","9991912465");
            std::string saved;
            if (LoadUniverseJson(pid, saved)) return RJson(saved);
            std::string found = findByPlaceId(pid);
            if (!found.empty()) return RJson(found);
            /* Baseplate fallback — not owned by the local player */
            char buf[512];
            _snprintf(buf,sizeof(buf)-1,
                "{\"name\":\"Baseplate\",\"description\":\"\","
                "\"rootPlaceId\":%s,\"studioAccessToApisAllowed\":true,"
                "\"currentUserHasEditPermissions\":false,"
                "\"universeAvatarType\":\"MorphToR6\"}",pid.c_str());
            return RJson(buf);
        }
        /* /universes/v1/places/{placeId}/universe */
        if (sub.find("/places/") != std::string::npos) {
            size_t ps = sub.find("/places/") + 8;
            size_t pe = sub.find('/', ps);
            std::string pid = (pe == std::string::npos) ? sub.substr(ps) : sub.substr(ps, pe - ps);
            std::string found = findByPlaceId(pid);
            if (!found.empty()) return RJson(found);
            return RJson(UniverseJson());
        }
        /* /universes/v1/universes/{universeId} or similar */
        {
            size_t lastSlash = sub.rfind('/');
            if (lastSlash != std::string::npos) {
                std::string maybeId = sub.substr(lastSlash + 1);
                std::string saved;
                if (!maybeId.empty() && LoadUniverseJson(maybeId, saved)) return RJson(saved);
            }
        }
        return RJson(UniverseJson());
    }

    /* ---- /users/* (top-level non-versioned) ---- */
    if (STARTS(P,"/users")) {
        /* Accept any numeric user id in the path — always return our user */
        return RJson(J("{\"id\":{I},\"name\":\"{U}\",\"displayName\":\"{U}\"}"));
    }


    /* ---- /studio-login ---- */
    if (STARTS(P,"/studio-login"))
        return RJson(J("{\"user\":{\"AccountAgeInDays\":1324354,"
            "\"UserId\":{I},\"Username\":\"{U}\","
            "\"AgeBracket\":0,\"Roles\":[\"Soothsayer\",\"BetaTester\"],"
            "\"Email\":{\"value\":\"d****@dummy.com\",\"isVerified\":true},"
            "\"IsBanned\":false,\"DisplayName\":\"{U}\"},"
            "\"userAgreements\":[]}"));

    /* ---- /studio-open-place ---- */
    if (STARTS(P,"/studio-open-place")) {
        std::string pid = QS(req,"placeId");
        if (!pid.empty()) {
            /* Search for universe whose rootPlaceId matches */
            std::string dir3 = UniversesDir();
            WIN32_FIND_DATAA fd3;
            HANDLE hf3 = FindFirstFileA((dir3 + "*.json").c_str(), &fd3);
            std::string foundUni;
            if (hf3 != INVALID_HANDLE_VALUE) {
                do {
                    if (fd3.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
                    std::string raw3 = ReadFile(dir3 + fd3.cFileName);
                    if (raw3.empty()) continue;
                    if (CfgStr(raw3, "rootPlaceId") == pid) { foundUni = raw3; break; }
                } while (FindNextFileA(hf3, &fd3));
                FindClose(hf3);
            }
            if (!foundUni.empty()) {
                std::string uid3  = CfgStr(foundUni, "universeId");
                std::string rpid3 = CfgStr(foundUni, "rootPlaceId");
                std::string name3 = CfgStr(foundUni, "name");
                if (uid3.empty())  uid3  = pid;
                if (rpid3.empty()) rpid3 = pid;
                if (name3.empty()) name3 = "Local Place";
                char buf[1024]; _snprintf(buf,sizeof(buf)-1,
                    "{\"universe\":{\"Id\":%s,\"RootPlaceId\":%s,\"Name\":\"%s\","
                    "\"Description\":\"\",\"IsArchived\":false,"
                    "\"CreatorType\":\"User\",\"CreatorTargetId\":%s,"
                    "\"PrivacyType\":\"Private\","
                    "\"Created\":\"2022-01-01T00:00:00.000+00:00\","
                    "\"Updated\":\"2022-01-01T00:00:00.000+00:00\"},"
                    "\"teamCreateEnabled\":false,"
                    "\"place\":{\"Creator\":{\"CreatorType\":\"User\",\"CreatorTargetId\":%s}}}",
                    uid3.c_str(), rpid3.c_str(), name3.c_str(),
                    g_userId.c_str(), g_userId.c_str());
                return RJson(buf);
            }
        }
        /* Fallback: default hardcoded Baseplate universe */
        return RJson("{\"universe\":{\"Id\":3681567139,\"RootPlaceId\":9991912465,\"Name\":\"(SE) Baseplate\",\"Description\":\"Baseplate template with Streaming Enabled\",\"IsArchived\":false,\"CreatorType\":\"User\",\"CreatorTargetId\":998796,\"PrivacyType\":\"Public\",\"Created\":\"2022-06-22T17:23:30.077+00:00\",\"Updated\":\"2023-05-02T22:16:25.23+00:00\"},\"teamCreateEnabled\":false,\"place\":{\"Creator\":{\"CreatorType\":\"User\",\"CreatorTargetId\":998796}}}");
    }

    /* ---- /client/pbe  (product-based entitlement beacon) ---- */
    if (STARTS(P,"/client"))
        return RJson("{}");

    /* ---- /rcc/pbe  (RCC service beacon) ---- */
    if (STARTS(P,"/rcc"))
        return RJson("{}");

    /* ---- /studio/* ---- */
    if (STARTS(P,"/studio")) {
        if (P.find("e.png")!=std::string::npos) {
            std::string data = ReadFile(DllPath("www\\studio\\e.png\\img.png"));
            if (!data.empty()) {
                Resp r; r.status=200; r.statusText="OK";
                r.contentType="image/png"; r.body=data; return r;
            }
        }
        return RJson("{}");
    }

    /* ---- /scripts/* ---- */
    if (STARTS(P,"/scripts"))
        return RText("");

    /* ---- /universal-app-configuration ---- */
    if (STARTS(P,"/universal-app-configuration")) {
        if (P.find("/app-policy")!=std::string::npos)
            return RJson("{\"ChatConversationHeaderGroupDetails\":true,"
    "\"ShowDisplayName\":true,\"GamesDropDownList\":true,"
    "\"GameDetailsMorePage\":true,\"Notifications\":true,"
    "\"SearchBar\":true,\"SocialLinks\":true,"
    "\"UseLuobuAuthentication\":true,"
    "\"CheckUserAgreementsUpdatedOnLogin\":true,"
    "\"UseOmniRecommendation\":true,"
    "\"IsEmotesEnabled\":true}");
        if (P.find("/cookie-policy")!=std::string::npos)
            return RJson("{\"ShouldCallEvidon\":false,"
                "\"ShouldDisplayCookieBannerV3\":false,"
                "\"NonEssentialCookieList\":[],"
                "\"EssentialCookieList\":[]}");
        if (P.find("/app-patch")!=std::string::npos)
            return RJson("{\"SchemaVersion\":\"1\","
                "\"CanaryUserIds\":[],\"CanaryPercentage\":0}");
        /* studio / play-button-ui / robux-product-policy / intl-auth-compliance */
        return RJson("{}");
    }

    /* ---- /product-experimentation-platform ---- */
    if (STARTS(P,"/product-experimentation-platform"))
        return RJson("{\"assignments\":[]}");

    /* ---- /v2/* ---- */
    if (STARTS(P,"/v2")) {
        std::string sub = P.substr(3);
        if (P.find("/avatar-fetch")!=std::string::npos ||
            P.find("/aavatar-fetch")!=std::string::npos)
            return RJson(AvatarFetchJson(QS(req,"placeId"), QS(req,"userId")));
        if (STARTS(sub,"/client-version"))
            return RJson(VERSION_JSON);
        if (STARTS(sub,"/persistence"))
            return HandleOpenCloudDs(req);
        if (STARTS(sub,"/settings"))
            return RJson("{\"applicationSettings\":{}}");
        if (STARTS(sub,"/universes")) {
            /* Extract universe ID: /v2/universes/{id}/... */
            std::string univId2;
            {
                size_t idStart = strlen("/universes/");
                if (sub.size() > idStart) {
                    size_t idEnd = sub.find('/', idStart);
                    univId2 = (idEnd == std::string::npos) ? sub.substr(idStart) : sub.substr(idStart, idEnd - idStart);
                }
            }
            if (P.find("/places")!=std::string::npos) {
                std::string saved;
                if (!univId2.empty() && LoadUniverseJson(univId2, saved)) {
                    std::string rpid = CfgStr(saved, "rootPlaceId");
                    std::string uname = CfgStr(saved, "name");
                    char buf[512]; _snprintf(buf,sizeof(buf)-1,
                        "{\"previousPageCursor\":null,\"nextPageCursor\":null,"
                        "\"data\":[{\"id\":%s,\"universeId\":%s,\"name\":\"%s\",\"description\":\"\"}]}",
                        rpid.c_str(), univId2.c_str(), uname.c_str());
                    return RJson(buf);
                }
                return RJson("{\"previousPageCursor\":null,\"nextPageCursor\":null,"
                    "\"data\":[{\"id\":9991912465,\"universeId\":9991912465,"
                    "\"name\":\"Baseplate\",\"description\":\"\"}]}");
            }
            if (P.find("/badges")!=std::string::npos)
                return RJson("{\"previousPageCursor\":null,\"nextPageCursor\":null,\"data\":[]}");
            if (P.find("/configuration")!=std::string::npos) {
                /* PATCH — persist name/description + avatar settings */
                if (M == "PATCH" || M == "PUT") {
                    Log("config PATCH body=[%s]", req.body.c_str());
                    std::string nm3 = CfgStr(req.body, "name");
                    if (nm3.empty()) nm3 = CfgStr(req.body, "Name");
                    std::string ds3 = CfgStr(req.body, "description");
                    if (!univId2.empty()) {
                        if (!nm3.empty()) UpdateUniverseField(univId2, "name", nm3);
                        if (!ds3.empty()) UpdateUniverseField(univId2, "description", ds3);
                        PersistAvatarConfig(univId2, req.body);
                    }
                    /* Echo the now-current config so Studio reflects the save. */
                    std::string saved2;
                    if (!univId2.empty() && LoadUniverseJson(univId2, saved2))
                        return RJson(BuildUniverseConfigJson(univId2, saved2));
                    return RJson("{}");
                }
                std::string saved;
                if (!univId2.empty() && LoadUniverseJson(univId2, saved))
                    return RJson(BuildUniverseConfigJson(univId2, saved));
                return RJson(BuildUniverseConfigJson("9991912465", ""));
            }
            if (!univId2.empty()) {
                std::string saved;
                if (LoadUniverseJson(univId2, saved)) return RJson(saved);
            }
            return RJson(UniverseJson());
        }
        /* /v2/users/{id}/groups/roles — any user ID */
        if (STARTS(sub,"/users") && sub.find("/groups/roles") != std::string::npos)
            return RJson(GROUPS_ROLES_JSON);
        if (STARTS(sub,"/groups_roles") || STARTS(sub,"/groups"))
            return RJson("[]");
        /* -- Asset delivery (/v2/asset/?id=X  /v2/assets/?id=X) -- */
        if (STARTS(sub,"/asset") || STARTS(sub,"/assets")) {

 if (sub.find("/details") != std::string::npos) {
                /* Extract the asset id from the path: /v2/assets/{id}/details */
                std::string assetId;
                size_t slashAfterAssets = sub.find('/', 7); /* skip "/assets" (7 chars) */
                if (slashAfterAssets != std::string::npos) {
                    size_t idStart = slashAfterAssets + 1;
                    size_t idEnd   = sub.find('/', idStart);
                    assetId = (idEnd == std::string::npos)
                        ? sub.substr(idStart)
                        : sub.substr(idStart, idEnd - idStart);
                }
                if (assetId.empty()) assetId = QS(req, "id");
                if (assetId.empty()) assetId = "9991912465";

                /* Look up the game name from the saved universe JSON.
                 * The assetId here is a place/asset ID, which is stored as
                 * "rootPlaceId" in the universe JSON files.  Try a direct load
                 * first (universeId == assetId), then scan by rootPlaceId. */
                std::string assetName = "Baseplate"; /* default fallback */
                {
                    std::string saved;
                    bool found = LoadUniverseJson(assetId, saved);
                    if (!found) {
                        /* scan all universe files for a matching rootPlaceId */
                        std::string dir2 = UniversesDir();
                        WIN32_FIND_DATAA fd2;
                        HANDLE hf2 = FindFirstFileA((dir2 + "*.json").c_str(), &fd2);
                        if (hf2 != INVALID_HANDLE_VALUE) {
                            do {
                                if (fd2.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
                                std::string raw2 = ReadFile(dir2 + fd2.cFileName);
                                if (raw2.empty()) continue;
                                if (CfgStr(raw2, "rootPlaceId") == assetId) {
                                    saved = raw2; found = true; break;
                                }
                            } while (FindNextFileA(hf2, &fd2));
                            FindClose(hf2);
                        }
                    }
                    if (found && !saved.empty()) {
                        std::string n = CfgStr(saved, "name");
                        if (!n.empty()) assetName = n;
                    }
                }

                /* escape assetName for safe JSON embedding */
                std::string escapedName;
                for (size_t qi = 0; qi < assetName.size(); qi++) {
                    if (assetName[qi] == '"' || assetName[qi] == '\\')
                        escapedName += '\\';
                    escapedName += assetName[qi];
                }

                /* Real economy /v2/assets/{id}/details is PascalCase (AssetId/TargetId/
                   ProductId). The engine's Game Explorer reads the place id from HERE
                   ("Update AssetId => ID"); lowercase-only "assetId" made it fail with
                   "Unable to get place id from place metadata". Emit PascalCase + camel
                   variants so whichever the engine reads, the id is present. */
                char buf[1536];
                _snprintf(buf, sizeof(buf)-1,
                    "{\"TargetId\":%s,\"AssetId\":%s,\"ProductId\":%s,\"assetId\":%s,"
                    "\"id\":%s,\"Id\":%s,\"TargetPlaceId\":%s,\"PlaceId\":%s,"
                    "\"ProductType\":\"User Product\","
                    "\"Name\":\"%s\",\"Description\":\"\","
                    "\"AssetTypeId\":9,\"assetTypeId\":9,"
                    "\"Creator\":{\"Id\":%s,\"Name\":\"%s\",\"CreatorType\":\"User\","
                        "\"CreatorTargetId\":%s,\"HasVerifiedBadge\":false,"
                        "\"id\":%s,\"type\":1,\"creatorType\":\"User\",\"creatorTargetId\":%s},"
                    "\"IconImageAssetId\":0,"
                    "\"Created\":\"2022-05-11T13:27:09.897Z\",\"Updated\":\"2022-06-19T07:23:39.03Z\","
                    "\"created\":\"2022-05-11T13:27:09.897Z\",\"updated\":\"2022-06-19T07:23:39.03Z\","
                    "\"PriceInRobux\":null,\"Sales\":0,\"IsNew\":false,\"IsForSale\":false,"
                    "\"IsPublicDomain\":true,\"IsLimited\":false,\"IsLimitedUnique\":false,"
                    "\"isPublic\":true,\"isForSale\":false,\"isLimited\":false,"
                    "\"isLimitedUnique\":false,\"enableComments\":false}",
                    assetId.c_str(), assetId.c_str(), assetId.c_str(), assetId.c_str(),
                    assetId.c_str(), assetId.c_str(), assetId.c_str(), assetId.c_str(),
                    escapedName.c_str(),
                    g_userId.c_str(), g_username.c_str(), g_userId.c_str(),
                    g_userId.c_str(), g_userId.c_str());
                return RJson(buf);
            }

            if (sub.find("/batch")!=std::string::npos ||
                sub.find("/ebatch")!=std::string::npos)
                return RJson("{\"data\":[]}");
            return HandleAssetDelivery(req);
        }
        return RJson("{}");
    }

    /* ---- /v9/* ---- */
    if (STARTS(P,"/v9"))
        return RJson("{\"isUserOptIn\":false,\"value\":false}");

    /* ---- /v1.0/* and /v1.1/* (analytics / avatar-fetch) ---- */
    if (STARTS(P,"/v1.")) {
        if (P.find("/avatar-fetch")!=std::string::npos ||
            P.find("/aavatar-fetch")!=std::string::npos)
            return RJson(AvatarFetchJson(QS(req,"placeId"), QS(req,"userId")));
        if (P.find("/game-start-info")!=std::string::npos)
            return RJson("{\"gameServerUserGroupPolicies\":[],"
                "\"universePolicies\":{\"allowedExternalLinkReferences\":[]}}");
        /* MultiIncrement, BatchIncrement, BatchAddToSequencesV2 */
        return RJson("{}");
    }

    /* ---- /v1/* ---- */
    if (STARTS(P,"//v1")) {
        std::string sub = P.substr(4);
        if (STARTS(sub,"/settings")) {
            return RJson("{\"showAgeVerificationOverlay\":false,\"inExperienceFaeUpsell\":\"Disabled\",\"elegibleToSeeVoiceUpsell\":false,\"showVoiceOptInOverlay\":false,\"showVoiceInExperienceUpsell\":false,\"showVoiceInExperienceUpsellVariant\":\"\",\"showAvatarVideoOptInOverlay\":false,\"showDataConsentToast\":false,\"showJoinVoiceUpsellTooltip\":false,\"showM3LikelySpeakingBubbles\":false,\"universePlaceVoiceEnabledSettings\":{\"isUniverseEnabledForVoice\":true,\"isPlaceEnabledForVoice\":true,\"isUniverseEnabledForAvatarVideo\":true,\"isPlaceEnabledForAvatarVideo\":true,\"isChatGroupsApiEnabled\":false},\"voiceSettings\":{\"isVoiceEnabled\":true,\"isUserOptIn\":true,\"isUserEligible\":true,\"isBanned\":false,\"banReason\":0,\"bannedUntil\":null,\"canVerifyAgeForVoice\":false,\"isVerifiedForVoice\":true,\"denialReason\":0,\"isOptInDisabled\":false,\"hasEverOpted\":true,\"isAvatarVideoEnabled\":false,\"isAvatarVideoOptIn\":false,\"isAvatarVideoOptInDisabled\":false,\"isAvatarVideoEligible\":true,\"hasEverOptedAvatarVideo\":false,\"userHasAvatarCameraAlwaysAvailable\":false,\"canVerifyPhoneForVoice\":false,\"seamlessVoiceStatus\":2,\"allowVoiceDataUsage\":false,\"seamlessVoiceVariant\":\"[]\"}}");
        }
    }
    if (STARTS(P,"/v1")) {
        std::string sub = P.substr(3);

        if (STARTS(sub,"/places")) {
            /* /v1/places/{placeId}/teamcreate/active_session/members  etc. */
            if (sub.find("/teamcreate") != std::string::npos)
                return RJson("{\"data\":[]}");
            return RJson("{\"previousPageCursor\":null,\"nextPageCursor\":null,\"data\":[]}");
        }
        if (STARTS(sub,"/games")) {
    if (P.find("/icons") != std::string::npos)
    {
        /* Build one entry per requested universeId */
        std::string imgData = ReadFile(DllPath("www\\Png.png"));
        std::string iconUrl = imgData.empty() ? "" : "http://localhost/Png.png";
        std::string iconState = imgData.empty() ? "Blocked" : "Completed";
        /* Parse universeIds= (comma-separated or repeated &universeIds=) */
        std::string uidsParam = QS(req, "universeIds");
        std::string iconArr;
        if (!uidsParam.empty()) {
            size_t p2 = 0;
            while (p2 <= uidsParam.size()) {
                size_t sep = uidsParam.find(',', p2);
                std::string uid3 = (sep==std::string::npos)
                    ? uidsParam.substr(p2) : uidsParam.substr(p2, sep-p2);
                if (!uid3.empty()) {
                    if (!iconArr.empty()) iconArr += ",";
                    iconArr += "{\"targetId\":"+uid3+",\"state\":\""+iconState+"\",";
                    iconArr += "\"imageUrl\":\""+iconUrl+"\"}";
                }
                if (sep == std::string::npos) break;
                p2 = sep + 1;
            }
        }
        if (iconArr.empty()) {
            iconArr = "{\"targetId\":9991912465,\"state\":\""+iconState+"\",";
            iconArr += "\"imageUrl\":\""+iconUrl+"\"}"; }
        return RJson("{\"data\":[" + iconArr + "]}");
    }
    return RJson(J("{\"data\":[{"
        "\"id\":9991912465,"
        "\"rootPlaceId\":9991912465,"
        "\"name\":\"Baseplate\","
        "\"description\":\"\","
        "\"sourceName\":null,"
        "\"sourceDescription\":null,"
        "\"creator\":{\"id\":{I},\"name\":\"{U}\",\"type\":\"User\","
            "\"isRNVAccount\":false,\"hasVerifiedBadge\":false},"
        "\"price\":null,"
        "\"allowedGearGenres\":[\"All\"],"
        "\"allowedGearCategories\":[],"
        "\"isGenreEnforced\":true,"
        "\"copyingAllowed\":false,"
        "\"playing\":0,"
        "\"visits\":0,"
        "\"maxPlayers\":10,"
        "\"created\":\"2022-05-11T13:27:09.897Z\","
        "\"updated\":\"2022-06-19T07:23:39.03Z\","
        "\"studioAccessToApisAllowed\":true,"
        "\"createVipServersAllowed\":false,"
        "\"genre\":\"All\","
        "\"genre_l1\":\"\","
        "\"genre_l2\":\"\","
        "\"untranslated_genre_l1\":\"na\","
        "\"isAllGenre\":true,"
        "\"isFavoritedByUser\":false,"
        "\"favoritedCount\":0,"
        "\"isActive\":true,"
        "\"privacyType\":\"Public\","
        "\"canonicalUrlPath\":\"/games/9991912465/Baseplate\""
        "}]}"));
}

        /* -- Login -- */
        if (STARTS(sub,"/login"))
            return RJson(J("{\"user\":{\"id\":{I},"
                "\"name\":\"{U}\",\"displayName\":\"{U}\"},"
                "\"twoStepVerificationData\":null,"
                "\"identityVerificationLoginTicket\":null,"
                "\"isBanned\":false}"));

        /* -- Authentication ticket -- */
        if (STARTS(sub,"/authentication-ticket"))
            return RJson("{\"authenticationTicket\":\"hardcoded_auth_ticket_2023\"}");

        /* -- Avatar -- */
        if (STARTS(sub,"/avatar-fetch"))
            return RJson(AvatarFetchJson(QS(req,"placeId"), QS(req,"userId")));
        if (STARTS(sub,"/avatar-rules"))
            return RJson("{\"playerAvatarTypes\":[\"R6\",\"R15\"],"
                "\"scales\":{\"height\":{\"min\":0.9,\"max\":1.05,\"increment\":0.01},"
                "\"width\":{\"min\":0.7,\"max\":1.0,\"increment\":0.01},"
                "\"head\":{\"min\":0.95,\"max\":1.0,\"increment\":0.01},"
                "\"proportion\":{\"min\":0.0,\"max\":1.0,\"increment\":0.01},"
                "\"bodyType\":{\"min\":0.0,\"max\":1.0,\"increment\":0.01}},"
                "\"wearableAssetTypes\":[],"
                "\"bodyColorsPalette\":[],"
                "\"basicBodyColorsPalette\":[],"
                "\"bundlesEnabledForUser\":true,"
                "\"emotesEnabledForUser\":true}");
        if (STARTS(sub,"/avatar") && !STARTS(sub,"/avatar-"))
            return RJson("{\"scales\":{\"height\":1.0,\"width\":1.0,\"head\":1.0,"
                "\"depth\":1.0,\"proportion\":0.0,\"bodyType\":0.0},"
                "\"playerAvatarType\":\"R6\","
                "\"bodyColors\":{\"headColorId\":1002,\"torsoColorId\":1002,"
                "\"rightArmColorId\":1002,\"leftArmColorId\":1002,"
                "\"rightLegColorId\":1002,\"leftLegColorId\":1002},"
                "\"assets\":[],\"defaultShirtApplied\":false,"
                "\"defaultPantsApplied\":false,\"emotes\":[]}");

        /* -- Autolocalization -- */
        if (STARTS(sub,"/autolocalization"))
            return RJson("{\"tableId\":\"\",\"locale\":\"en_us\",\"entries\":[]}");

        /* -- Locales -- */
        if (STARTS(sub,"/locales"))
            return RJson("{\"signupAndLogin\":{\"id\":1,\"locale\":\"en_us\","
                "\"name\":\"English(US)\",\"nativeName\":\"English\","
                "\"language\":{\"id\":41,\"name\":\"English\","
                "\"nativeName\":\"English\",\"languageCode\":\"en\"}},"
                "\"generalExperience\":{\"id\":1,\"locale\":\"en_us\","
                "\"name\":\"English(US)\",\"nativeName\":\"English\","
                "\"language\":{\"id\":41,\"name\":\"English\","
                "\"nativeName\":\"English\",\"languageCode\":\"en\"}},"
                "\"ugc\":{\"id\":1,\"locale\":\"en_us\","
                "\"name\":\"English(US)\",\"nativeName\":\"English\","
                "\"language\":{\"id\":41,\"name\":\"English\","
                "\"nativeName\":\"English\",\"languageCode\":\"en\"}}}");

        /* -- Player policies -- */
        if (STARTS(sub,"/player-policies-client") || STARTS(sub,"/player-policies"))
            return RJson("{\"isSubjectToChinaPolicies\":false,"
    "\"arePaidRandomItemsRestricted\":false,"
    "\"isPaidItemTradingAllowed\":true,"
    "\"areAdsAllowed\":true,"
    "\"isEmotesEnabled\":true,"
    "\"allowedExternalLinkReferences\":"
    "[\"Discord\",\"YouTube\",\"Twitch\",\"Facebook\"]}");

        /* -- Thumbnails -- */
        if (STARTS(sub,"/thumbnails/load"))
            return RJson("{}");
        if (STARTS(sub,"/thumbnails/metadata"))
            return RJson("{\"logRatio\":0}");
        if (STARTS(sub,"/thumbnails"))
            return RJson("{\"data\":[]}");

        /* -- Settings -- */
        if (STARTS(sub,"/settings/user-opt-in"))
            return RJson("{\"isUserOptIn\":false}");
        if (STARTS(sub,"/settings/verify"))
            return RJson("{\"value\":false}");
        if (STARTS(sub,"/settings"))
            return RJson("{\"isVoiceEnabled\":true,\"isUserOptIn\":true,\"isUserEligible\":true,\"isBanned\":false,\"banReason\":0,\"bannedUntil\":null,\"canVerifyAgeForVoice\":true,\"isVerifiedForVoice\":true,\"denialReason\":0,\"isOptInDisabled\":false,\"hasEverOpted\":true,\"isAvatarVideoEnabled\":true,\"isAvatarVideoOptIn\":true,\"isAvatarVideoOptInDisabled\":false,\"isAvatarVideoEligible\":true,\"hasEverOptedAvatarVideo\":true,\"userHasAvatarCameraAlwaysAvailable\":true,\"canVerifyPhoneForVoice\":true,\"seamlessVoiceStatus\":1,\"allowVoiceDataUsage\":true,\"seamlessVoiceVariant\":\"\"}");
        /* -- Presence -- */
        if (STARTS(sub,"/presence"))
            return RJson("{\"userPresences\":[]}");

        /* -- Purchases / products -- */
        if (STARTS(sub,"/purchases"))
            return RJson("{\"purchased\":true,\"reason\":\"AlreadyOwned\","
                "\"productId\":0,\"currency\":\"Robux\",\"price\":0}");

        /* -- Search -- */
       if (STARTS(sub,"/search")) {
    /* Prepend all locally saved universes, then append the hardcoded ones */
    std::string savedArr = AllUniversesJson(); /* "[{...},{...}]" or "[]" */

    std::string savedItems;

    if (savedArr.size() > 2) {
        std::string raw = savedArr.substr(1, savedArr.size() - 2);

        /* Convert legacy "universeId" -> "id".
         * Skip items that already have "id" (new-format files) to avoid duplicates. */
        {
            size_t pos = 0;
            while ((pos = raw.find("\"universeId\":", pos)) != std::string::npos) {
                /* Look back to the opening { of this JSON object */
                size_t itemStart = raw.rfind('{', pos);
                size_t idPos = (itemStart != std::string::npos)
                               ? raw.find("\"id\":", itemStart) : std::string::npos;
                if (idPos != std::string::npos && idPos < pos) {
                    /* Item already has "id" — just erase the "universeId":VALUE, part */
                    size_t ve = pos + 13;
                    while (ve < raw.size() && raw[ve] != ',' && raw[ve] != '}') ve++;
                    if (ve < raw.size() && raw[ve] == ',') ve++; /* eat trailing comma */
                    raw.erase(pos, ve - pos);
                    /* pos unchanged — re-scan from same spot */
                } else {
                    raw.replace(pos, 13, "\"id\":");
                    pos += 5;
                }
            }
        }

        savedItems = raw;
    }

    return RJson("{\"previousPageCursor\":null,\"nextPageCursor\":null,\"data\":[" + savedItems + "]}");
}

        /* -- Sponsored pages -- */
        if (STARTS(sub,"/sponsored-pages"))
            return RJson("{\"data\":[]}");

        /* -- Themes -- */
        if (STARTS(sub,"/themes"))
            return RJson("{\"themeType\":\"Dark\"}");

        /* -- Gametemplates -- */
        if (STARTS(sub,"/gametemplates"))
            return RJson("{\"previousPageCursor\":null,\"nextPageCursor\":null,\"data\":[]}");

        /* -- Game start info -- */
        if (STARTS(sub,"/game-start-info")) {
            std::string uid_gs = QS(req,"universeId");
            std::string saved_gs;
            if (!uid_gs.empty() && LoadUniverseJson(uid_gs, saved_gs)) {
                std::string nm_gs   = CfgStr(saved_gs, "name");
                std::string rpid_gs = CfgStr(saved_gs, "rootPlaceId");
                if (nm_gs.empty())   nm_gs   = "Untitled Place";
                if (rpid_gs.empty()) rpid_gs = uid_gs;
                char buf_gs[512];
                _snprintf(buf_gs, sizeof(buf_gs)-1,
                    "{\"gameServerUserGroupPolicies\":[],"
                    "\"universePolicies\":{\"allowedExternalLinkReferences\":[]},"
                    "\"name\":\"%s\",\"universeDisplayName\":\"%s\","
                    "\"creatorId\":%s,\"creatorName\":\"%s\","
                    "\"universeId\":%s,\"placeId\":%s}",
                    nm_gs.c_str(), nm_gs.c_str(),
                    g_userId.c_str(), g_username.c_str(),
                    uid_gs.c_str(), rpid_gs.c_str());
                return RJson(buf_gs);
            }
            return RJson(J("{\"gameServerUserGroupPolicies\":[],"
                "\"universePolicies\":{\"allowedExternalLinkReferences\":[]},"
                "\"name\":\"Baseplate\",\"universeDisplayName\":\"Baseplate\","
                "\"creatorId\":{I},\"creatorName\":\"{U}\","
                "\"universeId\":9991912465,\"placeId\":9991912465}"));
        }

        /* -- Games (icons etc.) -- */
        if (STARTS(sub,"/games"))
            return RJson("{\"data\":[]}");

        /* -- Asset delivery (/v1/asset/?id=X  /v1/assets/?id=X) -- */
        if (STARTS(sub,"/asset") || STARTS(sub,"/assets")) {
            /* Batch / ebatch endpoints */
            if (sub.find("/batch")!=std::string::npos ||
                sub.find("/ebatch")!=std::string::npos)
                return RJson("{\"data\":[]}");
            /* AssetSaving */
            if (sub.find("AssetSaving")!=std::string::npos ||
                sub.find("assetsaving")!=std::string::npos)
                return RJson("{\"success\":true}");
            /* Actual asset delivery */
            return HandleAssetDelivery(req);
        }

        /* -- Batch (legacy /v1/batch) -- */
        if (STARTS(sub,"/batch"))
            return RJson("{\"data\":[]}");

        /* -- Performance -- */
        if (STARTS(sub,"/performance"))
            return RJson("{}");

        /* -- Team create -- */
        if (STARTS(sub,"/team-create-preemptive") || STARTS(sub,"/team-create"))
            return RJson("{\"status\":0,\"message\":null,\"settings\":null}");

        /* -- Universes -- */
        if (STARTS(sub,"/universes")) {
            /* Extract universe ID from path: /v1/universes/{id}/... */
            std::string univId;
            {
                const char* marker = "/universes/";
                size_t mp = sub.find(marker);
                if (mp != std::string::npos) {
                    size_t idStart = mp + strlen(marker);
                    size_t idEnd   = sub.find('/', idStart);
                    univId = (idEnd == std::string::npos) ? sub.substr(idStart) : sub.substr(idStart, idEnd - idStart);
                }
            }
            if (P.find("/teamcreate") != std::string::npos)
                return RJson("{\"isEnabled\":false}");
            if (P.find("/permissions") != std::string::npos)
                /* Team Create / cloud-edit disabled by default: canCloudEdit:false makes
               Studio open owned cloud places as a plain editable download (Save/Publish
               still work via canManage/canPublish) instead of a live cloud-edit session,
               which otherwise hangs at "Loading game (attempt #N)" with no edit RCC. */
            return RJson("{\"canManage\":true,\"canCloudEdit\":false,\"canPublish\":true,\"canView\":true,\"isPublic\":false}");
            if (P.find("/places")!=std::string::npos) {
                std::string saved;
                if (!univId.empty() && LoadUniverseJson(univId, saved)) {
                    std::string rpid = CfgStr(saved, "rootPlaceId");
                    std::string uname = CfgStr(saved, "name");
                    char buf[512]; _snprintf(buf,sizeof(buf)-1,
                        "{\"previousPageCursor\":null,\"nextPageCursor\":null,"
                        "\"data\":[{\"id\":%s,\"universeId\":%s,\"name\":\"%s\",\"description\":\"\"}]}",
                        rpid.c_str(), univId.c_str(), uname.c_str());
                    return RJson(buf);
                }
                return RJson("{\"previousPageCursor\":null,\"nextPageCursor\":null,"
                    "\"data\":[{\"id\":9991912465,\"universeId\":9991912465,"
                    "\"name\":\"Baseplate\",\"description\":\"\"}]}");
            }
            if (P.find("/badges")!=std::string::npos)
                return RJson("{\"previousPageCursor\":null,\"nextPageCursor\":null,\"data\":[]}");
            if (P.find("/configuration")!=std::string::npos) {
                /* PATCH — persist name/description + avatar settings */
                if (M == "PATCH" || M == "PUT") {
                    Log("v1 config PATCH body=[%s]", req.body.c_str());
                    std::string nm4 = CfgStr(req.body, "name");
                    if (nm4.empty()) nm4 = CfgStr(req.body, "Name");
                    std::string ds4 = CfgStr(req.body, "description");
                    if (!univId.empty()) {
                        if (!nm4.empty()) UpdateUniverseField(univId, "name", nm4);
                        if (!ds4.empty()) UpdateUniverseField(univId, "description", ds4);
                        PersistAvatarConfig(univId, req.body);
                    }
                    std::string saved2;
                    if (!univId.empty() && LoadUniverseJson(univId, saved2))
                        return RJson(BuildUniverseConfigJson(univId, saved2));
                    return RJson("{}");
                }
                std::string saved;
                if (!univId.empty() && LoadUniverseJson(univId, saved))
                    return RJson(BuildUniverseConfigJson(univId, saved));
                return RJson(BuildUniverseConfigJson("9991912465", ""));
            }
            if (P.find("/multiget")!=std::string::npos) {
                /* ids=X&ids=Y — build data array from saved universes */
                std::string jout = "{\"data\":[";
                bool jfirst = true;
                /* iterate query string for ids= parameters */
                std::string q = req.query;
                size_t pos = 0;
                while (pos < q.size()) {
                    size_t amp = q.find('&', pos);
                    std::string kv = (amp == std::string::npos) ? q.substr(pos) : q.substr(pos, amp - pos);
                    pos = (amp == std::string::npos) ? q.size() : amp + 1;
                    if (kv.compare(0, 4, "ids=") != 0) continue;
                    std::string uid2 = UrlDecode(kv.substr(4));
                    std::string saved;
                    if (LoadUniverseJson(uid2, saved)) {
                        if (!jfirst) jout += ",";
                        jout += NormalizeUniverseJson(saved); jfirst = false;
                    }
                }
                if (jfirst) { /* nothing saved — return mock; Baseplate is NOT owned by local player */
                    jout += "{\"id\":9991912465,\"name\":\"Baseplate\","
                            "\"rootPlaceId\":9991912465,\"isActive\":true,"
                            "\"privacyType\":\"Public\","
                            "\"creatorType\":\"User\",\"creatorTargetId\":998796,"
                            "\"creatorName\":\"Roblox\"}";
                }
                jout += "]}";
                return RJson(jout);
            }
            /* Single universe lookup by ID */
            if (!univId.empty()) {
                std::string saved;
                if (LoadUniverseJson(univId, saved)) return RJson(NormalizeUniverseJson(saved));
            }
            return RJson(UniverseJson());
        }

        /* -- Users -- */
        if (STARTS(sub,"/users")) {
            /* authenticated sub-paths first */
            if (P.find("/authenticated/app-launch-info")!=std::string::npos)
                return RJson(J("{\"ageBracket\":0,\"countryCode\":\"US\","
                    "\"isPremium\":true,\"id\":{I},"
                    "\"name\":\"{U}\",\"displayName\":\"{U}\"}"));
            if (P.find("/authenticated/roles")!=std::string::npos)
                return RJson("{\"roles\":[\"Developer\",\"Soothsayer\"]}");
            if (P.find("/authenticated")!=std::string::npos)
                return RJson(UserJson());
            if (P.find("/avatar-headshot")!=std::string::npos)
                return RJson(J("{\"data\":[{\"targetId\":{I},\"state\":\"Completed\","
                    "\"imageUrl\":\"http://localhost/Thumbs/Avatar.ashx\"}]}"));
            if (P.find("/avatar-3d")!=std::string::npos)
                return RJson("{\"data\":[]}");
            if (P.find("/avatar")!=std::string::npos)
                return RJson("{\"scales\":{\"height\":1.0,\"width\":1.0,\"head\":1.0,"
                    "\"depth\":1.0,\"proportion\":0.0,\"bodyType\":0.0},"
                    "\"playerAvatarType\":\"R6\","
                    "\"bodyColors\":{\"headColorId\":1002,\"torsoColorId\":1002,"
                    "\"rightArmColorId\":1002,\"leftArmColorId\":1002,"
                    "\"rightLegColorId\":1002,\"leftLegColorId\":1002},"
                    "\"assets\":[],\"emotes\":[]}");
            if (P.find("/currency")!=std::string::npos)
                return RJson("{\"robux\":9999999999}");
            if (P.find("/friends")!=std::string::npos)
                return RJson("{\"previousPageCursor\":null,\"nextPageCursor\":null,\"data\":[]}");
            if (P.find("/universes/")!=std::string::npos && P.find("/status")!=std::string::npos)
                return RJson("{\"isActive\":true}");
            /* UserHasBadgeAsync -> GET /v1/users/{id}/badges/awarded-dates?badgeIds=...
             * Expects {"data":[{"badgeId":N,"awardedDate":"..."}]} — one entry per
             * AWARDED badge.  Empty data = not awarded (UserHasBadgeAsync -> false).
             * Returning {"success":true} made it fail with "Parsed invalid JSON data". */
            if (P.find("awarded-dates")!=std::string::npos)
                return RJson("{\"data\":[]}");
            /* BadgeService:AwardBadge -> POST /v1/users/{id}/badges/{badgeId}/award-badge
             * SERVER-ONLY call (badges can only be awarded by a game server), which is
             * why this crashed only the server and never the client.
             * The legacy endpoint returns a BARE JSON boolean (true/false), NOT an
             * object.  The engine decodes the body into a Variant and casts it to bool;
             * handing it an object ({"success":true}) is a type mismatch -> "Parsed
             * invalid JSON data" / Variant cast -> uncaught C++ throw on the server
             * DataModel -> whole server crashes.  Return the bare boolean. */
            if (P.find("/award-badge")!=std::string::npos)
                return RJson("true");
            if (P.find("/badges/")!=std::string::npos)
                return RJson("{\"success\":true}");
            /* /v1/users?userIds=... or /v1/users/{id} */
            return RJson(J("{\"data\":[{\"id\":{I},"
                "\"name\":\"{U}\",\"displayName\":\"{U}\"}]}"));
        }

        /* -- User (singular) -- */
        if (STARTS(sub,"/user")) {
            if (P.find("/canmanage") != std::string::npos) {
            /* Deny canManage for the hardcoded Baseplate place so Studio treats
             * it as unowned and opens "Publish to new place" on publish. */
            bool isBaseplate = (P.find("9991912465") != std::string::npos);
            if (isBaseplate)
                return RJson("{\"Success\":true,\"CanManage\":false}");
            /* CanManage is true ONLY for the host's own userId. Extract the id
             * segment from /v1/user/{id}/canmanage/{placeId}; everyone else
             * (other players joining) must get false. */
            bool owner = false;
            size_t cmPos = P.find("/canmanage");
            if (cmPos != std::string::npos && cmPos > 0) {
                size_t idStart = P.rfind('/', cmPos - 1);
                if (idStart != std::string::npos) {
                    std::string pathId = P.substr(idStart + 1, cmPos - idStart - 1);
                    owner = (!pathId.empty() && pathId == g_userId);
                }
            }
            return RJson(owner ? "{\"Success\":true,\"CanManage\":true}"
                               : "{\"Success\":true,\"CanManage\":false}");
        }
    if (P.find("/is-admin-developer-console-enabled") != std::string::npos) {
        /* Extract user id from path, e.g. /v1/user/{id}/is-admin-developer-console-enabled */
        bool authorized = false;
        size_t epPos = P.find("/is-admin-developer-console-enabled");
        if (epPos != std::string::npos) {
            size_t segEnd = epPos;
            size_t segStart = P.rfind('/', segEnd - 1);
            if (segStart != std::string::npos) {
                std::string pathId = P.substr(segStart + 1, segEnd - segStart - 1);
                authorized = (!pathId.empty() && pathId == g_userId);
            }
        }
        if (authorized)
            return RJson("{\"isAdminDeveloperConsoleEnabled\":true}");
        else
            return RJson("{\"isAdminDeveloperConsoleEnabled\":false}", 403);
    }
            if (P.find("/currency")!=std::string::npos)
                return RJson("{\"robux\":9999999999}");
            if (P.find("/universes")!=std::string::npos) {
                std::string savedArr = AllUniversesJson();
                std::string savedItems;
                if (savedArr.size() > 2) savedItems = savedArr.substr(1, savedArr.size() - 2);
                /* Baseplate mock is appended but NOT owned by the local player */
                std::string mockItem = "{\"id\":9991912465,\"name\":\"Baseplate\","
                    "\"description\":\"Baseplate local server.\","
                    "\"isArchived\":false,\"rootPlaceId\":9991912465,\"isActive\":true,"
                    "\"privacyType\":\"Public\",\"creatorType\":\"User\","
                    "\"creatorTargetId\":998796,\"creatorName\":\"Roblox\","
                    "\"created\":\"2022-05-11T13:27:09.897Z\","
                    "\"updated\":\"2022-06-19T07:23:39.03Z\"}";
                std::string data = savedItems.empty() ? mockItem : (savedItems + "," + mockItem);
                return RJson("{\"previousPageCursor\":null,\"nextPageCursor\":null,\"data\":[" + data + "]}");
            }
            if (P.find("/groups/canmanage")!=std::string::npos)
                return RJson("{\"Success\":true,\"CanManage\":true}");
            if (P.find("/friend-requests")!=std::string::npos)
                return RJson("{\"count\":0}");
            if (P.find("/teamcreate")!=std::string::npos)
                return RJson("{\"data\":[]}");
            if (P.find("/opt-in-feature-stages")!=std::string::npos)
                return RJson("{\"data\":[]}");
            return RJson("{\"Success\":true}");
        }

        /* -- Avatar thumbnail customization -- */
        if (STARTS(sub,"/avatar/thumbnail-customization") ||
            STARTS(sub,"/avatar/thumbnail-customizations"))
            return RJson("{\"errors\":[{\"code\":0,\"message\":\"AnErrorOcurred\"}]}");

        /* -- Purchases (generic product) -- */
        if (P.find("/products/")!=std::string::npos)
            return RJson("{\"purchased\":true,\"reason\":\"AlreadyOwned\","
                "\"productId\":0,\"currency\":\"Robux\",\"price\":0}");

        /* -- Badges -- */
        if (P.find("/badges")!=std::string::npos)
            return RJson("{\"previousPageCursor\":null,\"nextPageCursor\":null,\"data\":[]}");

        /* -- Asset batch / ebatch -- */
        if (STARTS(sub,"/assets/ebatch"))
            return RJson("[]");
        /* /v1/assets/{id}/saved-versions  and other asset sub-paths */
        if (STARTS(sub,"/assets")) {
            if (sub.find("/saved-versions") != std::string::npos)
                return RJson("{\"previousPageCursor\":null,\"nextPageCursor\":null,\"data\":[{\"assetVersionNumber\":1,\"creatingUniverseId\":null,\"assetId\":1,\"creatorType\":\"User\",\"creatorTargetId\":1,\"created\":\"2022-01-01T00:00:00Z\"}]}");
            return RJson("{}");
        }

        /* -- v1 DataStore persistence API (standard + sorted/ordered) --
         * Handles GET/POST /v1/persistence/{type}
         *         POST     /v1/persistence/{type}/multi-get
         *         POST     /v1/persistence/{type}/increment
         *         POST     /v1/persistence/{type}/remove
         *         GET      /v1/persistence/sorted/list  (OrderedDataStore pages)
         */
        if (STARTS(sub,"/persistence")) {
            const std::string uid1 = "1";
            /* psub = everything after "/persistence", e.g. "/sorted/list" */
            std::string psub = sub.substr(12);
            std::string ptype, prest;
            if (!psub.empty() && psub[0] == '/') {
                size_t nx = psub.find('/', 1);
                if (nx != std::string::npos) {
                    ptype = psub.substr(1, nx - 1);
                    prest = psub.substr(nx); /* e.g. "/list", "/increment" */
                } else {
                    ptype = psub.substr(1); /* e.g. "sorted", "standard" */
                    prest = "";
                }
            }
            std::string pscope  = QS(req, "scope", "global");
            std::string pdsname = QS(req, "key");     /* datastore name */
            std::string ptarget = QS(req, "target");  /* entry key      */

            /* TEMP DIAGNOSTIC: log the full shape of every ordered/standard op so we
             * can see exactly what SetAsync/GetSortedAsync send (method, params, and
             * the request BODY, which the normal >> line doesn't capture). */
            Log("DS-v1: M=%s type=%s rest=%s ds=%s scope=%s target=%s usnParam=%s bodylen=%d body=[%.160s]",
                M.c_str(), ptype.c_str(), prest.c_str(), pdsname.c_str(), pscope.c_str(),
                ptarget.c_str(),
                (req.query.find("usn=") != std::string::npos ? "yes" : "no"),
                (int)req.body.size(), req.body.c_str());

            /* ---- GET /v1/persistence/sorted/list  (OrderedDataStore pages) ---- */
            if (ptype == "sorted" && STARTS(prest, "/list") && M == "GET") {
                int pageSize = atoi(QS(req,"pageSize","100").c_str());
                if (pageSize <= 0 || pageSize > 100) pageSize = 100;
                bool ascending = (QS(req,"direction","desc") == "asc");
                std::string minStr = QS(req,"minValue");
                std::string maxStr = QS(req,"maxValue");
                bool hasMin = !minStr.empty(), hasMax = !maxStr.empty();
                long long minVal = hasMin ? atoll(minStr.c_str()) : 0;
                long long maxVal = hasMax ? atoll(maxStr.c_str()) : 0;
                std::string excKey = QS(req,"exclusiveStartKey");

                std::string dir1 = DsDir(uid1, pscope, pdsname);

                /* Collect all numeric entries from disk */
                struct SortedEntry { std::string tgt; long long val; };
                std::vector<SortedEntry> entries;
                WIN32_FIND_DATAA fd1;
                HANDLE hf1 = FindFirstFileA((dir1 + "*.json").c_str(), &fd1);
                if (hf1 != INVALID_HANDLE_VALUE) {
                    do {
                        if (fd1.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
                        std::string fname1 = fd1.cFileName;
                        if (fname1.size() < 6) continue;
                        std::string tgt1 = UrlDecode(fname1.substr(0, fname1.size() - 5));
                        DsRec r1; if (!DsRead(dir1 + fname1, r1)) continue;
                        char* ep1 = NULL;
                        long long v1 = strtoll(r1.value.c_str(), &ep1, 10);
                        if (!ep1 || ep1 == r1.value.c_str()) continue; /* non-numeric */
                        if (hasMin && v1 < minVal) continue;
                        if (hasMax && v1 > maxVal) continue;
                        SortedEntry e1; e1.tgt = tgt1; e1.val = v1;
                        entries.push_back(e1);
                    } while (FindNextFileA(hf1, &fd1));
                    FindClose(hf1);
                }

                /* Bubble sort (small datasets, guaranteed to compile on XP target) */
                for (size_t si = 0; si + 1 < entries.size(); si++) {
                    for (size_t sj = si + 1; sj < entries.size(); sj++) {
                        bool doSwap = ascending ? (entries[si].val > entries[sj].val)
                                                : (entries[si].val < entries[sj].val);
                        if (doSwap) {
                            SortedEntry tmp = entries[si];
                            entries[si] = entries[sj];
                            entries[sj] = tmp;
                        }
                    }
                }

                /* Pagination: skip past exclusiveStartKey */
                size_t startIdx = 0;
                if (!excKey.empty()) {
                    for (size_t ei = 0; ei < entries.size(); ei++) {
                        if (entries[ei].tgt == excKey) { startIdx = ei + 1; break; }
                    }
                }

                std::string jout = "{\"entries\":[";
                bool jfirst = true; std::string lastTgt;
                size_t cnt = 0;
                for (size_t ei = startIdx; ei < entries.size() && (int)cnt < pageSize; ei++, cnt++) {
                    if (!jfirst) jout += ",";
                    char vb1[64]; sprintf(vb1, "%lld", entries[ei].val);
                    jout += "{\"target\":\"" + entries[ei].tgt + "\",\"value\":" + vb1 + ",\"usn\":\"1\"}";
                    lastTgt = entries[ei].tgt;
                    jfirst = false;
                }
                jout += "]";
                if (!entries.empty() && startIdx + cnt < entries.size())
                    jout += ",\"lastEvaluatedKey\":\"" + lastTgt + "\"";
                else
                    jout += ",\"lastEvaluatedKey\":null";
                jout += "}";
                return RJson(jout);
            }

            /* ---- POST /v1/persistence/{type}/increment ---- */
            if (STARTS(prest,"/increment") && M == "POST") {
                long long by1 = atoll(QS(req,"by","1").c_str());
                std::string d2 = DsDir(uid1, pscope, pdsname);
                std::string f2 = DsFile(d2, ptarget);
                DsRec r2; long long prev2 = 0; int ver2 = 1;
                if (DsRead(f2, r2)) { prev2 = atoll(r2.value.c_str()); ver2 = r2.version + 1; }
                long long nv2 = prev2 + by1;
                char vb2[64]; sprintf(vb2, "%lld", nv2);
                DsWrite(f2, vb2, ver2, r2.createdAt);
                char rb2[128]; sprintf(rb2, "{\"value\":\"%lld\",\"usn\":\"%d\"}", nv2, ver2);
                return RJson(rb2);
            }

            /* ---- POST /v1/persistence/{type}/remove ---- */
            if (STARTS(prest,"/remove") && M == "POST") {
                std::string d3 = DsDir(uid1, pscope, pdsname);
                std::string f3 = DsFile(d3, ptarget);
                DeleteFileA(f3.c_str());
                return RJson("{}");
            }

            /* ---- POST /v1/persistence/{type}/multi-get ---- */
            if (STARTS(prest,"/multi-get") && M == "POST") {
                std::string body4 = req.body;
                std::string jout4 = "{\"entries\":[";
                bool first4 = true;
                size_t kpos = body4.find("\"keys\"");
                if (kpos != std::string::npos) {
                    size_t aS = body4.find('[', kpos);
                    size_t aE = body4.rfind(']');
                    if (aS != std::string::npos && aE != std::string::npos && aE > aS) {
                        std::string arr4 = body4.substr(aS + 1, aE - aS - 1);
                        size_t pos4 = 0;
                        while (pos4 < arr4.size()) {
                            size_t oS = arr4.find('{', pos4); if (oS == std::string::npos) break;
                            int depth4 = 0; size_t oE = oS;
                            for (size_t ii = oS; ii < arr4.size(); ii++) {
                                if (arr4[ii] == '{') depth4++;
                                else if (arr4[ii] == '}') { depth4--; if (depth4 == 0) { oE = ii; break; } }
                            }
                            if (oE == oS) break;
                            std::string obj4 = arr4.substr(oS, oE - oS + 1);
                            pos4 = oE + 1;
                            std::string esc4  = CfgStr(obj4,"scope"); if (esc4.empty()) esc4 = "global";
                            std::string ek4   = CfgStr(obj4,"key");
                            std::string et4   = CfgStr(obj4,"target");
                            std::string d4    = DsDir(uid1, esc4, ek4);
                            std::string f4    = DsFile(d4, et4);
                            DsRec r4; if (!DsRead(f4, r4)) continue;
                            char uv4[32]; sprintf(uv4, "%d", r4.version);
                            if (!first4) jout4 += ",";
                            jout4 += "{\"key\":\"" + ek4 + "\",\"scope\":\"" + esc4 +
                                     "\",\"target\":\"" + et4 + "\",\"value\":" + r4.value +
                                     ",\"usn\":\"" + uv4 + "\"}";
                            first4 = false;
                        }
                    }
                }
                jout4 += "]}";
                return RJson(jout4);
            }

            /* ---- GET or POST /v1/persistence/{type}  (single entry) ----
             * Both GetAsync (read) and SetAsync (write) hit this same bare path,
             * and BOTH can arrive as POST -- the engine distinguishes them by the
             * presence of a value body / a `usn=` query param (writes have them,
             * reads don't), NOT by HTTP method.  Keying off the method made a
             * no-body read-POST fall into the write branch, which overwrote the
             * stored value with "null" and replied "{}".
             *
             * The reply is the RAW stored value as the body (same as the working
             * read path / the v2 store).  A MISSING key must return a bare `null`
             * with 200 -- NOT "{}"/404 -- so OrderedDataStore/DataStore GetAsync
             * resolves to nil instead of erroring ("Error Loading!"). */
            if (prest.empty()) {
                std::string d5 = DsDir(uid1, pscope, pdsname);
                std::string f5 = DsFile(d5, ptarget);
                bool hasUsn  = (req.query.find("usn=") != std::string::npos);
                bool isWrite = (M == "POST") && (!req.body.empty() || hasUsn);
                if (isWrite) {
                    DsRec old5; int ver5 = DsRead(f5, old5) ? old5.version + 1 : 1;
                    std::string val5 = req.body.empty() ? "null" : req.body;
                    DsWrite(f5, val5, ver5, old5.createdAt);
                    /* SetAsync parses this reply -- "{}" was missing the value/version
                     * envelope, so SetAsync threw and the pcall bailed before
                     * GetSortedAsync ever ran (hence no /sorted/list request).  Echo the
                     * stored value (raw, type preserved) plus version + usn, matching the
                     * /increment envelope the engine already accepts. */
                    char vb5[32]; sprintf(vb5, "%d", ver5);
                    return RJson("{\"value\":" + val5 +
                                 ",\"version\":\"" + vb5 + "\",\"usn\":\"" + vb5 + "\"}");
                }
                /* READ (GetAsync): raw value, or bare null when absent. */
                DsRec r5;
                Resp rv5; rv5.status = 200; rv5.statusText = "OK";
                rv5.contentType = "application/json; charset=utf-8";
                rv5.body = DsRead(f5, r5) ? r5.value : std::string("null");
                return rv5;
            }
            return RJson("{}");
        }

        /* Anything else under /v1 */
        return RJson("{}");
    }

    if (STARTS(P,"/playfab-universes-service"))
        return RJson("{\"titleId\":\"\",\"enabled\":false}");

    /* ---- Catch-all for /v1.0 /v1.1 prefixes missed above ---- */
    if (STARTS(P,"/v1."))
        return RJson("{}");

    /* ---- /Data/Upload.ashx  (place publish / save to disk) ---- */
    if (STARTS(P,"/Data/Upload.ashx") || STARTS(P,"/data/upload.ashx")) {
        if (M == "POST") {
            std::string assetId = QS(req,"assetid");
            if (assetId.empty()) assetId = QS(req,"assetId");
            /* Log all headers so we can identify the game-name header */
            Log("Upload.ashx: assetId='%s' body=%d bytes issavedversiononly=%s",
                assetId.c_str(), (int)req.body.size(),
                QS(req,"issavedversiononly","?").c_str());
            Log("Upload.ashx QueryString: %s", req.query.c_str());
            for (auto it = req.headers.begin(); it != req.headers.end(); ++it)
                Log("  Upload Header [%s]: %s", it->first.c_str(), it->second.c_str());
            if (!assetId.empty() && !req.body.empty()) {
                std::string dir  = DllPath("data\\SavedData\\");
                EnsureDir(dir);
                /* ParseHttp already gunzipped the body if it arrived
                 * Content-Encoding: gzip, so req.body is the raw .rbxl here.
                 * Store it gzip-COMPRESSED to save disk space (Roblox keeps
                 * places gzipped anyway). The asset-delivery read path detects
                 * the gzip magic and decompresses before serving. If compression
                 * fails for any reason we fall back to writing the raw bytes. */
                std::string savePath = dir + assetId + ".rbxl";
                std::string toWrite = req.body;
                if (!IsGzip(toWrite)) {
                    std::string gz = GzipCompress(toWrite);
                    if (!gz.empty()) toWrite.swap(gz);
                }
                WriteFile_(savePath, toWrite);
                /* Remove any old extensionless file left from previous versions */
                DeleteFileA((dir + assetId).c_str());
                Log("Upload.ashx: saved %s (%d raw -> %d on disk, gzip=%d) -> %s",
                    assetId.c_str(), (int)req.body.size(), (int)toWrite.size(),
                    (int)IsGzip(toWrite), savePath.c_str());
                /* If this placeId belongs to a known universe, touch the universe JSON
                 * so LoadUniverseJson (which checks PlaceAssetExists) will now succeed */
                {
                    std::string dir4 = UniversesDir();
                    WIN32_FIND_DATAA fd4;
                    HANDLE hf4 = FindFirstFileA((dir4 + "*.json").c_str(), &fd4);
                    if (hf4 != INVALID_HANDLE_VALUE) {
                        do {
                            if (fd4.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
                            std::string raw4 = ReadFile(dir4 + fd4.cFileName);
                            if (raw4.empty()) continue;
                            if (CfgStr(raw4, "rootPlaceId") == assetId) {
                                Log("Upload.ashx: universe %s now has place asset",
                                    fd4.cFileName);
                                break;
                            }
                        } while (FindNextFileA(hf4, &fd4));
                        FindClose(hf4);
                    }
                }
            } else {
                if (assetId.empty())
                    Log("Upload.ashx: WARNING - assetId is empty, place NOT saved");
                else
                    Log("Upload.ashx: WARNING - body is empty, place NOT saved");
            }
            return RText("1");
        }
        return RText("1");
    }

    /* ---- /content-aliases-api ---- */
    if (STARTS(P,"/content-aliases-api"))
        return RJson("{\"FinalPage\":true,\"Aliases\":[],\"PageSize\":50}");

    /* ---- /packages-api/v1/places/{id}/packages ---- */
    if (STARTS(P,"/packages-api")) {
        return RJson("{\"packageLinks\":[]}");
    }


    /* ---- Static files (www\) ---- */
    Resp staticR;
    if (ServeStatic(P, staticR)) return staticR;

    /* ---- 404 ---- */
    Log("404 %s %s", M.c_str(), P.c_str());
    return RJson("{\"errors\":[{\"code\":\"NotFound\",\"message\":\"Not found\"}]}", 404);
}

/* ============================================================================
   SECTION 12 — Raw TCP receive (accumulate full HTTP request)
   ========================================================================= */
/* Returns true when the plaintext buffer contains a complete HTTP request:
 * all headers AND exactly Content-Length body bytes. */
static bool HttpRequestComplete(const std::string& out)
{
    size_t hend = out.find("\r\n\r\n");
    if (hend == std::string::npos) return false;
    std::string lo = ToLower(out.substr(0, hend));
    size_t clp = lo.find("content-length:");
    if (clp == std::string::npos) return true;   /* no body */
    int cl = atoi(out.c_str() + clp + 15);
    if (cl <= 0) return true;
    return (int)out.size() - (int)(hend + 4) >= cl;
}

static bool RecvFull(SOCKET s, std::string& out)
{
    char buf[65536]; out.clear();   /* 64 KB chunks for fast large-file reads */
    while (true) {
        fd_set fds; struct timeval tv = {30, 0}; /* 30 s handles large .rbxl uploads */
        FD_ZERO(&fds); FD_SET(s, &fds);
        if (select(0, &fds, NULL, NULL, &tv) <= 0) return !out.empty();
        int r = recv(s, buf, sizeof(buf), 0);
        if (r <= 0) return !out.empty();
        out.append(buf, r);
        if (HttpRequestComplete(out)) return true;
    }
}

/* ============================================================================
   SECTION 13 — SChannel TLS (server side, XP+)
   ========================================================================= */
static bool LoadSslCert()
{
    /* Load PEM cert and key directly — same files Apache uses.
     * No openssl / PFX conversion required.
     *
     * ssl\server.crt  — PEM X.509 certificate (-----BEGIN CERTIFICATE-----)
     * ssl\server.key  — PEM private key, PKCS#1 or PKCS#8
     */

    /* ---- 1. Decode PEM certificate -> DER -> CERT_CONTEXT ---- */
    std::string certPem = ReadFile(DllPath("ssl\\server.crt"));
    if (certPem.empty()) {
        Log("SSL: ssl\\server.crt not found");
        return false;
    }
    static const char CERT_HDR[] = "-----BEGIN CERTIFICATE-----";
    static const char CERT_FTR[] = "-----END CERTIFICATE-----";
    size_t hs = certPem.find(CERT_HDR);
    size_t fe = (hs != std::string::npos) ? certPem.find(CERT_FTR, hs + strlen(CERT_HDR)) : std::string::npos;
    if (hs == std::string::npos || fe == std::string::npos) {
        Log("SSL: ssl\\server.crt has no valid PEM CERTIFICATE block");
        return false;
    }
    hs += strlen(CERT_HDR);
    std::string rawCert = certPem.substr(hs, fe - hs);
    std::string b64Cert;
    for (size_t i = 0; i < rawCert.size(); i++)
        if (!isspace((unsigned char)rawCert[i])) b64Cert += rawCert[i];
    std::vector<unsigned char> certDer = Base64Decode(b64Cert);
    if (certDer.empty()) { Log("SSL: cert base64-decode failed"); return false; }

    g_pCert = CertCreateCertificateContext(
        X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
        &certDer[0], (DWORD)certDer.size());
    if (!g_pCert) {
        Log("SSL: CertCreateCertificateContext failed (err=%lu)", GetLastError());
        return false;
    }

    /* ---- 2. Decode PEM private key -> CAPI PRIVATEKEYBLOB ---- */
    std::string keyPem = ReadFile(DllPath("ssl\\server.key"));
    if (keyPem.empty()) {
        Log("SSL: ssl\\server.key not found");
        CertFreeCertificateContext(g_pCert); g_pCert = NULL;
        return false;
    }
    static const char* KH[] = {
        "-----BEGIN RSA PRIVATE KEY-----",
        "-----BEGIN PRIVATE KEY-----",
        NULL
    };
    static const char* KF[] = {
        "-----END RSA PRIVATE KEY-----",
        "-----END PRIVATE KEY-----",
        NULL
    };
    std::string b64Key; bool pkcs8 = false;
    for (int i = 0; KH[i]; i++) {
        size_t khs = keyPem.find(KH[i]); if (khs == std::string::npos) continue;
        khs += strlen(KH[i]);
        size_t kfe = keyPem.find(KF[i], khs); if (kfe == std::string::npos) continue;
        std::string rawKey = keyPem.substr(khs, kfe - khs);
        for (size_t j = 0; j < rawKey.size(); j++)
            if (!isspace((unsigned char)rawKey[j])) b64Key += rawKey[j];
        pkcs8 = (i == 1); break;
    }
    if (b64Key.empty()) {
        Log("SSL: ssl\\server.key has no recognized PEM private key header");
        CertFreeCertificateContext(g_pCert); g_pCert = NULL;
        return false;
    }
    std::vector<unsigned char> keyDer = Base64Decode(b64Key);
    if (keyDer.empty()) {
        Log("SSL: key base64-decode failed");
        CertFreeCertificateContext(g_pCert); g_pCert = NULL;
        return false;
    }

    BYTE*  pbBlob = NULL;
    DWORD  cbBlob = 0;
    if (pkcs8) {
        /* Unwrap PKCS#8 envelope first */
        CRYPT_PRIVATE_KEY_INFO* pki = NULL; DWORD cbPki = 0;
        if (!CryptDecodeObjectEx(X509_ASN_ENCODING, PKCS_PRIVATE_KEY_INFO,
                &keyDer[0], (DWORD)keyDer.size(),
                CRYPT_DECODE_ALLOC_FLAG, NULL, &pki, &cbPki)) {
            Log("SSL: CryptDecodeObjectEx(PKCS8) failed (err=%lu)", GetLastError());
            CertFreeCertificateContext(g_pCert); g_pCert = NULL;
            return false;
        }
        CryptDecodeObjectEx(X509_ASN_ENCODING, PKCS_RSA_PRIVATE_KEY,
                pki->PrivateKey.pbData, pki->PrivateKey.cbData,
                CRYPT_DECODE_ALLOC_FLAG, NULL, &pbBlob, &cbBlob);
        LocalFree(pki);
    } else {
        CryptDecodeObjectEx(X509_ASN_ENCODING, PKCS_RSA_PRIVATE_KEY,
                &keyDer[0], (DWORD)keyDer.size(),
                CRYPT_DECODE_ALLOC_FLAG, NULL, &pbBlob, &cbBlob);
    }
    if (!pbBlob) {
        Log("SSL: CryptDecodeObjectEx(RSA key) failed (err=%lu)", GetLastError());
        CertFreeCertificateContext(g_pCert); g_pCert = NULL;
        return false;
    }

    /* ---- 3. Import key into a named user-space key container ---- */
    /* SChannel requires the private key to live in a named CSP container
     * so it can open it by name via CERT_KEY_PROV_INFO_PROP_ID.
     * User-space containers require no admin rights. */
    static const char  kContA[] = "HWSSSLKey";
    static const WCHAR kContW[] = L"HWSSSLKey";

    HCRYPTPROV hProv = NULL;
    if (!CryptAcquireContextA(&hProv, kContA, NULL, PROV_RSA_FULL, 0)) {
        /* Container doesn't exist yet — create it */
        if (!CryptAcquireContextA(&hProv, kContA, NULL, PROV_RSA_FULL, CRYPT_NEWKEYSET)) {
            Log("SSL: CryptAcquireContext failed (err=%lu)", GetLastError());
            LocalFree(pbBlob);
            CertFreeCertificateContext(g_pCert); g_pCert = NULL;
            return false;
        }
    }

    HCRYPTKEY hKey = NULL;
    if (!CryptImportKey(hProv, pbBlob, cbBlob, 0, CRYPT_EXPORTABLE, &hKey)) {
        Log("SSL: CryptImportKey failed (err=%lu)", GetLastError());
        LocalFree(pbBlob);
        CryptReleaseContext(hProv, 0);
        CertFreeCertificateContext(g_pCert); g_pCert = NULL;
        return false;
    }
    CryptDestroyKey(hKey);   /* key is now stored in the container */
    LocalFree(pbBlob);
    CryptReleaseContext(hProv, 0);

    /* ---- 4. Attach key container to the cert context ---- */
    CRYPT_KEY_PROV_INFO kpi = {0};
    kpi.pwszContainerName = const_cast<LPWSTR>(kContW);
    kpi.pwszProvName      = NULL;          /* default provider */
    kpi.dwProvType        = PROV_RSA_FULL;
    kpi.dwFlags           = 0;
    kpi.cProvParam        = 0;
    kpi.rgProvParam       = NULL;
    kpi.dwKeySpec         = AT_KEYEXCHANGE;
    if (!CertSetCertificateContextProperty(g_pCert, CERT_KEY_PROV_INFO_PROP_ID, 0, &kpi)) {
        Log("SSL: CertSetCertificateContextProperty failed (err=%lu)", GetLastError());
        CertFreeCertificateContext(g_pCert); g_pCert = NULL;
        return false;
    }

    Log("SSL: PEM cert+key loaded OK (PKCS#%d key, no PFX needed)", pkcs8 ? 8 : 1);
    return true;
}

static bool InitSChannel()
{
    if(!g_pCert) return false;
    SCHANNEL_CRED cred={0};
    cred.dwVersion=SCHANNEL_CRED_VERSION;
    cred.cCreds=1; cred.paCred=&g_pCert;
    cred.grbitEnabledProtocols=
        SP_PROT_TLS1_SERVER|SP_PROT_TLS1_1_SERVER|SP_PROT_TLS1_2_SERVER;
    cred.dwFlags=SCH_CRED_NO_SYSTEM_MAPPER|SCH_CRED_NO_DEFAULT_CREDS;
    SECURITY_STATUS ss=AcquireCredentialsHandleA(
        NULL,(char*)UNISP_NAME_A,SECPKG_CRED_INBOUND,
        NULL,&cred,NULL,NULL,&g_hCred,NULL);
    g_credValid=(ss==SEC_E_OK);
    return g_credValid;
}

struct SslCtx {
    CtxtHandle hCtxt; BOOL valid;
    SecPkgContext_StreamSizes sizes;
    std::vector<BYTE> extra;
};

static bool SslHandshake(SOCKET s, SslCtx& ctx)
{
    ctx.valid=FALSE;
    const DWORD F=ASC_REQ_SEQUENCE_DETECT|ASC_REQ_REPLAY_DETECT|
                  ASC_REQ_CONFIDENTIALITY|ASC_RET_EXTENDED_ERROR|
                  ASC_REQ_ALLOCATE_MEMORY|ASC_REQ_STREAM;
    std::vector<BYTE> ib(32768); int ibLen=0;
    BOOL first=TRUE; SecBuffer sb[2],ob[1];
    SecBufferDesc ibd,obd; DWORD outF=0;
    while(true){
        /* receive */
        {fd_set fds;struct timeval tv={5,0};FD_ZERO(&fds);FD_SET(s,&fds);
         if(select(0,&fds,NULL,NULL,&tv)<=0) return false;
         int r=recv(s,(char*)&ib[ibLen],(int)ib.size()-ibLen,0);
         if(r<=0) return false; ibLen+=r;}
        sb[0]={(ULONG)ibLen,SECBUFFER_TOKEN,&ib[0]};
        sb[1]={0,SECBUFFER_EMPTY,NULL};
        ibd={SECBUFFER_VERSION,2,sb};
        ob[0]={0,SECBUFFER_TOKEN,NULL};
        obd={SECBUFFER_VERSION,1,ob};
        SECURITY_STATUS ss=AcceptSecurityContext(&g_hCred,
            first?NULL:&ctx.hCtxt,&ibd,F,SECURITY_NATIVE_DREP,
            &ctx.hCtxt,&obd,&outF,NULL);
        first=FALSE;
        if(ob[0].cbBuffer>0&&ob[0].pvBuffer)
            {send(s,(char*)ob[0].pvBuffer,ob[0].cbBuffer,0);FreeContextBuffer(ob[0].pvBuffer);}
        if(ss==SEC_E_OK){
            if(sb[1].BufferType==SECBUFFER_EXTRA&&sb[1].cbBuffer>0)
                ctx.extra.assign((BYTE*)sb[1].pvBuffer,(BYTE*)sb[1].pvBuffer+sb[1].cbBuffer);
            QueryContextAttributes(&ctx.hCtxt,SECPKG_ATTR_STREAM_SIZES,&ctx.sizes);
            ctx.valid=TRUE; return true;
        }
        if(ss==SEC_I_CONTINUE_NEEDED){
            if(sb[1].BufferType==SECBUFFER_EXTRA&&sb[1].cbBuffer>0)
                {memmove(&ib[0],&ib[ibLen-sb[1].cbBuffer],sb[1].cbBuffer);ibLen=sb[1].cbBuffer;}
            else ibLen=0;
            continue;
        }
        return false;
    }
}

static bool SslRead(SOCKET s, SslCtx& ctx, std::string& out)
{
    /* Ciphertext buffer — grows dynamically so large uploads never hit the cap.
     * A TLS record is at most ~16 KB, but a place file can be many megabytes
     * spread across hundreds of records. */
    DWORD cap = ctx.sizes.cbHeader + ctx.sizes.cbMaximumMessage + ctx.sizes.cbTrailer + 65536;
    std::vector<BYTE> eb(cap); DWORD eLen = 0;
    if (!ctx.extra.empty()) {
        memcpy(&eb[0], &ctx.extra[0], ctx.extra.size());
        eLen = (DWORD)ctx.extra.size();
        ctx.extra.clear();
    }
    while (true) {
        SecBuffer db[4];
        db[0] = {(ULONG)eLen, SECBUFFER_DATA,  &eb[0]};
        db[1] = {0,           SECBUFFER_EMPTY, NULL};
        db[2] = {0,           SECBUFFER_EMPTY, NULL};
        db[3] = {0,           SECBUFFER_EMPTY, NULL};
        SecBufferDesc dbd = {SECBUFFER_VERSION, 4, db};
        SECURITY_STATUS ss = DecryptMessage(&ctx.hCtxt, &dbd, 0, NULL);
        if (ss == SEC_E_OK) {
            for (int i = 0; i < 4; i++)
                if (db[i].BufferType == SECBUFFER_DATA)
                    out.append((char*)db[i].pvBuffer, db[i].cbBuffer);
            /* Save leftover ciphertext (pipelined next request) */
            ctx.extra.clear();
            for (int i = 0; i < 4; i++)
                if (db[i].BufferType == SECBUFFER_EXTRA && db[i].cbBuffer > 0)
                    ctx.extra.assign((BYTE*)db[i].pvBuffer,
                                     (BYTE*)db[i].pvBuffer + db[i].cbBuffer);
            /* KEY FIX: keep reading TLS records until the FULL HTTP body has
             * arrived.  The old code returned as soon as \r\n\r\n appeared,
             * which meant the body of large POSTs (place uploads) was always
             * empty — Studio sends headers in one TLS record, body in the next. */
            if (HttpRequestComplete(out)) return true;
            /* More records needed — consume any EXTRA bytes first */
            eLen = 0;
            if (!ctx.extra.empty()) {
                memcpy(&eb[0], &ctx.extra[0], ctx.extra.size());
                eLen = (DWORD)ctx.extra.size();
                ctx.extra.clear();
            }
        } else if (ss == SEC_E_INCOMPLETE_MESSAGE) {
            /* Not enough ciphertext yet for a full TLS record — read more. */
            if (eLen >= cap) {          /* grow buffer for very large records */
                cap *= 2;
                eb.resize(cap);
            }
            fd_set fds; struct timeval tv = {30, 0}; /* 30 s for large uploads */
            FD_ZERO(&fds); FD_SET(s, &fds);
            if (select(0, &fds, NULL, NULL, &tv) <= 0) return false;
            int r = recv(s, (char*)&eb[eLen], (int)(cap - eLen), 0);
            if (r <= 0) return false;
            eLen += r;
        } else {
            return false;
        }
    }
}

static bool SslWrite(SOCKET s, SslCtx& ctx, const std::string& data)
{
    size_t off=0;
    while(off<data.size()){
        size_t chunk=std::min((size_t)ctx.sizes.cbMaximumMessage,data.size()-off);
        size_t total=ctx.sizes.cbHeader+chunk+ctx.sizes.cbTrailer;
        std::vector<BYTE> buf(total);
        memcpy(&buf[ctx.sizes.cbHeader],data.c_str()+off,chunk);
        SecBuffer sb[3];
        sb[0]={ctx.sizes.cbHeader,SECBUFFER_STREAM_HEADER,&buf[0]};
        sb[1]={(ULONG)chunk,SECBUFFER_DATA,&buf[ctx.sizes.cbHeader]};
        sb[2]={ctx.sizes.cbTrailer,SECBUFFER_STREAM_TRAILER,&buf[ctx.sizes.cbHeader+chunk]};
        SecBufferDesc sbd={SECBUFFER_VERSION,3,sb};
        if(EncryptMessage(&ctx.hCtxt,0,&sbd,0)!=SEC_E_OK) return false;
        DWORD toSend=sb[0].cbBuffer+sb[1].cbBuffer+sb[2].cbBuffer;
        if(send(s,(char*)&buf[0],toSend,0)!=(int)toSend) return false;
        off+=chunk;
    }
    return true;
}

/* ============================================================================
   SECTION 14 — Connection worker thread
   ========================================================================= */
struct ClientArg { SOCKET s; BOOL ssl; };

static DWORD WINAPI ClientThread(LPVOID param)
{
    ClientArg* a=(ClientArg*)param; SOCKET s=a->s; BOOL isSsl=a->ssl; delete a;
    std::string rawReq; SslCtx sslCtx; sslCtx.valid=FALSE;
    if(isSsl){
        if(!g_credValid||!SslHandshake(s,sslCtx)){closesocket(s);return 0;}
        if(!SslRead(s,sslCtx,rawReq)){closesocket(s);return 0;}
    } else {
        if(!RecvFull(s,rawReq)){closesocket(s);return 0;}
    }
    Req req; if(!ParseHttp(rawReq,req)){closesocket(s);return 0;}
    /* Hold every reply until the Roblox cookie prompt has been completed or
     * skipped, so Studio's launch waits for the user instead of racing ahead
     * with no credentials. /ping is exempt so the watchdog's health checks stay
     * responsive (no spurious failover). Once signaled the wait returns
     * instantly; the 5-min cap is just a safety net against a stuck prompt. */
    if(g_cookieReadyEvent && !STARTS(req.path,"/ping"))
        WaitForSingleObject(g_cookieReadyEvent, 300000);
    Resp resp=Route(req);
    if (req.path != "/ping" && !STARTS(req.path, "/ping")
        && resp.contentType.find("json") != std::string::npos
        && resp.body.size() < 4096)
        Log("<< %s -> %s", req.path.c_str(), resp.body.c_str());
    std::string raw=BuildRaw(resp);
    if(isSsl&&sslCtx.valid){
        SslWrite(s,sslCtx,raw);
        /* graceful TLS shutdown */
        DWORD tok=SCHANNEL_SHUTDOWN;
        SecBuffer sb={sizeof(DWORD),SECBUFFER_TOKEN,&tok};
        SecBufferDesc sbd={SECBUFFER_VERSION,1,&sb};
        ApplyControlToken(&sslCtx.hCtxt,&sbd);
        sb={0,SECBUFFER_TOKEN,NULL}; sbd={SECBUFFER_VERSION,1,&sb};
        DWORD outF=0;
        AcceptSecurityContext(&g_hCred,&sslCtx.hCtxt,NULL,0,0,NULL,&sbd,&outF,NULL);
        if(sb.pvBuffer){send(s,(char*)sb.pvBuffer,sb.cbBuffer,0);FreeContextBuffer(sb.pvBuffer);}
        DeleteSecurityContext(&sslCtx.hCtxt);
    } else {
        send(s,raw.c_str(),(int)raw.size(),0);
    }
    closesocket(s); return 0;
}

static void AcceptLoop(SOCKET ls, BOOL isSsl)
{
    while(!g_shutdown){
        fd_set fds; struct timeval tv={1,0};
        FD_ZERO(&fds); FD_SET(ls,&fds);
        if(select(0,&fds,NULL,NULL,&tv)<=0) continue;
        SOCKET c=accept(ls,NULL,NULL);
        if(c==INVALID_SOCKET) continue;
        ClientArg* a=new ClientArg(); a->s=c; a->ssl=isSsl;
        HANDLE h=CreateThread(NULL,0,ClientThread,(LPVOID)a,0,NULL);
        if(h) CloseHandle(h);
    }
}

/* ============================================================================
   SECTION 15 — Server threads
   ========================================================================= */
static SOCKET BindListen(int port)
{
    SOCKET s=socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);
    if(s==INVALID_SOCKET) return INVALID_SOCKET;
    int yes=1; setsockopt(s,SOL_SOCKET,SO_REUSEADDR,(char*)&yes,sizeof(yes));
    SOCKADDR_IN a={0};
    a.sin_family=AF_INET; a.sin_port=htons((u_short)port); a.sin_addr.s_addr=INADDR_ANY;
    if(bind(s,(SOCKADDR*)&a,sizeof(a))!=0||listen(s,SOMAXCONN)!=0)
        {closesocket(s);return INVALID_SOCKET;}
    return s;
}

static DWORD WINAPI HttpThread(LPVOID)  { AcceptLoop(g_httpSock, FALSE); return 0; }
static DWORD WINAPI HttpsThread(LPVOID) { AcceptLoop(g_httpsSock,TRUE);  return 0; }

/* ============================================================================
   SECTION 16 — Instance election (named mutex) + watchdog
   ========================================================================= */
static bool PingServer()
{
    SOCKET s=socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);
    if(s==INVALID_SOCKET) return false;
    u_long nb=1; ioctlsocket(s,FIONBIO,&nb);
    SOCKADDR_IN a={0}; a.sin_family=AF_INET;
    a.sin_port=htons((u_short)g_httpPort); a.sin_addr.s_addr=inet_addr("127.0.0.1");
    connect(s,(SOCKADDR*)&a,sizeof(a));
    fd_set fds; struct timeval tv={2,0}; FD_ZERO(&fds); FD_SET(s,&fds);
    if(select(0,NULL,&fds,NULL,&tv)<=0){closesocket(s);return false;}
    nb=0; ioctlsocket(s,FIONBIO,&nb);
    const char r[]="GET /ping HTTP/1.0\r\nHost:127.0.0.1\r\n\r\n";
    send(s,r,(int)strlen(r),0);
    char buf[32]={0}; struct timeval tv2={2,0};
    FD_ZERO(&fds);FD_SET(s,&fds);
    if(select(0,&fds,NULL,NULL,&tv2)>0) recv(s,buf,31,0);
    closesocket(s);
    return strstr(buf,"OK")!=NULL;
}

static bool TryBecomeServer()
{
    /* try to own the election mutex — only one process wins */
    g_hOwnerMutex=CreateMutexA(NULL,TRUE,"Global\\HookedWebserver_Port80_Owner");
    if(!g_hOwnerMutex||GetLastError()==ERROR_ALREADY_EXISTS){
        if(g_hOwnerMutex){CloseHandle(g_hOwnerMutex);g_hOwnerMutex=NULL;}
        return false;
    }
    g_httpSock=BindListen(g_httpPort);
    if(g_httpSock==INVALID_SOCKET){
        ReleaseMutex(g_hOwnerMutex);CloseHandle(g_hOwnerMutex);g_hOwnerMutex=NULL;
        return false;
    }
    g_httpsSock=g_credValid?BindListen(g_httpsPort):INVALID_SOCKET;
    g_isServer=TRUE;
    HANDLE h; h=CreateThread(NULL,0,HttpThread,NULL,0,NULL); if(h)CloseHandle(h);
    if(g_httpsSock!=INVALID_SOCKET){h=CreateThread(NULL,0,HttpsThread,NULL,0,NULL);if(h)CloseHandle(h);}
    return true;
}

static DWORD WINAPI WatchdogThread(LPVOID)
{
    int fails=0;
    while(!g_shutdown){
        Sleep(g_wdInterval);
        if(g_isServer){fails=0;continue;}
        if(PingServer()){fails=0;continue;}
        if(++fails>=g_wdRetries){
            fails=0;
            if(g_hOwnerMutex){ReleaseMutex(g_hOwnerMutex);CloseHandle(g_hOwnerMutex);g_hOwnerMutex=NULL;}
            TryBecomeServer();
        }
    }
    return 0;
}

/* ============================================================================
   SECTION 17 — Startup thread (spawned from DllMain — never blocks DllMain)
   ========================================================================= */
static DWORD WINAPI StartupThread(LPVOID)
{
    InitDllDir();
    LoadConfig();
    LoadUsername();

    Log("=== HookedWebserver startup ===");
    Log("DLL directory: %s", g_dllDir);
    Log("Username: %s  UserId: %s", g_username.c_str(), g_userId.c_str());
    Log("HTTP port: %d  HTTPS port: %d", g_httpPort, g_httpsPort);

    WSADATA wsa; WSAStartup(MAKEWORD(2,2),&wsa);
    Log("Winsock initialized");

    /* Pop the Roblox cookie login NOW and gate request handling on it, so
     * Studio's launch is delayed until the user completes or skips it. The
     * event must exist before any ClientThread can run (i.e. before the
     * listener starts in TryBecomeServer below). */
    g_cookieReadyEvent = CreateEvent(NULL, TRUE, FALSE, NULL);   /* manual-reset, unsignaled */
    HANDLE hcw = CreateThread(NULL, 0, CookieWarmupThread, NULL, 0, NULL);
    if (hcw) CloseHandle(hcw);

    /* ensure data directories exist, relative to DLL */
    EnsureDir(DllPath("data"));
    EnsureDir(DllPath("data\\datastores"));
    EnsureDir(DllPath("data\\persistence"));
    EnsureDir(DllPath("data\\SavedData"));
    EnsureDir(DllPath("data\\universes"));

    LoadSignKey();
    Log("Sign key: %s", g_signKeyLoaded ? "loaded OK" : "not found (join scripts will use stub sig)");

    BOOL sslOk = LoadSslCert();
    if (sslOk) {
        sslOk = InitSChannel();
        Log("SSL/TLS: %s", sslOk ? "loaded OK" : "SChannel init failed");
    } else {
        Log("SSL/TLS: ssl\\server.crt / ssl\\server.key not found — copy from Apache certificats folder");
    }

    BOOL becameServer = TryBecomeServer();
    if (becameServer) {
        Log("Server ACTIVE — listening on HTTP:%d%s",
            g_httpPort,
            (g_httpsSock!=INVALID_SOCKET) ? " and HTTPS:443" : " (HTTPS not available)");
    } else {
        Log("Server WATCHDOG — another instance owns port %d, monitoring...", g_httpPort);
    }

    /* always run watchdog — idles harmlessly if we are the server */
    HANDLE h=CreateThread(NULL,0,WatchdogThread,NULL,0,NULL);
    if(h) CloseHandle(h);

    /* (cookie prompt + readiness gate were started early, above) */

    Log("Startup complete.");
    return 0;
}

/* ============================================================================
   SECTION 18 — Exported functions + DllMain
   ========================================================================= */
extern "C" {
__declspec(dllexport) void   WINAPI HWS_Start()    { /* auto-started in DllMain */ }
__declspec(dllexport) void   WINAPI HWS_Stop()     { g_shutdown=TRUE; }
__declspec(dllexport) BOOL   WINAPI HWS_IsServer() { return g_isServer; }
__declspec(dllexport) int    WINAPI HWS_GetPort()  { return g_isServer?g_httpPort:0; }
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID)
{
    if(reason==DLL_PROCESS_ATTACH){
        g_hDll=hModule;
        DisableThreadLibraryCalls(hModule);
        /* never block the loader — spin up everything in a background thread */
        HANDLE h=CreateThread(NULL,0,StartupThread,NULL,0,NULL);
        if(h) CloseHandle(h);
    }
    else if(reason==DLL_PROCESS_DETACH){
        g_shutdown=TRUE;
        if(g_httpSock !=INVALID_SOCKET) closesocket(g_httpSock);
        if(g_httpsSock!=INVALID_SOCKET) closesocket(g_httpsSock);
        if(g_hOwnerMutex){ReleaseMutex(g_hOwnerMutex);CloseHandle(g_hOwnerMutex);}
        if(g_signKeyLoaded){CryptDestroyKey(g_hSignKey);CryptReleaseContext(g_hSignProv,0);}
        if(g_credValid) FreeCredentialsHandle(&g_hCred);
        if(g_pCert)     CertFreeCertificateContext(g_pCert);
        WSACleanup();
    }
    return TRUE;
}