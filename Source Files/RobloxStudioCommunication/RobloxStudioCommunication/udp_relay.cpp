// udp_relay.cpp - implementation of the UDP magic-packet username relay.
//
// See udp_relay.h for the design overview and wire format. This file
// contains the IAT hooks and the IP->username map.
#include "udp_relay.h"
#include "iat_hook.h"
#include "name_patcher.h"
#include "rcc_patch.h"
#include "server_console.h"
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <mswsock.h>
#include <winhttp.h>
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "winhttp.lib")
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <map>
#include <mutex>
#include <set>
#include <string>
namespace RobloxStudioPatcher
{
    // ---------- Magic header ----------------------------------------------
    static const uint32_t kMagic = 0xC0DE5A45;
    static const uint8_t  kVersion = 3;          // v3 = name + userId + accountAge + appearance
    static const size_t   kHeaderSize = 6;          // magic(4) + ver(1) + nameLen(1)
    static const size_t   kMaxName = 255;        // nameLen is a byte
    static const size_t   kIdTrailer = 12;         // userId(8 BE) + accountAge(4 BE)
    static const size_t   kMaxApp = 8192;       // appearance blob (v3): appLen(2 BE) + data
    static const size_t   kMaxPacket = kHeaderSize + kMaxName + kIdTrailer + 2 + kMaxApp;
    // ---------- Username cache --------------------------------------------
    static std::mutex      s_usernameMutex;
    static std::string     s_cachedUsername;
    static std::string GetUsernameAscii()
    {
        std::lock_guard<std::mutex> lock(s_usernameMutex);
        if (!s_cachedUsername.empty()) return s_cachedUsername;
        std::wstring dir = GetDllDirectory();
        if (dir.empty()) return {};
        std::wstring w = ReadTextFileTrimmed(dir + L"username.txt");
        if (w.empty()) return {};
        std::string out;
        out.reserve(w.size());
        for (wchar_t c : w)
        {
            if (c >= 32 && c <= 126) out.push_back(static_cast<char>(c));
        }
        if (out.size() > kMaxName) out.resize(kMaxName);
        s_cachedUsername = out;
        return out;
    }
    // Read a decimal number from a sidecar file next to the DLL (e.g.
    // "userid.txt", "accountage.txt"). Returns 0 if missing/empty/invalid.
    static unsigned long long ReadNumberSidecar(const wchar_t* fileName)
    {
        std::wstring dir = GetDllDirectory();
        if (dir.empty()) return 0;
        std::wstring w = ReadTextFileTrimmed(dir + fileName);
        if (w.empty()) return 0;
        return _wcstoui64(w.c_str(), nullptr, 10);
    }
    // AccountAge is hardcoded (no sidecar) - change this one value to whatever
    // account age in days the joining player should report.
    static const uint32_t kHardcodedAccountAge = 3650;   // ~10 years
    static uint64_t GetUserIdToSend() { return ReadNumberSidecar(L"userid.txt"); }
    static uint32_t GetAccountAgeToSend() { return kHardcodedAccountAge; }
    static std::string AsciiOf(const std::wstring& w)
    {
        std::string out; for (wchar_t c : w) if (c >= 32 && c <= 126) out.push_back((char)c);
        return out;
    }
    // Read one BrickColor name from BodyColors\<file> next to the DLL.
    static std::string ReadBodyColor(const std::wstring& dir, const wchar_t* file)
    {
        std::wstring w = ReadTextFileTrimmed(dir + L"BodyColors\\" + file);
        if (w.empty()) w = ReadTextFileTrimmed(dir + L"Settings\\BodyColors\\" + file);
        return AsciiOf(w);
    }
    // Client side: read this player's avatar appearance (Appearence.ini next to
    // the DLL), and append the 6 body-part BrickColor names as a trailer:
    //   <asset urls>|COLORS|head;torso;leftArm;rightArm;leftLeg;rightLeg
    // The webserver converts the BrickColor names to bodyColor3s. Capped to kMaxApp.
    static std::string GetAppearanceAscii()
    {
        std::wstring dir = GetDllDirectory();
        if (dir.empty()) return {};
        std::wstring w = ReadTextFileTrimmed(dir + L"Appearence.ini");
        if (w.empty()) w = ReadTextFileTrimmed(dir + L"Appearance.ini");
        std::string out = AsciiOf(w);
        std::string h = ReadBodyColor(dir, L"HeadColor.txt");
        std::string t = ReadBodyColor(dir, L"TorsoColor.txt");
        std::string la = ReadBodyColor(dir, L"LeftArmColor.txt");
        std::string ra = ReadBodyColor(dir, L"RightArmColor.txt");
        std::string ll = ReadBodyColor(dir, L"LeftLegColor.txt");
        std::string rl = ReadBodyColor(dir, L"RightLegColor.txt");
        if (!(h.empty() && t.empty() && la.empty() && ra.empty() && ll.empty() && rl.empty()))
            out += "|COLORS|" + h + ";" + t + ";" + la + ";" + ra + ";" + ll + ";" + rl;
        if (out.empty()) return {};
        if (out.size() > kMaxApp) out.resize(kMaxApp);
        return out;
    }
    // Host side: hand a received appearance to the local HookedWebserver via
    //   POST https://127.0.0.1:443/offblox/appearance?username=<name>
    // WinHTTP handles the TLS; we ignore the self-signed localhost cert. Short
    // timeouts so a slow/absent webserver can never hang the receive thread.
    static void PostAppearanceToLocal(const std::string& username,
        const std::string& appearance)
    {
        std::wstring wpath = L"/offblox/appearance?username=";
        for (char c : username) wpath.push_back((wchar_t)(unsigned char)c);
        HINTERNET hSession = WinHttpOpen(L"OffBlox/1.0",
            WINHTTP_ACCESS_TYPE_NO_PROXY, WINHTTP_NO_PROXY_NAME,
            WINHTTP_NO_PROXY_BYPASS, 0);
        if (!hSession) return;
        WinHttpSetTimeouts(hSession, 2000, 2000, 2000, 2000);
        BOOL ok = FALSE;
        HINTERNET hConnect = WinHttpConnect(hSession, L"127.0.0.1", 443, 0);
        if (hConnect)
        {
            HINTERNET hReq = WinHttpOpenRequest(hConnect, L"POST", wpath.c_str(),
                NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES,
                WINHTTP_FLAG_SECURE);
            if (hReq)
            {
                DWORD secFlags = SECURITY_FLAG_IGNORE_UNKNOWN_CA
                    | SECURITY_FLAG_IGNORE_CERT_CN_INVALID
                    | SECURITY_FLAG_IGNORE_CERT_DATE_INVALID
                    | SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE;
                WinHttpSetOption(hReq, WINHTTP_OPTION_SECURITY_FLAGS,
                    &secFlags, sizeof(secFlags));
                ok = WinHttpSendRequest(hReq,
                    L"Content-Type: text/plain\r\n", (DWORD)-1L,
                    (LPVOID)appearance.data(), (DWORD)appearance.size(),
                    (DWORD)appearance.size(), 0);
                if (ok) WinHttpReceiveResponse(hReq, NULL);
                WinHttpCloseHandle(hReq);
            }
            WinHttpCloseHandle(hConnect);
        }
        WinHttpCloseHandle(hSession);
        LogF(L"[udp_relay] POSTed appearance for '%hs' (%d chars) -> "
            L"https://127.0.0.1:443 ok=%d\n",
            username.c_str(), (int)appearance.size(), (int)ok);
    }
    // ---------- Destinations we've already announced to --------------------
    static std::mutex          s_destMutex;
    static std::set<uint64_t>  s_destsSeen;      // (ip << 16) | port
    static bool ShouldAnnounceToDest(const sockaddr* to, int tolen)
    {
        if (!to || tolen < (int)sizeof(sockaddr_in) || to->sa_family != AF_INET)
            return false;
        const sockaddr_in* dst = reinterpret_cast<const sockaddr_in*>(to);
        char ipStr[INET_ADDRSTRLEN] = {};
        inet_ntop(AF_INET, &dst->sin_addr, ipStr, sizeof(ipStr));
        if (dst->sin_addr.s_addr == 0)
        {
            LOG(L"[udp_relay] ShouldAnnounce: SKIP zero addr\n");
            return false;
        }
        // SKIP loopback (127.0.0.0/8). Under RbxTransport the engine's only
        // sendto destination is the vestigial local RakNet DummyServer on
        // 127.x - announcing into it goes nowhere AND injecting a foreign
        // datagram there desyncs that RakNet stub (this is what broke RakNet).
        // The real host is reached by the dedicated MagicAnnouncerThread.
        if ((ntohl(dst->sin_addr.s_addr) & 0xFF000000u) == 0x7F000000u)
        {
            LOG(L"[udp_relay] ShouldAnnounce: SKIP loopback\n");
            return false;
        }
        uint64_t key = (uint64_t(dst->sin_addr.s_addr) << 16) | ntohs(dst->sin_port);
        std::lock_guard<std::mutex> lock(s_destMutex);
        bool first = s_destsSeen.insert(key).second;
        LOG(L"[udp_relay] ShouldAnnounce: %hs:%d first=%d\n",
            ipStr, ntohs(dst->sin_port), (int)first);
        return first;
    }
    // ---------- Originals saved by the IAT hook installer -----------------
    using PFN_sendto = int (WINAPI*)(SOCKET, const char*, int, int,
        const sockaddr*, int);
    using PFN_recvfrom = int (WINAPI*)(SOCKET, char*, int, int,
        sockaddr*, int*);
    using PFN_WSASendTo = int (WINAPI*)(SOCKET, LPWSABUF, DWORD, LPDWORD,
        DWORD, const sockaddr*, int,
        LPWSAOVERLAPPED,
        LPWSAOVERLAPPED_COMPLETION_ROUTINE);
    using PFN_WSARecvFrom = int (WINAPI*)(SOCKET, LPWSABUF, DWORD, LPDWORD,
        LPDWORD, sockaddr*, LPINT,
        LPWSAOVERLAPPED,
        LPWSAOVERLAPPED_COMPLETION_ROUTINE);
    // WSARecv - connected-socket variant (no from/fromlen).
    // RakNet on 2023 Studio uses this instead of WSARecvFrom.
    using PFN_WSARecv = int (WINAPI*)(SOCKET, LPWSABUF, DWORD, LPDWORD,
        LPDWORD,
        LPWSAOVERLAPPED,
        LPWSAOVERLAPPED_COMPLETION_ROUTINE);
    static PFN_sendto      s_orig_sendto = nullptr;
    static PFN_recvfrom    s_orig_recvfrom = nullptr;
    static PFN_WSASendTo   s_orig_WSASendTo = nullptr;
    static PFN_WSARecvFrom s_orig_WSARecvFrom = nullptr;
    static PFN_WSARecv     s_orig_WSARecv = nullptr;
    // ---------- Anti-impersonation (host side) ----------------------------
    //
    // Every joining client announces its username in a magic packet, and every
    // datagram carries its source ip:port (recovered via getpeername on the
    // connected WSARecv path). We track which username belongs to which LIVE
    // connection. Instead of cutting impostors, we let them in but force their
    // in-game name to the default "Player%d" (and skip applying their relayed
    // identity/appearance) when they claim:
    //   * a username already held by another still-active connection, or
    //   * the HOST's own username from a non-loopback ip.
    // Non-conflicting joins keep their custom name as usual.
    //
    // IMPORTANT: the conflict test keys on the SOURCE CONNECTION (ip:port ->
    // SourceKey), NOT on userId. Every client instance reads the same sidecar
    // files, so two different players announce the SAME name AND the SAME
    // userId - userId therefore cannot tell "my own re-announce" apart from "a
    // second person with my name", and keying on it let real duplicates through.
    // The client fires its identity magic ~30x from ONE stable socket, so all
    // its repeats share ONE source key (recognised here as a repeat, no flip).
    // A genuinely separate connection arrives on a DIFFERENT key; if the name
    // is still held by a live connection that second claimant is forced to the
    // default "Player%d".
    static const DWORD kPeerTimeoutMs = 2000;   // unseen this long => "gone"
    struct PeerInfo { std::string username; DWORD lastSeen; };
    static std::mutex                      s_peerMutex;
    static std::map<uint64_t, PeerInfo>    s_peers;      // src key -> {username,uid,lastSeen}
    static std::map<std::string, uint64_t> s_userToKey;  // username -> current src key

    // After a player leaves we briefly ignore re-announces from THAT source key:
    // the leaving client's announcer keeps firing for a moment, which would
    // otherwise free-then-instantly-rejoin the same name. Refreshed on each
    // swallowed packet, so it clears shortly after the announcer actually stops.
    // A genuine rejoin opens a fresh socket (different key) and is unaffected.
    static const DWORD                     kLeaveCooldownMs = 2500;
    static std::map<uint64_t, DWORD>       s_leftCooldown;   // left key -> last-seen tick

    // A connection forced to the default name (rejected) keeps sending its join
    // burst; remember it briefly so we log/patch the rejection ONCE instead of
    // once per datagram. (Accepted joins are already deduped via s_userToKey.)
    static const DWORD                     kForcedDedupMs = 3000;
    static std::map<uint64_t, DWORD>       s_forcedRecent;   // forced key -> last-seen tick

    // Anti-impersonation: a name is protected while its holder's peer is still
    // present. Leave detection (PlayerRemoving hook) removes the peer the instant
    // the player actually leaves, so protection lasts the WHOLE session - it no
    // longer depends on a 2s liveness window kept warm by announce-spam (that was
    // the regression when the burst was shortened). This long timeout is ONLY a
    // safety net so a missed leave (e.g. a crash) can't lock a name out forever.
    static const DWORD                     kHolderProtectMs = 600000;   // 10 min
    // Stable per-connection key from ip:port. Handles BOTH IPv4 and IPv6 -
    // RakNet on loopback uses ::1, which the old IPv4-only version saw as
    // "unknown" (0), breaking dedup AND making the local host look external.
    // 0 means "couldn't determine".
    static uint64_t SourceKey(const sockaddr* from, int fromlen)
    {
        const unsigned char* addr = nullptr; int alen = 0; uint16_t port = 0;
        if (from && from->sa_family == AF_INET && fromlen >= (int)sizeof(sockaddr_in)) {
            const sockaddr_in* s = reinterpret_cast<const sockaddr_in*>(from);
            addr = reinterpret_cast<const unsigned char*>(&s->sin_addr); alen = 4; port = s->sin_port;
        }
        else if (from && from->sa_family == AF_INET6 && fromlen >= (int)sizeof(sockaddr_in6)) {
            const sockaddr_in6* s = reinterpret_cast<const sockaddr_in6*>(from);
            addr = reinterpret_cast<const unsigned char*>(&s->sin6_addr); alen = 16; port = s->sin6_port;
        }
        else return 0;
        uint64_t k = 1469598103934665603ULL;             // FNV-1a over addr+port
        for (int i = 0; i < alen; i++) { k ^= addr[i]; k *= 1099511628211ULL; }
        k ^= (port & 0xFF); k *= 1099511628211ULL;
        k ^= (port >> 8);   k *= 1099511628211ULL;
        return k ? k : 1;
    }
    // ONLY the exact local-machine loopback counts: 127.0.0.1, ::1, or
    // ::ffff:127.0.0.1. NOT the whole 127.0.0.0/8 block - tunnel services like
    // playit.gg forward remote players in on other 127.x.x.x addresses (e.g.
    // 127.155.161.72), and those must be treated as EXTERNAL so the host-name
    // security still kicks in for them.
    static bool IsLoopbackAddr(const sockaddr* from)
    {
        if (!from) return false;
        if (from->sa_family == AF_INET) {
            const sockaddr_in* s = reinterpret_cast<const sockaddr_in*>(from);
            return ntohl(s->sin_addr.s_addr) == 0x7F000001;             // exactly 127.0.0.1
        }
        if (from->sa_family == AF_INET6) {
            const sockaddr_in6* s = reinterpret_cast<const sockaddr_in6*>(from);
            const unsigned char* a = reinterpret_cast<const unsigned char*>(&s->sin6_addr);
            bool v6loop = true; for (int i = 0; i < 15; i++) if (a[i]) { v6loop = false; break; }
            if (v6loop && a[15] == 1) return true;                       // ::1
            static const unsigned char m[12] = { 0,0,0,0,0,0,0,0,0,0,0xff,0xff };
            if (std::memcmp(a, m, 12) == 0 &&                            // ::ffff:127.0.0.1
                a[12] == 127 && a[13] == 0 && a[14] == 0 && a[15] == 1) return true;
            return false;
        }
        return false;
    }
    // Liveness: refresh a known peer's lastSeen on every received datagram so
    // the duplicate check can tell who is still connected. Called from ALL recv
    // hooks (including the connected WSARecv path RakNet actually uses).
    static void TouchPeer(const sockaddr* from, int fromlen)
    {
        uint64_t key = SourceKey(from, fromlen);
        if (key == 0) return;
        std::lock_guard<std::mutex> lk(s_peerMutex);
        std::map<uint64_t, PeerInfo>::iterator it = s_peers.find(key);
        if (it != s_peers.end()) it->second.lastSeen = GetTickCount();
    }
    // Decide what to do with a joining identity:
    //   kApplyIdentity    - first time seen (or takeover of a dead name): apply.
    //   kRepeatIdentity   - the SAME source connection (same source key)
    //                       re-announcing. The client fires the magic ~30x from
    //                       one stable socket, so every repeat shares this key:
    //                       refresh liveness and skip re-patching / re-POSTing.
    //   kForceDefaultName - a DIFFERENT connection (different source key)
    //                       claiming a name still held by a live connection, or
    //                       the host name from an external ip -> "Player%d".
    enum JoinDecision { kApplyIdentity, kRepeatIdentity, kForceDefaultName };
    static JoinDecision ClassifyJoin(const std::string& name,
        const sockaddr* from, int fromlen)
    {
        uint64_t key = SourceKey(from, fromlen);
        bool loopback = IsLoopbackAddr(from);
        std::string hostUser = GetUsernameAscii();
        std::lock_guard<std::mutex> lk(s_peerMutex);
        DWORD now = GetTickCount();
        // A key that JUST left is still re-announcing (its announcer hasn't
        // stopped yet) -> swallow so a leave isn't followed by a false rejoin.
        // Refresh the timer while the stragglers keep coming; clear once they stop.
        if (key != 0)
        {
            std::map<uint64_t, DWORD>::iterator cd = s_leftCooldown.find(key);
            if (cd != s_leftCooldown.end())
            {
                if (now - cd->second < kLeaveCooldownMs) { cd->second = now; return kRepeatIdentity; }
                s_leftCooldown.erase(cd);
            }
        }
        // A connection we already rejected (forced to default) keeps sending its
        // burst -> swallow the repeats so the rejection is logged/applied once.
        if (key != 0)
        {
            std::map<uint64_t, DWORD>::iterator fr = s_forcedRecent.find(key);
            if (fr != s_forcedRecent.end())
            {
                if (now - fr->second < kForcedDedupMs) { fr->second = now; return kRepeatIdentity; }
                s_forcedRecent.erase(fr);
            }
        }
        // Host username taken from a non-loopback ip -> not the real host.
        if (!hostUser.empty() && name == hostUser && !loopback) {
            LogF(L"[udp_relay] '%hs' uses host name from external ip -> Player%%d\n",
                name.c_str());
            if (key != 0) s_forcedRecent[key] = now;
            return kForceDefaultName;
        }
        std::map<std::string, uint64_t>::iterator u = s_userToKey.find(name);
        if (u != s_userToKey.end()) {
            // Same source connection re-announcing (the ~30x burst from one
            // socket => one key). Already applied: refresh liveness and skip.
            if (key != 0 && u->second == key) {
                std::map<uint64_t, PeerInfo>::iterator self = s_peers.find(key);
                if (self != s_peers.end()) self->second.lastSeen = now;
                return kRepeatIdentity;
            }
            // A DIFFERENT connection claiming a name whose holder is still
            // PRESENT -> impersonation -> force default. The holder is removed on
            // real leave (leave detection), so "present" means actively in use,
            // for the whole session - not just a 2s liveness window. The long
            // timeout is only a crash safety net. (key==0 means we couldn't
            // attribute this datagram to a connection; don't flip on it, to avoid
            // a false positive against the legitimate holder.)
            std::map<uint64_t, PeerInfo>::iterator orig = s_peers.find(u->second);
            bool inUse = (orig != s_peers.end()) &&
                (now - orig->second.lastSeen < kHolderProtectMs);
            if (inUse && key != 0) {
                LogF(L"[udp_relay] '%hs' already in use by another connection -> Player%%d\n",
                    name.c_str());
                s_forcedRecent[key] = now;
                return kForceDefaultName;
            }
            // Holder actually left (peer gone) or ancient/unknown -> allow takeover.
        }
        // First sighting (or takeover of a dead name): claim it for this key.
        if (key != 0) {
            PeerInfo pi; pi.username = name; pi.lastSeen = now;
            s_peers[key] = pi;
            s_userToKey[name] = key;
        }
        return kApplyIdentity;
    }

    // ---------- Leave detection -------------------------------------------
    // When a player leaves we drop their peer so the SAME human reclaims their
    // name on reconnect (instead of being bumped to Player%d because the stale
    // entry still "holds" the name). Two independent signals from the server's
    // output stream feed this (see OnServerOutputLine):
    //   * "Disconnect from <ip>|<port>"  - frees by source key (works when the
    //                                      magic rode that connection's port)
    //   * "Player (<name>) is being removed" - frees by username (robust even
    //                                      when the disconnect port differs from
    //                                      the magic-announce port)
    static void ErasePeerKeyLocked(uint64_t key)   // caller holds s_peerMutex
    {
        std::map<uint64_t, PeerInfo>::iterator it = s_peers.find(key);
        if (it == s_peers.end()) return;
        std::string uname = it->second.username;
        std::map<std::string, uint64_t>::iterator u = s_userToKey.find(uname);
        if (u != s_userToKey.end() && u->second == key) s_userToKey.erase(u);
        s_peers.erase(it);
        s_leftCooldown[key] = GetTickCount();   // suppress this key's straggler announces
        LogF(L"[udp_relay] peer left -> freed name '%hs'\n", uname.c_str());
        ServerConsolePlayerLeft(uname);
    }

    static void RemovePeerByIpPort(const char* ip, int port)
    {
        sockaddr_in sa; std::memset(&sa, 0, sizeof(sa));
        sa.sin_family = AF_INET;
        sa.sin_port = htons((unsigned short)port);
        if (InetPtonA(AF_INET, ip, &sa.sin_addr) != 1) return;
        uint64_t key = SourceKey(reinterpret_cast<sockaddr*>(&sa), sizeof(sa));
        std::lock_guard<std::mutex> lk(s_peerMutex);
        if (s_peers.find(key) != s_peers.end()) ErasePeerKeyLocked(key);
        else LogF(L"[udp_relay] disconnect %hs:%d -> no tracked peer "
                  L"(port differs from magic key; username path will handle it)\n", ip, port);
    }

    static void RemovePeerByUsername(const std::string& name)
    {
        if (name.empty()) return;
        std::lock_guard<std::mutex> lk(s_peerMutex);
        std::map<std::string, uint64_t>::iterator u = s_userToKey.find(name);
        if (u == s_userToKey.end()) return;
        uint64_t key = u->second;
        std::map<uint64_t, PeerInfo>::iterator it = s_peers.find(key);
        if (it != s_peers.end()) s_peers.erase(it);
        s_userToKey.erase(u);
        s_leftCooldown[key] = GetTickCount();   // suppress this key's straggler announces
        LogF(L"[udp_relay] player removed -> freed name '%hs'\n", name.c_str());
        ServerConsolePlayerLeft(name);
    }

    // Parse leave signals out of a server output line. Cheap substring checks;
    // the caller only invokes this for lines that already contain one of the
    // trigger substrings. Returns true if the line was an INTERNAL signal that
    // should be suppressed from the visible output (the PlayerRemoving tag),
    // false for real engine lines that should still be shown.
    bool OnServerOutputLine(const char* msg)
    {
        if (!msg) return false;

        // Internal leave signal from the injected PlayerRemoving handler:
        //   "OffBloxPlayerLeft:<name>"
        // This is the reliable path - PlayerRemoving fires on EVERY leave and
        // carries the exact name, with no Player-layout reversing.
        const char* tag = std::strstr(msg, "OffBloxPlayerLeft:");
        if (tag)
        {
            std::string name(tag + 18);   // strlen("OffBloxPlayerLeft:") == 18
            while (!name.empty() &&
                   (name.back() == '\r' || name.back() == '\n' ||
                    name.back() == ' '  || name.back() == '\t'))
                name.pop_back();
            RemovePeerByUsername(name);
            return true;                  // suppress this internal line
        }

        const char* d = std::strstr(msg, "Disconnect from ");
        if (d)
        {
            d += 16;   // past "Disconnect from "
            char ip[64] = {}; int i = 0;
            while (d[i] && d[i] != '|' && d[i] != ' ' && i < 63) { ip[i] = d[i]; ++i; }
            ip[i] = '\0';
            int port = (d[i] == '|') ? atoi(d + i + 1) : 0;
            if (ip[0] && port > 0 && std::strcmp(ip, "UNASSIGNED_SYSTEM_ADDRESS") != 0)
                RemovePeerByIpPort(ip, port);
            return false;
        }
        const char* rem = std::strstr(msg, "is being removed");
        if (rem)
        {
            const char* open = nullptr;            // last '(' before "is being removed"
            for (const char* p = msg; p < rem; ++p) if (*p == '(') open = p;
            if (open)
            {
                const char* close = std::strchr(open, ')');
                if (close && close > open + 1)
                    RemovePeerByUsername(std::string(open + 1, close - open - 1));
            }
            return false;
        }
        return false;
    }

    // Public entry for the C++ player-removal hook (player_leave.cpp).
    void RelayFreePlayerName(const char* name)
    {
        if (name && *name) RemovePeerByUsername(std::string(name));
    }
    // ---------- Magic packet construction ---------------------------------
    static int BuildMagicPacket(char* out, size_t outCap)
    {
        std::string name = GetUsernameAscii();
        if (name.empty()) return 0;
        std::string app = GetAppearanceAscii();
        size_t appPos = kHeaderSize + name.size() + kIdTrailer;  // appLen(2) + data sits here
        size_t total = appPos + 2 + app.size();
        if (total > outCap) { app.clear(); total = appPos + 2; } // drop appearance if oversized
        uint32_t mNbo = htonl(kMagic);
        std::memcpy(out, &mNbo, 4);
        out[4] = static_cast<char>(kVersion);
        out[5] = static_cast<char>(name.size());
        std::memcpy(out + kHeaderSize, name.data(), name.size());
        // Trailer: userId (8 bytes big-endian) + accountAge (4 bytes BE).
        uint64_t uid = GetUserIdToSend();
        uint32_t age = GetAccountAgeToSend();
        unsigned char* t =
            reinterpret_cast<unsigned char*>(out + kHeaderSize + name.size());
        for (int i = 0; i < 8; ++i) t[i] = (unsigned char)((uid >> (56 - 8 * i)) & 0xFF);
        for (int i = 0; i < 4; ++i) t[8 + i] = (unsigned char)((age >> (24 - 8 * i)) & 0xFF);
        // v3 appearance: appLen (2 BE) + raw Appearence.ini bytes.
        unsigned char* a = reinterpret_cast<unsigned char*>(out + appPos);
        a[0] = (unsigned char)((app.size() >> 8) & 0xFF);
        a[1] = (unsigned char)(app.size() & 0xFF);
        std::memcpy(out + appPos + 2, app.data(), app.size());
        return static_cast<int>(total);
    }
    // Inspect a received datagram. If it's ours, patch the name and return
    // true. from/fromlen are optional - RakNet calls recvfrom on connected
    // sockets with a null from pointer, so we must not require them.
    static bool TryConsumeMagic(const char* buf, int len,
        const sockaddr* from, int fromlen)
    {
        if (len < (int)kHeaderSize) return false;
        uint32_t got;
        std::memcpy(&got, buf, 4);
        if (ntohl(got) != kMagic) return false;
        uint8_t ver = static_cast<uint8_t>(buf[4]);
        if (ver < 1 || ver > 3) return false;   // v1 name / v2 +ids / v3 +appearance
        size_t nL = static_cast<uint8_t>(buf[5]);
        if (len < (int)(kHeaderSize + nL)) return false;
        std::string name(buf + kHeaderSize, nL);
        // v2 trailer: userId (8 BE) + accountAge (4 BE). Present only when the
        // datagram is long enough; v1 senders omit it.
        bool     haveId = false;
        uint64_t uid = 0;
        uint32_t age = 0;
        if (ver >= 2 && len >= (int)(kHeaderSize + nL + kIdTrailer))
        {
            const unsigned char* t =
                reinterpret_cast<const unsigned char*>(buf + kHeaderSize + nL);
            for (int i = 0; i < 8; ++i) uid = (uid << 8) | t[i];
            for (int i = 0; i < 4; ++i) age = (age << 8) | t[8 + i];
            haveId = true;
        }
        // v3 appearance: appLen (2 BE) + raw Appearence.ini bytes.
        std::string appearance;
        if (ver >= 3)
        {
            size_t appPos = kHeaderSize + nL + kIdTrailer;
            if (len >= (int)(appPos + 2))
            {
                const unsigned char* a =
                    reinterpret_cast<const unsigned char*>(buf + appPos);
                size_t appLen = (size_t(a[0]) << 8) | a[1];
                if (appLen > 0 && len >= (int)(appPos + 2 + appLen))
                    appearance.assign(buf + appPos + 2, appLen);
            }
        }
        char srcIp[INET6_ADDRSTRLEN] = "<unknown>";
        int  srcPort = 0;
        if (from && from->sa_family == AF_INET && fromlen >= (int)sizeof(sockaddr_in))
        {
            const sockaddr_in* src = reinterpret_cast<const sockaddr_in*>(from);
            inet_ntop(AF_INET, &src->sin_addr, srcIp, sizeof(srcIp));
            srcPort = ntohs(src->sin_port);
        }
        else if (from && from->sa_family == AF_INET6 && fromlen >= (int)sizeof(sockaddr_in6))
        {
            const sockaddr_in6* src = reinterpret_cast<const sockaddr_in6*>(from);
            inet_ntop(AF_INET6, &src->sin6_addr, srcIp, sizeof(srcIp));
            srcPort = ntohs(src->sin6_port);
        }
        // One decision per source connection. ClassifyJoin keys on the source
        // key, so the client's ~30x re-announce from its one stable socket is
        // recognised as a single peer (kRepeatIdentity -> swallowed, no re-patch
        // / re-POST), while a genuinely separate connection claiming a live name
        // is forced to the default name.
        JoinDecision decision = ClassifyJoin(name, from, fromlen);
        if (decision == kRepeatIdentity)
            return true;                          // identity already applied; swallow silently
        LogF(L"[udp_relay] RECV magic from %hs:%d username='%hs' userId=%llu "
            L"accountAge=%u haveId=%d, patching now\n",
            srcIp, srcPort, name.c_str(),
            (unsigned long long)uid, (unsigned)age, (int)haveId);
        // A conflicting username (the host's name from an external ip, or a name
        // held by a live DIFFERENT account) still gets in, but as the default
        // "Player%d" - and we skip applying their relayed identity/appearance,
        // so they can't impersonate anyone. ClassifyJoin deduped the burst, so
        // this runs ONCE per connection; the console reflects the FORCED name.
        if (decision == kForceDefaultName) {
            PatchPlayerNameCallSite("Guest_%d");
            // Clear any stale relayed identity so this rejected joiner can't
            // inherit the previous (accepted) player's userId -- which would also
            // hand them that player's avatar via avatar-fetch. With the identity
            // cleared the engine uses its own default id, for which the local
            // webserver serves the gray guest avatar.
            ApplyReceivedIdentity(0, 0);
            ServerConsolePlayerJoined("Guest_%d (rejected '" + name + "' - name in use)");
            return true;
        }
        PatchPlayerNameCallSite(name);
        ServerConsolePlayerJoined(name);
        if (haveId)
            ApplyReceivedIdentity(uid, age);
        if (!appearance.empty())
            PostAppearanceToLocal(name, appearance);   // host -> local webserver
        return true;
    }
    // ---------- Hook implementations --------------------------------------
    // Forward decls - the join-gate helpers are defined further down (next to
    // the announcer) but are used here in the send hooks.
    static bool DestIsServerEndpoint(const sockaddr* to, int tolen);
    static void HintJoin(const char* why);

    static int WINAPI Hook_sendto(SOCKET s, const char* buf, int len,
        int flags, const sockaddr* to, int tolen)
    {
        if (DestIsServerEndpoint(to, tolen)) HintJoin("sendto");
        if (ShouldAnnounceToDest(to, tolen))
        {
            char pkt[kMaxPacket];
            int  pktLen = BuildMagicPacket(pkt, sizeof(pkt));
            if (pktLen > 0 && s_orig_sendto)
            {
                const sockaddr_in* dst = reinterpret_cast<const sockaddr_in*>(to);
                char ipStr[INET_ADDRSTRLEN] = {};
                inet_ntop(AF_INET, &dst->sin_addr, ipStr, sizeof(ipStr));
                uint8_t nL = static_cast<uint8_t>(pkt[5]);
                std::string name(pkt + kHeaderSize, nL);
                LogF(L"[udp_relay] SEND magic to %hs:%d username='%hs'\n",
                    ipStr, ntohs(dst->sin_port), name.c_str());
                s_orig_sendto(s, pkt, pktLen, 0, to, tolen);
            }
        }
        return s_orig_sendto ? s_orig_sendto(s, buf, len, flags, to, tolen)
            : SOCKET_ERROR;
    }
    static int WINAPI Hook_recvfrom(SOCKET s, char* buf, int len, int flags,
        sockaddr* from, int* fromlen)
    {
        if (!s_orig_recvfrom) return SOCKET_ERROR;
        int n = s_orig_recvfrom(s, buf, len, flags, from, fromlen);
        if (n == SOCKET_ERROR || n <= 0) return n;
        int fl = fromlen ? *fromlen : 0;
        TouchPeer(from, fl);                      // liveness tracking
        if (TryConsumeMagic(buf, n, from, fl))
        {
            WSASetLastError(WSAEWOULDBLOCK);
            return SOCKET_ERROR;
        }
        return n;
    }
    static int WINAPI Hook_WSASendTo(SOCKET s, LPWSABUF buffers,
        DWORD bufCount, LPDWORD bytesSent,
        DWORD flags, const sockaddr* to,
        int tolen, LPWSAOVERLAPPED ovl,
        LPWSAOVERLAPPED_COMPLETION_ROUTINE comp)
    {
        if (DestIsServerEndpoint(to, tolen)) HintJoin("WSASendTo");
        if (ShouldAnnounceToDest(to, tolen) && s_orig_WSASendTo)
        {
            char pkt[kMaxPacket];
            int  pktLen = BuildMagicPacket(pkt, sizeof(pkt));
            if (pktLen > 0)
            {
                const sockaddr_in* dst = reinterpret_cast<const sockaddr_in*>(to);
                char ipStr[INET_ADDRSTRLEN] = {};
                inet_ntop(AF_INET, &dst->sin_addr, ipStr, sizeof(ipStr));
                uint8_t nL = static_cast<uint8_t>(pkt[5]);
                std::string name(pkt + kHeaderSize, nL);
                LogF(L"[udp_relay] SEND magic (WSA) to %hs:%d username='%hs'\n",
                    ipStr, ntohs(dst->sin_port), name.c_str());
                WSABUF wb;
                wb.buf = pkt;
                wb.len = static_cast<ULONG>(pktLen);
                DWORD injSent = 0;
                s_orig_WSASendTo(s, &wb, 1, &injSent, 0, to, tolen,
                    nullptr, nullptr);
            }
        }
        return s_orig_WSASendTo
            ? s_orig_WSASendTo(s, buffers, bufCount, bytesSent, flags,
                to, tolen, ovl, comp)
            : SOCKET_ERROR;
    }
    static int WINAPI Hook_WSARecvFrom(SOCKET s, LPWSABUF buffers,
        DWORD bufCount, LPDWORD bytesRecvd,
        LPDWORD flags, sockaddr* from,
        LPINT fromlen, LPWSAOVERLAPPED ovl,
        LPWSAOVERLAPPED_COMPLETION_ROUTINE comp)
    {
        if (!s_orig_WSARecvFrom) return SOCKET_ERROR;
        if (!ovl && !comp)
        {
            int r = s_orig_WSARecvFrom(s, buffers, bufCount, bytesRecvd,
                flags, from, fromlen, nullptr, nullptr);
            if (r != 0) return r;
            if (!bytesRecvd || *bytesRecvd == 0) return r;
            int fl = fromlen ? *fromlen : 0;
            TouchPeer(from, fl);                   // liveness tracking
            if (bufCount == 1 && buffers && buffers[0].buf)
            {
                if (TryConsumeMagic(buffers[0].buf, (int)*bytesRecvd, from, fl))
                {
                    WSASetLastError(WSAEWOULDBLOCK);
                    return SOCKET_ERROR;
                }
            }
            return r;
        }
        return s_orig_WSARecvFrom(s, buffers, bufCount, bytesRecvd, flags,
            from, fromlen, ovl, comp);
    }
    // WSARecv - connected-socket variant used by RakNet on 2023 Studio.
    // No from/fromlen; recover peer via getpeername for logging only.
    static int WINAPI Hook_WSARecv(SOCKET s, LPWSABUF buffers,
        DWORD bufCount, LPDWORD bytesRecvd,
        LPDWORD flags, LPWSAOVERLAPPED ovl,
        LPWSAOVERLAPPED_COMPLETION_ROUTINE comp)
    {
        if (!s_orig_WSARecv) return SOCKET_ERROR;
        if (!ovl && !comp)
        {
            int r = s_orig_WSARecv(s, buffers, bufCount, bytesRecvd,
                flags, nullptr, nullptr);
            if (r != 0) return r;
            if (!bytesRecvd || *bytesRecvd == 0) return r;
            if (bufCount == 1 && buffers && buffers[0].buf)
            {
                // MUST be sockaddr_storage (not sockaddr_in): RakNet's connected
                // socket on loopback is IPv6 (::1), which needs 28 bytes. A
                // 16-byte sockaddr_in makes getpeername fail (WSAEFAULT) -> the
                // peer comes back unknown, which breaks both the ip logging AND
                // the host-username-from-external-ip security check.
                sockaddr_storage peer{};
                int peerLen = sizeof(peer);
                sockaddr* peerPtr = nullptr;
                int         peerLenOut = 0;
                if (getpeername(s, reinterpret_cast<sockaddr*>(&peer), &peerLen) == 0)
                {
                    peerPtr = reinterpret_cast<sockaddr*>(&peer);
                    peerLenOut = peerLen;
                }
                TouchPeer(peerPtr, peerLenOut);   // liveness tracking
                if (TryConsumeMagic(buffers[0].buf, (int)*bytesRecvd,
                    peerPtr, peerLenOut))
                {
                    WSASetLastError(WSAEWOULDBLOCK);
                    return SOCKET_ERROR;
                }
            }
            return r;
        }
        return s_orig_WSARecv(s, buffers, bufCount, bytesRecvd, flags, ovl, comp);
    }
    // ---------- Host QUIC (WSARecvMsg) identity capture --------------------
    //
    // msquic (the RbxTransport "sys" backend) receives datagrams on the host's
    // open port via WSARecvMsg with overlapped/IOCP completion - NOT through
    // recvfrom/WSARecvFrom/WSARecv, so the hooks above never see the client's
    // identity datagram. We grab the WSARecvMsg pointer msquic resolves through
    // WSAIoctl(SIO_GET_EXTENSION_FUNCTION_POINTER), wrap it, and scan completed
    // receives for our magic packet.
    //
    // Observe-only: we read the name and let the datagram fall through to
    // msquic, which drops it as an unknown/undecryptable QUIC packet (non-fatal)
    // - so we never mutate msquic's I/O state or risk tearing the connection.
    typedef INT(WSAAPI* PFN_WSARecvMsg)(SOCKET, LPWSAMSG, LPDWORD,
        LPWSAOVERLAPPED,
        LPWSAOVERLAPPED_COMPLETION_ROUTINE);
    typedef int (WSAAPI* PFN_WSAIoctl)(SOCKET, DWORD, LPVOID, DWORD, LPVOID,
        DWORD, LPDWORD, LPWSAOVERLAPPED,
        LPWSAOVERLAPPED_COMPLETION_ROUTINE);
    typedef BOOL(WINAPI* PFN_GQCSEx)(HANDLE, LPOVERLAPPED_ENTRY, ULONG,
        PULONG, DWORD, BOOL);
    static PFN_WSARecvMsg s_orig_WSARecvMsg = nullptr;
    static PFN_WSAIoctl   s_orig_WSAIoctl = nullptr;
    static PFN_GQCSEx     s_orig_GQCSEx = nullptr;
    static bool           s_quicMsgLogged = false;   // one-shot diagnostic
    // Pending overlapped WSARecvMsg receives: overlapped -> the WSAMSG it will
    // fill, so the IOCP-completion hook can find the buffer + source address
    // once bytes arrive. Updated on every WSARecvMsg call (msquic reuses both).
    static std::mutex                         s_msgMutex;
    static std::map<LPOVERLAPPED, LPWSAMSG>   s_pendingMsg;
    static void ScanMsgForMagic(LPWSAMSG msg, DWORD bytes)
    {
        if (!msg || bytes == 0 || msg->dwBufferCount == 0 || !msg->lpBuffers) return;
        const char* buf = msg->lpBuffers[0].buf;
        if (!buf) return;
        int len = (int)bytes;
        if ((ULONG)len > msg->lpBuffers[0].len) len = (int)msg->lpBuffers[0].len;
        TouchPeer(msg->name, msg->namelen);
        TryConsumeMagic(buf, len, msg->name, msg->namelen);   // observe + patch name
    }
    static INT WSAAPI Hook_WSARecvMsg(SOCKET s, LPWSAMSG msg, LPDWORD bytesRecvd,
        LPWSAOVERLAPPED ovl,
        LPWSAOVERLAPPED_COMPLETION_ROUTINE comp)
    {
        if (!s_orig_WSARecvMsg) return SOCKET_ERROR;
        if (!s_quicMsgLogged)
        {
            s_quicMsgLogged = true;
            LogF(L"[udp_relay] WSARecvMsg first call: overlapped=%p comp=%p (mode=%ls)\n",
                ovl, comp, (ovl || comp) ? L"async" : L"sync");
        }
        if (!ovl && !comp)
        {
            INT r = s_orig_WSARecvMsg(s, msg, bytesRecvd, nullptr, nullptr);
            if (r == 0 && bytesRecvd && *bytesRecvd > 0)
                ScanMsgForMagic(msg, *bytesRecvd);
            return r;
        }
        if (ovl && msg)
        {
            std::lock_guard<std::mutex> lk(s_msgMutex);
            s_pendingMsg[ovl] = msg;
        }
        return s_orig_WSARecvMsg(s, msg, bytesRecvd, ovl, comp);
    }
    static BOOL WINAPI Hook_GQCSEx(HANDLE port, LPOVERLAPPED_ENTRY entries,
        ULONG count, PULONG removed, DWORD ms, BOOL alertable)
    {
        BOOL ok = s_orig_GQCSEx
            ? s_orig_GQCSEx(port, entries, count, removed, ms, alertable)
            : FALSE;
        if (ok && removed && *removed && entries)
        {
            for (ULONG i = 0; i < *removed; ++i)
            {
                LPOVERLAPPED o = entries[i].lpOverlapped;
                if (!o) continue;
                LPWSAMSG msg = nullptr;
                {
                    std::lock_guard<std::mutex> lk(s_msgMutex);
                    std::map<LPOVERLAPPED, LPWSAMSG>::iterator it = s_pendingMsg.find(o);
                    if (it != s_pendingMsg.end()) msg = it->second;
                }
                if (msg) ScanMsgForMagic(msg, entries[i].dwNumberOfBytesTransferred);
            }
        }
        return ok;
    }
    static int WSAAPI Hook_WSAIoctl(SOCKET s, DWORD code, LPVOID inBuf, DWORD inLen,
        LPVOID outBuf, DWORD outLen, LPDWORD bytesRet,
        LPWSAOVERLAPPED ovl,
        LPWSAOVERLAPPED_COMPLETION_ROUTINE comp)
    {
        int r = s_orig_WSAIoctl
            ? s_orig_WSAIoctl(s, code, inBuf, inLen, outBuf, outLen, bytesRet, ovl, comp)
            : SOCKET_ERROR;
        if (r == 0 && code == SIO_GET_EXTENSION_FUNCTION_POINTER &&
            inBuf && inLen >= sizeof(GUID) && outBuf && outLen >= sizeof(void*))
        {
            GUID want = WSAID_WSARECVMSG;
            if (std::memcmp(inBuf, &want, sizeof(GUID)) == 0)
            {
                void** slot = reinterpret_cast<void**>(outBuf);
                if (*slot && *slot != reinterpret_cast<void*>(&Hook_WSARecvMsg))
                {
                    s_orig_WSARecvMsg = reinterpret_cast<PFN_WSARecvMsg>(*slot);
                    *slot = reinterpret_cast<void*>(&Hook_WSARecvMsg);
                    LogF(L"[udp_relay] captured WSARecvMsg (real=%p) -> hooked\n",
                        s_orig_WSARecvMsg);
                }
            }
        }
        return r;
    }
    // ---------- Join gate -------------------------------------------------
    //
    // The identity announce used to fire at process start, before the client
    // had even logged in or chosen to join. We now hold it until the client is
    // actually CONNECTING to the server (its transport sends/connects to the
    // server endpoint), which is the precise "about to join" moment. A fallback
    // timeout guarantees we still announce even if that signal is missed, so a
    // join can never be blocked.
    static HANDLE      s_joinGate      = nullptr;   // manual-reset; set on first server contact
    static const DWORD kJoinFallbackMs = 12000;     // announce anyway after this

    // True if `to` addresses the game server endpoint - its resolved IP on the
    // connect port or the RakNet port (connectPort+1). Matches the game ports
    // only, so unrelated loopback traffic (e.g. the :443 webserver) won't trip
    // the gate during startup.
    static bool DestIsServerEndpoint(const sockaddr* to, int tolen)
    {
        if (!to || tolen < (int)sizeof(sockaddr_in) || to->sa_family != AF_INET)
            return false;
        std::string ip; int port = 0;
        if (!GetServerEndpoint(ip, port)) return false;
        const sockaddr_in* d = reinterpret_cast<const sockaddr_in*>(to);
        char ipStr[INET_ADDRSTRLEN] = {};
        inet_ntop(AF_INET, &d->sin_addr, ipStr, sizeof(ipStr));
        if (ip != ipStr) return false;
        int dp = ntohs(d->sin_port);
        return dp == port || dp == port + 1;
    }

    static void HintJoin(const char* why)
    {
        if (!s_joinGate) return;
        if (WaitForSingleObject(s_joinGate, 0) != WAIT_OBJECT_0)   // first time only
            LogF(L"[udp_relay] join detected (%hs) -> announcing identity now\n", why);
        SetEvent(s_joinGate);
    }

    // connect() hook: msquic / RakNet connect their UDP socket to the server
    // endpoint right as the join begins. That is our most precise trigger.
    static int (WINAPI* s_orig_connect)(SOCKET, const sockaddr*, int) = nullptr;
    static int WINAPI Hook_connect(SOCKET s, const sockaddr* name, int namelen)
    {
        if (DestIsServerEndpoint(name, namelen)) HintJoin("connect");
        return s_orig_connect ? s_orig_connect(s, name, namelen)
                              : connect(s, name, namelen);
    }

    // ---------- Client identity announcer ---------------------------------
    //
    // Under RbxTransport the client's RakNet is a vestigial loopback socket
    // (127.0.0.1:<ephemeral>) that never leaves the machine, so mirroring the
    // engine's sendto announced the magic packet to a dead end. QUIC traffic to
    // the real host doesn't go through sendto either, so we never aimed at it.
    //
    // Instead we send the magic datagram ourselves, from our own UDP socket,
    // straight at the resolved host IP:-port - the exact tunnelled port the
    // client's QUIC/RbxTransport connection uses. It rides the one open port to
    // the host, where the WSARecvMsg intercept consumes it before msquic. We
    // fire it early and repeatedly so the identity is present before the join
    // is processed. Sent via s_orig_sendto so it bypasses our own send hook.
    static DWORD WINAPI MagicAnnouncerThread(LPVOID)
    {
        WSADATA wsa; WSAStartup(MAKEWORD(2, 2), &wsa);
        char pkt[kMaxPacket];
        int  pktLen = BuildMagicPacket(pkt, sizeof(pkt));
        if (pktLen <= 0)
        {
            LogF(L"[udp_relay] announcer: no username/magic to send - exiting\n");
            return 0;
        }
        // Hold the announce until the client actually starts connecting to the
        // server (HintJoin sets s_joinGate). The fallback ensures we never block
        // a join if that signal is missed.
        if (s_joinGate)
        {
            DWORD wr = WaitForSingleObject(s_joinGate, kJoinFallbackMs);
            LogF(L"[udp_relay] announcer: %ls, sending identity\n",
                 wr == WAIT_OBJECT_0 ? L"join gate opened" : L"fallback timeout");
        }
        // ONE socket for every retry. A fresh socket per send would give each
        // announcement a different source port, so the host's anti-impersonation
        // check would see "same name from a new connection" and flip the player
        // to Player%d on every packet. A single stable source port keeps every
        // retry on the same connection key, so the host treats them as one peer.
        SOCKET s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (s == INVALID_SOCKET)
        {
            LogF(L"[udp_relay] announcer: socket() failed - exiting\n");
            return 0;
        }
        // ~15s of coverage so the name beats the join, then stops. The host
        // dedupes the repeats, so this is just to win the race, not to keep
        // re-sending forever.
        // Brief burst on join, NOT a 15s spam. The first received magic does
        // everything (registers the peer, applies identity, POSTs appearance)
        // and the name patch is persistent, so one delivered datagram is enough.
        // We send a few in quick succession only as insurance against a dropped
        // datagram / the create-player race, then STOP - so there are no
        // stragglers to cause a false rejoin after a leave.
        const int   kTries    = 3;
        const DWORD kTryGapMs = 100;
        for (int i = 0; i < kTries; ++i)
        {
            std::string ip; int port = 0;
            if (GetServerEndpoint(ip, port))
            {
                sockaddr_in dst; std::memset(&dst, 0, sizeof(dst));
                dst.sin_family = AF_INET;
                dst.sin_port = htons((unsigned short)port);
                InetPtonA(AF_INET, ip.c_str(), &dst.sin_addr);
                int r = s_orig_sendto
                    ? s_orig_sendto(s, pkt, pktLen, 0,
                        reinterpret_cast<sockaddr*>(&dst), sizeof(dst))
                    : sendto(s, pkt, pktLen, 0,
                        reinterpret_cast<sockaddr*>(&dst), sizeof(dst));
                LogF(L"[udp_relay] announce magic -> %hs:%d len=%d r=%d (try %d/%d)\n",
                     ip.c_str(), port, pktLen, r, i + 1, kTries);
            }
            else
            {
                LogF(L"[udp_relay] announcer: server endpoint not known - skipping\n");
                break;
            }
            if (i + 1 < kTries) Sleep(kTryGapMs);
        }
        closesocket(s);
        LogF(L"[udp_relay] magic announcer finished (sent %d)\n", kTries);
        return 0;
    }
    // ---------- Public entry ----------------------------------------------
    extern bool IsStartClientTask_Pub();
    extern bool IsStartServerTask_Pub();
    bool StartUdpRelay()
    {
        const bool isClient = IsStartClientTask_Pub();
        const bool isServer = IsStartServerTask_Pub();
        LogF(L"[udp_relay] installing IAT hooks (client=%d server=%d)\n",
            (int)isClient, (int)isServer);
        std::string u = GetUsernameAscii();
        if (u.empty())
            LogF(L"[udp_relay] no username.txt - send-side announce disabled\n");
        else
            LogF(L"[udp_relay] username='%hs' (%zu chars)\n", u.c_str(), u.size());
        bool any = false;
        if (isClient)
        {
            if (!IatHook("ws2_32.dll", "sendto",
                reinterpret_cast<void*>(&Hook_sendto),
                reinterpret_cast<void**>(&s_orig_sendto)))
            {
                if (InlineHook("ws2_32.dll", "sendto",
                    reinterpret_cast<void*>(&Hook_sendto),
                    reinterpret_cast<void**>(&s_orig_sendto)))
                {
                    any = true;
                    LogF(L"[udp_relay] sendto: IAT miss, inline hook installed\n");
                }
                else { LogF(L"[udp_relay] sendto: both IAT and inline hook FAILED\n"); }
            }
            else { any = true; }
            if (!IatHook("ws2_32.dll", "WSASendTo",
                reinterpret_cast<void*>(&Hook_WSASendTo),
                reinterpret_cast<void**>(&s_orig_WSASendTo)))
            {
                if (InlineHook("ws2_32.dll", "WSASendTo",
                    reinterpret_cast<void*>(&Hook_WSASendTo),
                    reinterpret_cast<void**>(&s_orig_WSASendTo)))
                {
                    any = true;
                    LogF(L"[udp_relay] WSASendTo: IAT miss, inline hook installed\n");
                }
                else { LogF(L"[udp_relay] WSASendTo: both IAT and inline hook FAILED\n"); }
            }
            else { any = true; }
        }
        else
        {
            HMODULE hWs2 = GetModuleHandleW(L"ws2_32.dll");
            s_orig_sendto = reinterpret_cast<PFN_sendto>(
                GetProcAddress(hWs2, "sendto"));
            s_orig_WSASendTo = reinterpret_cast<PFN_WSASendTo>(
                GetProcAddress(hWs2, "WSASendTo"));
        }
        if (!isClient)
        {
            if (!IatHook("ws2_32.dll", "recvfrom",
                reinterpret_cast<void*>(&Hook_recvfrom),
                reinterpret_cast<void**>(&s_orig_recvfrom)))
            {
                if (InlineHook("ws2_32.dll", "recvfrom",
                    reinterpret_cast<void*>(&Hook_recvfrom),
                    reinterpret_cast<void**>(&s_orig_recvfrom)))
                {
                    any = true;
                    LogF(L"[udp_relay] recvfrom: IAT miss, inline hook installed\n");
                }
                else { LogF(L"[udp_relay] recvfrom: both IAT and inline hook FAILED\n"); }
            }
            else { any = true; }
            if (!IatHook("ws2_32.dll", "WSARecvFrom",
                reinterpret_cast<void*>(&Hook_WSARecvFrom),
                reinterpret_cast<void**>(&s_orig_WSARecvFrom)))
            {
                if (InlineHook("ws2_32.dll", "WSARecvFrom",
                    reinterpret_cast<void*>(&Hook_WSARecvFrom),
                    reinterpret_cast<void**>(&s_orig_WSARecvFrom)))
                {
                    any = true;
                    LogF(L"[udp_relay] WSARecvFrom: IAT miss, inline hook installed\n");
                }
                else { LogF(L"[udp_relay] WSARecvFrom: both IAT and inline hook FAILED\n"); }
            }
            else { any = true; }
            // WSARecv - RakNet on 2023 Studio uses connected UDP sockets
            // and calls WSARecv instead of WSARecvFrom.
            if (!IatHook("ws2_32.dll", "WSARecv",
                reinterpret_cast<void*>(&Hook_WSARecv),
                reinterpret_cast<void**>(&s_orig_WSARecv)))
            {
                if (InlineHook("ws2_32.dll", "WSARecv",
                    reinterpret_cast<void*>(&Hook_WSARecv),
                    reinterpret_cast<void**>(&s_orig_WSARecv)))
                {
                    any = true;
                    LogF(L"[udp_relay] WSARecv: IAT miss, inline hook installed\n");
                }
                else { LogF(L"[udp_relay] WSARecv: both IAT and inline hook FAILED\n"); }
            }
            else { any = true; }
            // QUIC (msquic) receives the client's identity datagram on the open
            // port via WSARecvMsg + IOCP, which none of the hooks above cover.
            // Capture the WSARecvMsg pointer via WSAIoctl and scan completions.
            if (InlineHook("ws2_32.dll", "WSAIoctl",
                reinterpret_cast<void*>(&Hook_WSAIoctl),
                reinterpret_cast<void**>(&s_orig_WSAIoctl)))
            {
                any = true;
                LogF(L"[udp_relay] WSAIoctl hooked (WSARecvMsg capture armed)\n");
            }
            else LogF(L"[udp_relay] WSAIoctl hook FAILED - QUIC recv not captured\n");
            bool gq = InlineHook("kernel32.dll", "GetQueuedCompletionStatusEx",
                reinterpret_cast<void*>(&Hook_GQCSEx),
                reinterpret_cast<void**>(&s_orig_GQCSEx));
            if (!gq)
                gq = InlineHook("KernelBase.dll", "GetQueuedCompletionStatusEx",
                    reinterpret_cast<void*>(&Hook_GQCSEx),
                    reinterpret_cast<void**>(&s_orig_GQCSEx));
            LogF(L"[udp_relay] GetQueuedCompletionStatusEx hook %ls\n",
                gq ? L"installed" : L"FAILED (overlapped QUIC recv won't be scanned)");
        }
        LogF(L"[udp_relay] hooks: sendto=%p recvfrom=%p "
            L"WSASendTo=%p WSARecvFrom=%p WSARecv=%p\n",
            s_orig_sendto, s_orig_recvfrom,
            s_orig_WSASendTo, s_orig_WSARecvFrom, s_orig_WSARecv);
        // Client: fire the identity datagram directly at the resolved host
        // endpoint over the open (tunnelled) port - the loopback-mirror path
        // can't reach the host under RbxTransport. Runs on its own thread so it
        // can retry while the connection is being established.
        if (isClient)
        {
            // Create the join gate and hook connect() BEFORE the announcer runs,
            // so the announce waits for the actual connect to the server.
            s_joinGate = CreateEventW(nullptr, TRUE /*manual reset*/, FALSE, nullptr);
            if (!IatHook("ws2_32.dll", "connect",
                    reinterpret_cast<void*>(&Hook_connect),
                    reinterpret_cast<void**>(&s_orig_connect)))
            {
                if (InlineHook("ws2_32.dll", "connect",
                        reinterpret_cast<void*>(&Hook_connect),
                        reinterpret_cast<void**>(&s_orig_connect)))
                    LogF(L"[udp_relay] connect: IAT miss, inline hook installed\n");
                else
                    LogF(L"[udp_relay] connect hook FAILED - join gate relies on "
                         L"send-hooks + %lums fallback\n", kJoinFallbackMs);
            }
            HANDLE h = CreateThread(nullptr, 0, &MagicAnnouncerThread, nullptr, 0, nullptr);
            if (h) { CloseHandle(h); LogF(L"[udp_relay] client magic announcer started\n"); }
            else { LogF(L"[udp_relay] FAILED to start magic announcer\n"); }
        }
        if (!any)
        {
            LogF(L"[udp_relay] no ws2_32 imports hooked in main module\n");
            return false;
        }
        return true;
    }
}