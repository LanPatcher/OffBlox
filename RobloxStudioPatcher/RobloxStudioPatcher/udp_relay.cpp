// udp_relay.cpp - implementation of the UDP magic-packet username relay.
//
// See udp_relay.h for the design overview and wire format. This file
// contains the IAT hooks and the IP->username map.

#include "udp_relay.h"
#include "iat_hook.h"
#include "name_patcher.h"

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
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

    static const uint32_t kMagic       = 0xC0DE5A45;
    static const uint8_t  kVersion     = 3;          // v3 = name + userId + accountAge + appearance
    static const size_t   kHeaderSize  = 6;          // magic(4) + ver(1) + nameLen(1)
    static const size_t   kMaxName     = 255;        // nameLen is a byte
    static const size_t   kIdTrailer   = 12;         // userId(8 BE) + accountAge(4 BE)
    static const size_t   kMaxApp      = 8192;       // appearance blob (v3): appLen(2 BE) + data
    static const size_t   kMaxPacket   = kHeaderSize + kMaxName + kIdTrailer + 2 + kMaxApp;

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
    static uint64_t GetUserIdToSend()     { return ReadNumberSidecar(L"userid.txt"); }
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

        std::string h  = ReadBodyColor(dir, L"HeadColor.txt");
        std::string t  = ReadBodyColor(dir, L"TorsoColor.txt");
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

        uint64_t key = (uint64_t(dst->sin_addr.s_addr) << 16) | ntohs(dst->sin_port);
        std::lock_guard<std::mutex> lock(s_destMutex);
        bool first = s_destsSeen.insert(key).second;
        LOG(L"[udp_relay] ShouldAnnounce: %hs:%d first=%d\n",
             ipStr, ntohs(dst->sin_port), (int)first);
        return first;
    }

    // ---------- Originals saved by the IAT hook installer -----------------

    using PFN_sendto      = int (WINAPI*)(SOCKET, const char*, int, int,
                                          const sockaddr*, int);
    using PFN_recvfrom    = int (WINAPI*)(SOCKET, char*, int, int,
                                          sockaddr*, int*);
    using PFN_WSASendTo   = int (WINAPI*)(SOCKET, LPWSABUF, DWORD, LPDWORD,
                                          DWORD, const sockaddr*, int,
                                          LPWSAOVERLAPPED,
                                          LPWSAOVERLAPPED_COMPLETION_ROUTINE);
    using PFN_WSARecvFrom = int (WINAPI*)(SOCKET, LPWSABUF, DWORD, LPDWORD,
                                          LPDWORD, sockaddr*, LPINT,
                                          LPWSAOVERLAPPED,
                                          LPWSAOVERLAPPED_COMPLETION_ROUTINE);
    // WSARecv - connected-socket variant (no from/fromlen).
    // RakNet on 2023 Studio uses this instead of WSARecvFrom.
    using PFN_WSARecv     = int (WINAPI*)(SOCKET, LPWSABUF, DWORD, LPDWORD,
                                          LPDWORD,
                                          LPWSAOVERLAPPED,
                                          LPWSAOVERLAPPED_COMPLETION_ROUTINE);

    static PFN_sendto      s_orig_sendto      = nullptr;
    static PFN_recvfrom    s_orig_recvfrom    = nullptr;
    static PFN_WSASendTo   s_orig_WSASendTo   = nullptr;
    static PFN_WSARecvFrom s_orig_WSARecvFrom = nullptr;
    static PFN_WSARecv     s_orig_WSARecv     = nullptr;

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

    static const DWORD kPeerTimeoutMs = 2000;   // unseen this long => "gone"

    struct PeerInfo { std::string username; DWORD lastSeen; };
    static std::mutex                      s_peerMutex;
    static std::map<uint64_t, PeerInfo>    s_peers;      // src key -> {username,lastSeen}
    static std::map<std::string, uint64_t> s_userToKey;  // username -> current src key

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
        } else if (from && from->sa_family == AF_INET6 && fromlen >= (int)sizeof(sockaddr_in6)) {
            const sockaddr_in6* s = reinterpret_cast<const sockaddr_in6*>(from);
            addr = reinterpret_cast<const unsigned char*>(&s->sin6_addr); alen = 16; port = s->sin6_port;
        } else return 0;
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
            static const unsigned char m[12] = {0,0,0,0,0,0,0,0,0,0,0xff,0xff};
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
        std::map<uint64_t,PeerInfo>::iterator it = s_peers.find(key);
        if (it != s_peers.end()) it->second.lastSeen = GetTickCount();
    }

    // Decide a joining username. Returns true => FORCE the default name (the
    // claim conflicts); false => keep the custom name (and registers it).
    static bool JoinShouldUseDefaultName(const std::string& name,
                                         const sockaddr* from, int fromlen)
    {
        uint64_t key = SourceKey(from, fromlen);
        bool loopback = IsLoopbackAddr(from);
        std::string hostUser = GetUsernameAscii();

        std::lock_guard<std::mutex> lk(s_peerMutex);
        DWORD now = GetTickCount();

        // Host username taken from a non-loopback ip -> not the real host.
        if (!hostUser.empty() && name == hostUser && !loopback) {
            LogF(L"[udp_relay] '%hs' uses host name from external ip -> Player%%d\n",
                 name.c_str());
            return true;
        }

        // Name already held by a DIFFERENT, still-active connection.
        std::map<std::string,uint64_t>::iterator u = s_userToKey.find(name);
        if (u != s_userToKey.end() && (key == 0 || u->second != key)) {
            std::map<uint64_t,PeerInfo>::iterator orig = s_peers.find(u->second);
            bool active = (orig != s_peers.end()) && (now - orig->second.lastSeen < kPeerTimeoutMs);
            if (active) {
                LogF(L"[udp_relay] '%hs' is already in use -> Player%%d\n", name.c_str());
                return true;
            }
        }

        // No conflict -> claim the name for this connection (only if we have a
        // real key; an unknown source isn't tracked).
        if (key != 0) {
            PeerInfo pi; pi.username = name; pi.lastSeen = now;
            s_peers[key] = pi;
            s_userToKey[name] = key;
        }
        return false;
    }

    // ---------- Magic packet construction ---------------------------------

    static int BuildMagicPacket(char* out, size_t outCap)
    {
        std::string name = GetUsernameAscii();
        if (name.empty()) return 0;

        std::string app = GetAppearanceAscii();
        size_t appPos = kHeaderSize + name.size() + kIdTrailer;  // appLen(2) + data sits here
        size_t total  = appPos + 2 + app.size();
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
        for (int i = 0; i < 8; ++i) t[i]     = (unsigned char)((uid >> (56 - 8 * i)) & 0xFF);
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
        LogF(L"[udp_relay] RECV magic from %hs:%d username='%hs' userId=%llu "
             L"accountAge=%u haveId=%d, patching now\n",
             srcIp, srcPort, name.c_str(),
             (unsigned long long)uid, (unsigned)age, (int)haveId);

        // Anti-impersonation: a conflicting username (already in use, or the
        // host's name from an external ip) still gets in, but as the default
        // "Player%d" - and we skip applying their relayed identity/appearance,
        // so they can't impersonate anyone. Non-conflicting names are kept.
        if (JoinShouldUseDefaultName(name, from, fromlen)) {
            PatchPlayerNameCallSite("Player%d");
            return true;
        }

        PatchPlayerNameCallSite(name);
        if (haveId)
            ApplyReceivedIdentity(uid, age);
        if (!appearance.empty())
            PostAppearanceToLocal(name, appearance);   // host -> local webserver
        return true;
    }

    // ---------- Hook implementations --------------------------------------

    static int WINAPI Hook_sendto(SOCKET s, const char* buf, int len,
                                  int flags, const sockaddr* to, int tolen)
    {
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
                sockaddr*   peerPtr    = nullptr;
                int         peerLenOut = 0;
                if (getpeername(s, reinterpret_cast<sockaddr*>(&peer), &peerLen) == 0)
                {
                    peerPtr    = reinterpret_cast<sockaddr*>(&peer);
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
            s_orig_sendto    = reinterpret_cast<PFN_sendto>(
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
        }

        LogF(L"[udp_relay] hooks: sendto=%p recvfrom=%p "
             L"WSASendTo=%p WSARecvFrom=%p WSARecv=%p\n",
             s_orig_sendto, s_orig_recvfrom,
             s_orig_WSASendTo, s_orig_WSARecvFrom, s_orig_WSARecv);

        if (!any)
        {
            LogF(L"[udp_relay] no ws2_32 imports hooked in main module\n");
            return false;
        }
        return true;
    }
}
