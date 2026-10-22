// language: C++17, file: madium_unlock.cpp, runtime: Windows 11 x64, no external deps
// Patches the Madium 2.6.3 client-side license gates so the client accepts a locally served verdict.
//
// Reverse-engineered sites (Madium.exe SHA-256 ad1daac9f09763fb6632df5f92c76073e3c02cb4766917277e6469f9fb9f0a7a).
// Branch polarity was measured, not assumed: the string compare helper at 0x1400D0BD5 returns 0 on equal
// and 1 on differ, confirmed independently at the alg, hwid and status call sites.
//
//   expiry  0x140222F1E  7E 70 (jle)  -> 90 90   expires_at <= now() no longer aborts
//   hwid    0x140222E07  74 2E (je)   -> EB 2E   device binding always accepted
//   clock   0x140222E7A  72 71 (jb)   -> EB 71   issuedAt skew window always accepted
//   status  0x14021F71F  74 28 (je)   -> EB 28   status always treated as LICENSE_VALID
//   sig1    0x14021F545  74 2B (je)   -> 90 90   sign-in path: Ed25519 result ignored
//   sig2    0x140222DD1  74 4D (je)   -> 90 90   cached-verdict path: Ed25519 result ignored
//
// The optional --redirect patch moves the auth host to a local mock server:
//   string  file 0xB2FB94  "https://auth.getmadium.xyz"  ->  "http://<host:port>"
//   length  file 0xB2FBB8  u64 = 26                      ->  u64 = strlen(new host)

#include <windows.h>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>
#include <array>

namespace {

constexpr char kKnownBuildSha256[] = "ad1daac9f09763fb6632df5f92c76073e3c02cb4766917277e6469f9fb9f0a7a";
constexpr size_t kHostStringFileOffset = 0xB2FB94;
constexpr size_t kHostLengthFileOffset = 0xB2FBB8;
constexpr size_t kHostStringCapacity = 26;
constexpr char kOriginalHost[] = "https://auth.getmadium.xyz";
constexpr size_t kPubkeyFileOffset = 0xB2FF16; // pinned Ed25519 verifying key, 32 bytes
constexpr size_t kPubkeyCapacity = 32;

bool parseHex32(const std::string& hex, std::array<uint8_t, 32>& out) {
    if (hex.size() != 64) return false;
    auto nibble = [](char c, int& value) -> bool {
        if (c >= '0' && c <= '9') { value = c - '0'; return true; }
        if (c >= 'a' && c <= 'f') { value = c - 'a' + 10; return true; }
        if (c >= 'A' && c <= 'F') { value = c - 'A' + 10; return true; }
        return false;
    };
    for (size_t i = 0; i < 32; ++i) {
        int high = 0, low = 0;
        if (!nibble(hex[i * 2], high) || !nibble(hex[i * 2 + 1], low)) return false;
        out[i] = uint8_t((high << 4) | low);
    }
    return true;
}

struct Site {
    const char* name;
    uint64_t    va;
    size_t      fileOffset;
    std::array<uint8_t, 2> original;
    std::array<uint8_t, 2> replacement;
    const char* description;
    const char* profile;
};

const Site kSites[] = {
    {"expiry", 0x140222F1E, 0x22231E, {0x7E, 0x70}, {0x90, 0x90},
     "expires_at <= now() no longer aborts the verdict", "expiry"},
    {"hwid",   0x140222E07, 0x222207, {0x74, 0x2E}, {0xEB, 0x2E},
     "hwid comparison always continues past the device check", "unlock"},
    {"clock",  0x140222E7A, 0x22227A, {0x72, 0x71}, {0xEB, 0x71},
     "issuedAt skew window is always accepted", "unlock"},
    {"status", 0x14021F71F, 0x21EB1F, {0x74, 0x28}, {0xEB, 0x28},
     "status field is always treated as LICENSE_VALID", "unlock"},
    {"sig1",   0x14021F545, 0x21E945, {0x74, 0x2B}, {0x90, 0x90},
     "sign-in path: Ed25519 verification result ignored", "full"},
    {"sig2",   0x140222DD1, 0x2221D1, {0x74, 0x4D}, {0x90, 0x90},
     "cached-verdict path: Ed25519 verification result ignored", "full"},
};

bool profileIncludes(const char* profile, const char* siteProfile) {
    if (std::strcmp(profile, "expiry") == 0) return std::strcmp(siteProfile, "expiry") == 0;
    if (std::strcmp(profile, "unlock") == 0) return std::strcmp(siteProfile, "full") != 0;
    if (std::strcmp(profile, "full") == 0) return true;
    return false;
}

// ---------------------------------------------------------------- SHA-256

struct Sha256 {
    uint32_t state[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                          0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
    uint64_t bitLength = 0;
    uint8_t  buffer[64] = {};
    size_t   bufferLength = 0;

    static uint32_t rotr(uint32_t value, int bits) { return (value >> bits) | (value << (32 - bits)); }

    void compress(const uint8_t* block) {
        static const uint32_t k[64] = {
            0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
            0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
            0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
            0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
            0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
            0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
            0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
            0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2};
        uint32_t w[64];
        for (int i = 0; i < 16; ++i) {
            w[i] = (uint32_t(block[i * 4]) << 24) | (uint32_t(block[i * 4 + 1]) << 16) |
                   (uint32_t(block[i * 4 + 2]) << 8) | uint32_t(block[i * 4 + 3]);
        }
        for (int i = 16; i < 64; ++i) {
            uint32_t s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
            uint32_t s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16] + s0 + w[i - 7] + s1;
        }
        uint32_t a = state[0], b = state[1], c = state[2], d = state[3];
        uint32_t e = state[4], f = state[5], g = state[6], h = state[7];
        for (int i = 0; i < 64; ++i) {
            uint32_t s1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
            uint32_t ch = (e & f) ^ (~e & g);
            uint32_t temp1 = h + s1 + ch + k[i] + w[i];
            uint32_t s0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
            uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
            uint32_t temp2 = s0 + maj;
            h = g; g = f; f = e; e = d + temp1;
            d = c; c = b; b = a; a = temp1 + temp2;
        }
        state[0] += a; state[1] += b; state[2] += c; state[3] += d;
        state[4] += e; state[5] += f; state[6] += g; state[7] += h;
    }

    void update(const uint8_t* data, size_t length) {
        bitLength += uint64_t(length) * 8;
        while (length > 0) {
            size_t take = 64 - bufferLength;
            if (take > length) take = length;
            std::memcpy(buffer + bufferLength, data, take);
            bufferLength += take;
            data += take;
            length -= take;
            if (bufferLength == 64) { compress(buffer); bufferLength = 0; }
        }
    }

    std::string hex() {
        uint64_t total = bitLength;
        uint8_t pad = 0x80;
        update(&pad, 1);
        uint8_t zero = 0;
        while (bufferLength != 56) update(&zero, 1);
        uint8_t tail[8];
        for (int i = 0; i < 8; ++i) tail[i] = uint8_t(total >> (56 - i * 8));
        bitLength = total;
        std::memcpy(buffer + bufferLength, tail, 8);
        compress(buffer);
        static const char* digits = "0123456789abcdef";
        std::string out;
        out.reserve(64);
        for (uint32_t word : state) {
            for (int shift = 28; shift >= 0; shift -= 4) out.push_back(digits[(word >> shift) & 0xF]);
        }
        return out;
    }
};

std::string sha256Hex(const std::vector<uint8_t>& bytes) {
    Sha256 hash;
    hash.update(bytes.data(), bytes.size());
    return hash.hex();
}

// ---------------------------------------------------------------- file io

bool fileExists(const std::string& path) {
    DWORD attrs = GetFileAttributesA(path.c_str());
    return attrs != INVALID_FILE_ATTRIBUTES && !(attrs & FILE_ATTRIBUTE_DIRECTORY);
}

bool readFile(const std::string& path, std::vector<uint8_t>& out) {
    HANDLE handle = CreateFileA(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                                FILE_ATTRIBUTE_NORMAL, nullptr);
    if (handle == INVALID_HANDLE_VALUE) return false;
    LARGE_INTEGER size{};
    GetFileSizeEx(handle, &size);
    out.resize(size.QuadPart);
    DWORD read = 0;
    BOOL ok = ReadFile(handle, out.data(), DWORD(out.size()), &read, nullptr);
    CloseHandle(handle);
    return ok && read == out.size();
}

bool writeFile(const std::string& path, const std::vector<uint8_t>& bytes) {
    HANDLE handle = CreateFileA(path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                                FILE_ATTRIBUTE_NORMAL, nullptr);
    if (handle == INVALID_HANDLE_VALUE) return false;
    DWORD written = 0;
    BOOL ok = WriteFile(handle, bytes.data(), DWORD(bytes.size()), &written, nullptr);
    CloseHandle(handle);
    return ok && written == bytes.size();
}

bool copyFile(const std::string& from, const std::string& to) {
    return CopyFileA(from.c_str(), to.c_str(), FALSE) != 0;
}

// ---------------------------------------------------------------- reporting

struct SiteState {
    std::string name;
    uint64_t    va = 0;
    size_t      fileOffset = 0;
    std::array<uint8_t, 2> actual{};
    bool        matchesOriginal = false;
    bool        matchesReplacement = false;
    std::string description;
    std::string profile;
};

std::vector<SiteState> inspectSites(const std::vector<uint8_t>& bytes) {
    std::vector<SiteState> states;
    for (const Site& site : kSites) {
        SiteState state;
        state.name = site.name;
        state.va = site.va;
        state.fileOffset = site.fileOffset;
        state.description = site.description;
        state.profile = site.profile;
        if (site.fileOffset + 2 <= bytes.size()) {
            state.actual[0] = bytes[site.fileOffset];
            state.actual[1] = bytes[site.fileOffset + 1];
            state.matchesOriginal = state.actual == site.original;
            state.matchesReplacement = state.actual == site.replacement;
        }
        states.push_back(state);
    }
    return states;
}

void printSites(const std::vector<SiteState>& states) {
    printf("%-8s %-18s %-10s %-9s %-9s %s\n", "SITE", "VA", "FILE", "BYTES", "STATE", "PROFILE");
    for (const SiteState& state : states) {
        const char* label = state.matchesOriginal ? "original"
                          : state.matchesReplacement ? "patched" : "unknown";
        printf("%-8s 0x%012llX 0x%08X   %02X %02X     %-9s %s\n", state.name.c_str(),
               (unsigned long long)state.va, (unsigned)state.fileOffset, state.actual[0], state.actual[1],
               label, state.profile.c_str());
    }
}

void printHost(const std::vector<uint8_t>& bytes) {
    if (kHostStringFileOffset + kHostStringCapacity > bytes.size()) return;
    char host[64] = {};
    std::memcpy(host, bytes.data() + kHostStringFileOffset, kHostStringCapacity);
    host[sizeof(host) - 1] = '\0';
    uint64_t length = 0;
    std::memcpy(&length, bytes.data() + kHostLengthFileOffset, sizeof(length));
    const char* label = (std::strcmp(host, kOriginalHost) == 0) ? "original" : "redirected";
    printf("%-8s %-18s %-10s %-9s %-9s %s\n", "host", "-", "0xB2FB94", host, label, "full");
    printf("%-8s %-18s %-10s %llu\n", "hostlen", "-", "0xB2FBB8", (unsigned long long)length);
}

void printUsage() {
    printf("madium_unlock <Madium.exe> [options]\n\n");
    printf("  --list                  list patch sites and their current bytes\n");
    printf("  --verify                report state only, change nothing\n");
    printf("  --out <path>            write patched output (default <input>.patched.exe)\n");
    printf("  --in-place              patch the input file, keeping <input>.bak\n");
    printf("  --restore <backup>      copy a backup over the input file\n");
    printf("  --profile <name>        expiry | unlock | full   (default full)\n");
    printf("  --redirect <host:port>  point the auth host at a local server (needs profile full)\n");
    printf("  --pubkey <64 hex>       replace the pinned Ed25519 verifying key (32 bytes)\n");
    printf("  --ignore-build-check    patch even if the SHA-256 is not the analyzed build\n");
    printf("\nprofiles:\n");
    printf("  expiry  only the expires_at comparison\n");
    printf("  unlock  expiry + hwid + issuedAt skew + status\n");
    printf("  full    unlock + both Ed25519 verification results ignored\n");
}

std::string localUtcTimestamp() {
    SYSTEMTIME st{};
    GetSystemTime(&st);
    char buffer[64];
    sprintf_s(buffer, sizeof(buffer), "%04u-%02u-%02uT%02u:%02u:%02uZ", st.wYear, st.wMonth, st.wDay,
              st.wHour, st.wMinute, st.wSecond);
    return buffer;
}

} // namespace

int main(int argc, char** argv) {
    if (argc < 2) {
        printUsage();
        return 2;
    }

    std::string inputPath = argv[1];
    std::string outputPath;
    std::string profile = "full";
    std::string restoreFrom;
    std::string redirect;
    std::string pubkeyHex;
    bool listOnly = false;
    bool verifyOnly = false;
    bool inPlace = false;
    bool ignoreBuildCheck = false;

    for (int i = 2; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--list") listOnly = true;
        else if (arg == "--verify") verifyOnly = true;
        else if (arg == "--in-place") inPlace = true;
        else if (arg == "--ignore-build-check") ignoreBuildCheck = true;
        else if (arg == "--out" && i + 1 < argc) outputPath = argv[++i];
        else if (arg == "--profile" && i + 1 < argc) profile = argv[++i];
        else if (arg == "--restore" && i + 1 < argc) restoreFrom = argv[++i];
        else if (arg == "--redirect" && i + 1 < argc) redirect = argv[++i];
        else if (arg == "--pubkey" && i + 1 < argc) pubkeyHex = argv[++i];
        else {
            fprintf(stderr, "unrecognized argument: %s\n", arg.c_str());
            printUsage();
            return 2;
        }
    }

    if (profile != "expiry" && profile != "unlock" && profile != "full") {
        fprintf(stderr, "unknown profile: %s\n", profile.c_str());
        return 2;
    }
    if (!redirect.empty()) {
        std::string target = "http://" + redirect;
        if (target.size() > kHostStringCapacity) {
            fprintf(stderr, "redirect target too long: %s (max %zu chars)\n", target.c_str(),
                    kHostStringCapacity);
            return 2;
        }
        if (profile != "full") {
            fprintf(stderr, "--redirect needs --profile full so the Ed25519 result is ignored\n");
            return 2;
        }
    }
    std::array<uint8_t, 32> newPubkey{};
    bool havePubkey = false;
    if (!pubkeyHex.empty()) {
        if (!parseHex32(pubkeyHex, newPubkey)) {
            fprintf(stderr, "--pubkey needs exactly 64 hex characters\n");
            return 2;
        }
        havePubkey = true;
    }

    if (!restoreFrom.empty()) {
        if (!copyFile(restoreFrom, inputPath)) {
            fprintf(stderr, "restore failed: %s -> %s\n", restoreFrom.c_str(), inputPath.c_str());
            return 1;
        }
        printf("restored %s from %s\n", inputPath.c_str(), restoreFrom.c_str());
        return 0;
    }

    std::vector<uint8_t> bytes;
    if (!readFile(inputPath, bytes)) {
        fprintf(stderr, "cannot read %s\n", inputPath.c_str());
        return 1;
    }

    std::string digest = sha256Hex(bytes);
    printf("file      %s\n", inputPath.c_str());
    printf("sha256    %s\n", digest.c_str());
    printf("profile   %s\n", profile.c_str());
    if (!redirect.empty()) printf("redirect  http://%s\n", redirect.c_str());
    printf("now       %s (local UTC)\n", localUtcTimestamp().c_str());

    bool knownBuild = digest == kKnownBuildSha256;
    if (knownBuild) {
        printf("build     matches the analyzed Madium 2.6.3 build\n");
    } else {
        printf("WARNING   SHA-256 does not match the analyzed build %s\n", kKnownBuildSha256);
    }

    // The report modes never patch anything, so they must not be blocked by the
    // build check - a binary that already carries the patch hashes differently
    // and still has to be inspectable.
    if (listOnly || verifyOnly) {
        printSites(inspectSites(bytes));
        printHost(bytes);
        return 0;
    }

    // A binary that already carries our patch hashes differently. The per-site
    // byte assertions are the real safety net, so only refuse when the file
    // matches neither the pristine nor the patched state.
    bool allSitesKnown = true;
    for (const Site& site : kSites) {
        if (!profileIncludes(profile.c_str(), site.profile)) continue;
        if (site.fileOffset + 2 > bytes.size()) { allSitesKnown = false; break; }
        bool isOriginal = bytes[site.fileOffset] == site.original[0] &&
                          bytes[site.fileOffset + 1] == site.original[1];
        bool isPatched = bytes[site.fileOffset] == site.replacement[0] &&
                         bytes[site.fileOffset + 1] == site.replacement[1];
        if (!isOriginal && !isPatched) { allSitesKnown = false; break; }
    }
    if (!knownBuild && allSitesKnown) {
        printf("build     already carries this patch (sites match)\n");
        knownBuild = true;
    }

    if (!knownBuild && !ignoreBuildCheck) {
        fprintf(stderr, "aborting: pass --ignore-build-check to patch an unknown build\n");
        return 1;
    }

    std::vector<uint8_t> patched = bytes;
    int applied = 0;
    for (const Site& site : kSites) {
        if (!profileIncludes(profile.c_str(), site.profile)) continue;
        if (site.fileOffset + 2 > patched.size()) {
            fprintf(stderr, "site %s is out of bounds\n", site.name);
            return 1;
        }
        if (patched[site.fileOffset] == site.replacement[0] &&
            patched[site.fileOffset + 1] == site.replacement[1]) {
            printf("skip      %-7s already patched\n", site.name);
            continue;
        }
        if (patched[site.fileOffset] != site.original[0] ||
            patched[site.fileOffset + 1] != site.original[1]) {
            fprintf(stderr,
                    "site %s at VA 0x%llX has bytes %02X %02X, expected %02X %02X; refusing to patch\n",
                    site.name, (unsigned long long)site.va, patched[site.fileOffset],
                    patched[site.fileOffset + 1], site.original[0], site.original[1]);
            return 1;
        }
        patched[site.fileOffset] = site.replacement[0];
        patched[site.fileOffset + 1] = site.replacement[1];
        ++applied;
        printf("patch     %-7s VA 0x%012llX  %02X %02X -> %02X %02X\n", site.name,
               (unsigned long long)site.va, site.original[0], site.original[1], site.replacement[0],
               site.replacement[1]);
    }

    if (!redirect.empty()) {
        std::string target = "http://" + redirect;
        char current[64] = {};
        std::memcpy(current, patched.data() + kHostStringFileOffset, kHostStringCapacity);
        current[sizeof(current) - 1] = '\0';
        uint64_t currentLength = 0;
        std::memcpy(&currentLength, patched.data() + kHostLengthFileOffset, sizeof(currentLength));
        bool alreadyOurs = std::strcmp(current, target.c_str()) == 0;
        bool alreadyRedirected =
            std::strncmp(current, "http://", 7) == 0 || std::strncmp(current, "https://", 8) == 0;
        if (std::strcmp(current, kOriginalHost) != 0 && !alreadyOurs && !alreadyRedirected) {
            fprintf(stderr, "host string is already modified (%s / len %llu); refusing to touch it\n",
                    current, (unsigned long long)currentLength);
            return 1;
        }
        // Write only the new bytes: the capacity region is followed by unrelated consts that
        // must survive. The bytes between the new string and the end of the reserved
        // region are cleared so nothing of the old host can leak into a read that
        // does not stop at the length field.
        std::memcpy(patched.data() + kHostStringFileOffset, target.data(), target.size());
        for (size_t i = target.size(); i < kHostStringCapacity; ++i) {
            patched[kHostStringFileOffset + i] = 0;
        }
        uint64_t newLength = target.size();
        std::memcpy(patched.data() + kHostLengthFileOffset, &newLength, sizeof(newLength));
        ++applied;
        printf("patch     host    file 0x%08X  %s -> %s (len %llu)\n",
               (unsigned)kHostStringFileOffset, current, target.c_str(),
               (unsigned long long)newLength);
    }

    if (havePubkey) {
        if (kPubkeyFileOffset + kPubkeyCapacity > patched.size()) {
            fprintf(stderr, "pubkey region is out of bounds\n");
            return 1;
        }
        char oldHex[65] = {};
        for (size_t i = 0; i < 32; ++i) {
            sprintf_s(oldHex + i * 2, 3, "%02x", patched[kPubkeyFileOffset + i]);
        }
        std::memcpy(patched.data() + kPubkeyFileOffset, newPubkey.data(), kPubkeyCapacity);
        ++applied;
        printf("patch     pubkey  file 0x%08X  %s -> %s\n", (unsigned)kPubkeyFileOffset, oldHex,
               pubkeyHex.c_str());
    }

    if (applied == 0) {
        printf("nothing to do\n");
        return 0;
    }

    if (inPlace) {
        std::string backup = inputPath + ".bak";
        // A backup only counts as a backup if it holds the pristine bytes.
        // Re-patching an already-patched binary would otherwise leave a "backup"
        // that is just the patched file, which makes restore useless.
        bool backupIsPristine = false;
        if (fileExists(backup)) {
            std::vector<uint8_t> existing;
            if (readFile(backup, existing) && sha256Hex(existing) == kKnownBuildSha256) {
                backupIsPristine = true;
            }
        }
        if (!backupIsPristine) {
            if (fileExists(backup)) {
                std::string stale = backup + ".stale";
                printf("backup   %s (not pristine, moved to %s)\n", backup.c_str(), stale.c_str());
                remove(backup.c_str());
                rename(backup.c_str(), stale.c_str());
            }
            if (!copyFile(inputPath, backup)) {
                fprintf(stderr, "cannot create backup %s\n", backup.c_str());
                return 1;
            }
        } else {
            printf("backup   %s (pristine, kept)\n", backup.c_str());
        }
        if (!writeFile(inputPath, patched)) {
            fprintf(stderr, "cannot write %s\n", inputPath.c_str());
            return 1;
        }
        printf("wrote    %s\n", inputPath.c_str());
    } else {
        if (outputPath.empty()) outputPath = inputPath + ".patched.exe";
        if (!writeFile(outputPath, patched)) {
            fprintf(stderr, "cannot write %s\n", outputPath.c_str());
            return 1;
        }
        printf("wrote     %s\n", outputPath.c_str());
    }

    printf("sha256    %s\n", sha256Hex(patched).c_str());
    printf("\nre-verify:\n");
    printSites(inspectSites(patched));
    printHost(patched);
    return 0;
}
