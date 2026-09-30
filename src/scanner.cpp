// feito por: maquinzz
#include "scanner.hpp"
#include <cctype>
#include <fstream>
namespace sigscan {
namespace {
int hexv(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}
}
bool parsePattern(const std::string &text, std::vector<PatByte> &out, std::string &err) {
    out.clear();
    std::size_t i = 0;
    std::size_t n = text.size();
    if (n == 0 || n > 4096) { err = "bad_pattern_len"; return false; }
    while (i < n) {
        while (i < n && (text[i] == ' ' || text[i] == '\t' || text[i] == '\r' || text[i] == '\n')) ++i;
        if (i >= n) break;
        if (out.size() >= kMaxPat) { err = "pattern_too_long"; return false; }
        char a = text[i];
        if (a == '?') {
            ++i;
            if (i < n && text[i] == '?') ++i;
            PatByte b;
            b.wild = true;
            b.val = 0;
            out.push_back(b);
            continue;
        }
        if (i + 1 >= n) { err = "bad_token"; return false; }
        char b = text[i + 1];
        int hi = hexv(a);
        int lo = hexv(b);
        if (hi < 0 || lo < 0) { err = "bad_hex"; return false; }
        PatByte p;
        p.wild = false;
        p.val = static_cast<std::uint8_t>((hi << 4) | lo);
        out.push_back(p);
        i += 2;
    }
    if (out.empty()) { err = "empty_pattern"; return false; }
    return true;
}
std::vector<std::size_t> scanBuf(const std::uint8_t *data, std::size_t n, const std::vector<PatByte> &pat, std::size_t maxHits) {
    std::vector<std::size_t> hits;
    if (data == nullptr) return hits;
    if (pat.empty() || pat.size() > kMaxPat) return hits;
    if (n == 0 || n > kMaxScan) return hits;
    if (maxHits == 0 || maxHits > kMaxHits) maxHits = kMaxHits;
    std::size_t m = pat.size();
    if (m > n) return hits;
    bool allWild = true;
    for (std::size_t k = 0; k < m; ++k) {
        if (!pat[k].wild) { allWild = false; break; }
    }
    if (allWild) {
        for (std::size_t i = 0; i + m <= n; ++i) {
            hits.push_back(i);
            if (hits.size() >= maxHits) break;
        }
        return hits;
    }
    std::size_t end = n - m;
    for (std::size_t i = 0; i <= end; ++i) {
        bool ok = true;
        for (std::size_t k = 0; k < m; ++k) {
            if (pat[k].wild) continue;
            if (data[i + k] != pat[k].val) { ok = false; break; }
        }
        if (ok) {
            hits.push_back(i);
            if (hits.size() >= maxHits) break;
        }
        if (i == end) break;
    }
    return hits;
}
std::vector<std::uint64_t> scanFileBytes(const std::string &path, const std::vector<PatByte> &pat, std::string &err) {
    std::vector<std::uint64_t> out;
    if (path.empty() || path.size() > 4096) { err = "bad_path"; return out; }
    if (pat.empty()) { err = "empty_pattern"; return out; }
    std::ifstream f(path, std::ios::binary | std::ios::ate);
    if (!f) { err = "open_failed"; return out; }
    std::streamsize sz = f.tellg();
    if (sz <= 0) { err = "empty_file"; return out; }
    if (sz > static_cast<std::streamsize>(kMaxScan)) { err = "too_big"; return out; }
    f.seekg(0, std::ios::beg);
    std::vector<std::uint8_t> buf(static_cast<std::size_t>(sz));
    if (!f.read(reinterpret_cast<char*>(buf.data()), sz)) { err = "read_failed"; return out; }
    auto h = scanBuf(buf.data(), buf.size(), pat, kMaxHits);
    for (auto v : h) out.push_back(static_cast<std::uint64_t>(v));
    return out;
}
}
