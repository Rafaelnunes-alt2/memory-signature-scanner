// feito por: maquinzz
#include "scanner.hpp"
#include <cstdio>
#include <cstring>
#include <dirent.h>
#include <fstream>
#include <sstream>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>
namespace sigscan {
namespace {
constexpr std::size_t kMaxRegion = 64 * 1024 * 1024;
constexpr std::size_t kMaxTotal = 256 * 1024 * 1024;
bool parseMapLine(const std::string &line, std::uint64_t &start, std::uint64_t &end, bool &readable) {
    start = 0;
    end = 0;
    readable = false;
    std::size_t dash = line.find('-');
    if (dash == std::string::npos) return false;
    std::size_t sp = line.find(' ', dash);
    if (sp == std::string::npos) return false;
    std::string a = line.substr(0, dash);
    std::string b = line.substr(dash + 1, sp - dash - 1);
    try {
        start = std::stoull(a, nullptr, 16);
        end = std::stoull(b, nullptr, 16);
    } catch (...) {
        return false;
    }
    if (end <= start) return false;
    if (sp + 1 >= line.size()) return false;
    readable = (line[sp + 1] == 'r');
    return true;
}
}
int findPidByNameLinux(const std::string &name) {
    if (name.empty() || name.size() > 256) return -1;
    DIR *d = opendir("/proc");
    if (!d) return -1;
    int found = -1;
    struct dirent *e = nullptr;
    while ((e = readdir(d)) != nullptr) {
        const char *n = e->d_name;
        if (n[0] < '0' || n[0] > '9') continue;
        int pid = std::atoi(n);
        if (pid <= 0) continue;
        std::string cp = std::string("/proc") + std::string("/") + n + std::string("/") + std::string("comm");
        std::ifstream cf(cp);
        if (!cf) continue;
        std::string comm;
        std::getline(cf, comm);
        while (!comm.empty() && (comm.back() == '\n' || comm.back() == '\r')) comm.pop_back();
        if (comm == name) { found = pid; break; }
    }
    closedir(d);
    return found;
}
std::vector<std::uint64_t> scanPidLinux(int pid, const std::vector<PatByte> &pat, std::string &err) {
    std::vector<std::uint64_t> out;
    if (pid <= 0 || pid > 4194304) { err = "bad_pid"; return out; }
    if (pat.empty()) { err = "empty_pattern"; return out; }
    std::string mp = std::string("/proc") + std::string("/") + std::to_string(pid) + std::string("/") + std::string("maps");
    std::ifstream mf(mp);
    if (!mf) { err = "open_maps_failed"; return out; }
    std::string line;
    std::size_t total = 0;
    std::size_t m = pat.size();
    std::vector<std::uint8_t> tail;
    tail.reserve(m > 1 ? m - 1 : 0);
    std::uint64_t prevEnd = 0;
    bool first = true;
    while (std::getline(mf, line)) {
        std::uint64_t s = 0, e = 0;
        bool rd = false;
        if (!parseMapLine(line, s, e, rd)) continue;
        if (!rd) continue;
        if (e - s > kMaxRegion) continue;
        if (total >= kMaxTotal) break;
        std::size_t len = static_cast<std::size_t>(e - s);
        if (len == 0) continue;
        if (total + len > kMaxTotal) len = kMaxTotal - total;
        std::vector<std::uint8_t> buf(len);
        struct iovec local;
        struct iovec remote;
        local.iov_base = buf.data();
        local.iov_len = len;
        remote.iov_base = reinterpret_cast<void*>(static_cast<std::uintptr_t>(s));
        remote.iov_len = len;
        ssize_t got = process_vm_readv(pid, &local, 1, &remote, 1, 0);
        if (got <= 0) continue;
        std::size_t gn = static_cast<std::size_t>(got);
        std::vector<std::uint8_t> joined;
        joined.reserve(tail.size() + gn);
        std::uint64_t joinBase = first ? s : (prevEnd > m ? prevEnd - (m - 1) : s);
        if (!first && !tail.empty()) {
            for (auto c : tail) joined.push_back(c);
            for (std::size_t i = 0; i < gn; ++i) joined.push_back(buf[i]);
            joinBase = prevEnd - tail.size();
        } else {
            for (std::size_t i = 0; i < gn; ++i) joined.push_back(buf[i]);
            joinBase = s;
        }
        auto h = scanBuf(joined.data(), joined.size(), pat, kMaxHits - out.size());
        for (auto off : h) {
            out.push_back(joinBase + static_cast<std::uint64_t>(off));
            if (out.size() >= kMaxHits) break;
        }
        if (out.size() >= kMaxHits) break;
        tail.clear();
        if (m > 1 && gn >= m - 1) {
            for (std::size_t i = gn - (m - 1); i < gn; ++i) tail.push_back(buf[i]);
        } else if (gn > 0) {
            for (std::size_t i = 0; i < gn; ++i) tail.push_back(buf[i]);
        }
        prevEnd = s + gn;
        first = false;
        total += gn;
        if (total >= kMaxTotal) break;
    }
    if (mf.bad()) { err = "read_maps_failed"; return out; }
    return out;
}
}
