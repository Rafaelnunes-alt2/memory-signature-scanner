// feito por: maquinzz
#pragma once
#include <cstdint>
#include <string>
#include <vector>
namespace sigscan {
struct PatByte {
    bool wild = false;
    std::uint8_t val = 0;
};
constexpr std::size_t kMaxPat = 256;
constexpr std::size_t kMaxHits = 10000;
constexpr std::size_t kMaxScan = 256 * 1024 * 1024;
bool parsePattern(const std::string &text, std::vector<PatByte> &out, std::string &err);
std::vector<std::size_t> scanBuf(const std::uint8_t *data, std::size_t n, const std::vector<PatByte> &pat, std::size_t maxHits);
std::vector<std::uint64_t> scanPidLinux(int pid, const std::vector<PatByte> &pat, std::string &err);
std::vector<std::uint64_t> scanFileBytes(const std::string &path, const std::vector<PatByte> &pat, std::string &err);
int findPidByNameLinux(const std::string &name);
std::vector<std::uint64_t> scanPidWindows(int pid, const std::vector<PatByte> &pat, std::string &err);
int findPidByNameWindows(const std::string &name);
}
