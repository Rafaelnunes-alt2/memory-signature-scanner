// feito por: maquinzz
#include "scanner.hpp"
#include <cstdio>
#include <iostream>
namespace {
void usage() {
    std::cerr << "usage:\n";
    std::cerr << "  scanner --file <path> --pattern \"48 8B ??\" \n";
    std::cerr << "  scanner --pid <pid> --pattern \"48 8B ??\" \n";
    std::cerr << "  scanner --process <name> --pattern \"48 8B ??\" \n";
}
bool getArg(int argc, char **argv, const std::string &key, std::string &val) {
    for (int i = 1; i + 1 < argc; ++i) {
        if (key == argv[i]) { val = argv[i + 1]; return true; }
    }
    return false;
}
bool hasArg(int argc, char **argv, const std::string &key) {
    for (int i = 1; i < argc; ++i) {
        if (key == argv[i]) return true;
    }
    return false;
}
}
int main(int argc, char **argv) {
    if (hasArg(argc, argv, "--selftest")) {
        std::vector<std::uint8_t> buf(4096, 0x41);
        buf[100] = 0xDE;
        buf[101] = 0xAD;
        buf[102] = 0xBE;
        buf[103] = 0xEF;
        buf[2000] = 0xDE;
        buf[2001] = 0xAD;
        buf[2002] = 0x00;
        buf[2003] = 0xEF;
        std::vector<sigscan::PatByte> p1;
        std::string e1;
        sigscan::parsePattern("DE AD BE EF", p1, e1);
        auto h1 = sigscan::scanBuf(buf.data(), buf.size(), p1, 10000);
        std::vector<sigscan::PatByte> p2;
        std::string e2;
        sigscan::parsePattern("DE AD ?? EF", p2, e2);
        auto h2 = sigscan::scanBuf(buf.data(), buf.size(), p2, 10000);
        bool ok = (h1.size() == 1 && h1[0] == 100 && h2.size() == 2);
        std::cout << "selftest_exact=" << h1.size() << "\n";
        std::cout << "selftest_wild=" << h2.size() << "\n";
        std::cout << (ok ? "SELFTEST_OK" : "SELFTEST_FAIL") << "\n";
        return ok ? 0 : 2;
    }
    if (argc < 5) { usage(); return 1; }
    std::string patText;
    if (!getArg(argc, argv, "--pattern", patText)) { usage(); return 1; }
    std::vector<sigscan::PatByte> pat;
    std::string perr;
    if (!sigscan::parsePattern(patText, pat, perr)) {
        std::cerr << "pattern_failed: " << perr << "\n";
        return 1;
    }
    std::string fpath;
    std::string pidS;
    std::string procS;
    if (getArg(argc, argv, "--file", fpath)) {
        std::string err;
        auto hits = sigscan::scanFileBytes(fpath, pat, err);
        if (!err.empty() && hits.empty()) {
            bool maybeErr = (err == "open_failed" || err == "too_big" || err == "read_failed" || err == "bad_path");
            if (maybeErr) { std::cerr << "scan_failed: " << err << "\n"; return 2; }
        }
        for (auto o : hits) {
            char b[32] = {};
            std::snprintf(b, sizeof(b), "0x%llX", static_cast<unsigned long long>(o));
            std::cout << b << "\n";
        }
        std::cerr << "hits=" << hits.size() << "\n";
        return 0;
    }
    int pid = -1;
    if (getArg(argc, argv, "--pid", pidS)) {
        try { pid = std::stoi(pidS); } catch (...) { std::cerr << "bad_pid\n"; return 1; }
    } else if (getArg(argc, argv, "--process", procS)) {
#ifdef _WIN32
        pid = sigscan::findPidByNameWindows(procS);
#else
        pid = sigscan::findPidByNameLinux(procS);
#endif
        if (pid <= 0) { std::cerr << "process_not_found\n"; return 2; }
    } else {
        usage();
        return 1;
    }
    (void)hasArg;
    std::string err;
    std::vector<std::uint64_t> hits;
#ifdef _WIN32
    hits = sigscan::scanPidWindows(pid, pat, err);
#else
    hits = sigscan::scanPidLinux(pid, pat, err);
#endif
    if (!err.empty() && hits.empty()) {
        bool fatal = (err == "bad_pid" || err == "open_maps_failed" || err == "open_process_failed");
        if (fatal) { std::cerr << "scan_failed: " << err << "\n"; return 2; }
    }
    for (auto a : hits) {
        char b[32] = {};
        std::snprintf(b, sizeof(b), "0x%llX", static_cast<unsigned long long>(a));
        std::cout << b << "\n";
    }
    std::cerr << "hits=" << hits.size() << "\n";
    return 0;
}
