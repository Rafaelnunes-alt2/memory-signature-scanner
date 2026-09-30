// feito por: maquinzz
#include "scanner.hpp"
#ifdef _WIN32
#include <windows.h>
#include <tlhelp32.h>
namespace sigscan {
int findPidByNameWindows(const std::string &name) {
    if (name.empty() || name.size() > 256) return -1;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return -1;
    PROCESSENTRY32A pe;
    pe.dwSize = sizeof(pe);
    int found = -1;
    if (Process32FirstA(snap, &pe)) {
        do {
            if (name == pe.szExeFile) { found = static_cast<int>(pe.th32ProcessID); break; }
        } while (Process32NextA(snap, &pe));
    }
    CloseHandle(snap);
    return found;
}
std::vector<std::uint64_t> scanPidWindows(int pid, const std::vector<PatByte> &pat, std::string &err) {
    std::vector<std::uint64_t> out;
    if (pid <= 0) { err = "bad_pid"; return out; }
    if (pat.empty()) { err = "empty_pattern"; return out; }
    HANDLE h = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, static_cast<DWORD>(pid));
    if (!h) { err = "open_process_failed"; return out; }
    std::uintptr_t addr = 0;
    MEMORY_BASIC_INFORMATION mbi;
    std::size_t total = 0;
    const std::size_t lim = 256 * 1024 * 1024;
    while (VirtualQueryEx(h, reinterpret_cast<LPCVOID>(addr), &mbi, sizeof(mbi)) == sizeof(mbi)) {
        std::uintptr_t base = reinterpret_cast<std::uintptr_t>(mbi.BaseAddress);
        std::size_t sz = static_cast<std::size_t>(mbi.RegionSize);
        bool ok = (mbi.State == MEM_COMMIT);
        bool readable = (mbi.Protect & PAGE_READONLY) || (mbi.Protect & PAGE_READWRITE) || (mbi.Protect & PAGE_EXECUTE_READ) || (mbi.Protect & PAGE_EXECUTE_READWRITE) || (mbi.Protect & PAGE_WRITECOPY) || (mbi.Protect & PAGE_EXECUTE_WRITECOPY);
        bool guarded = (mbi.Protect & PAGE_GUARD) || (mbi.Protect & PAGE_NOACCESS);
        std::uintptr_t next = base + sz;
        if (next <= addr) break;
        addr = next;
        if (!ok || !readable || guarded) continue;
        if (sz == 0 || sz > 64 * 1024 * 1024) continue;
        if (total >= lim) break;
        if (total + sz > lim) sz = lim - total;
        std::vector<std::uint8_t> buf(sz);
        SIZE_T got = 0;
        if (!ReadProcessMemory(h, reinterpret_cast<LPCVOID>(base), buf.data(), sz, &got) || got == 0) continue;
        auto hits = scanBuf(buf.data(), static_cast<std::size_t>(got), pat, kMaxHits - out.size());
        for (auto o : hits) out.push_back(static_cast<std::uint64_t>(base) + o);
        if (out.size() >= kMaxHits) break;
        total += static_cast<std::size_t>(got);
        if (base + sz < base) break;
    }
    CloseHandle(h);
    return out;
}
}
#else
namespace sigscan {
int findPidByNameWindows(const std::string &name) {
    (void)name;
    return -1;
}
std::vector<std::uint64_t> scanPidWindows(int pid, const std::vector<PatByte> &pat, std::string &err) {
    (void)pid;
    (void)pat;
    err = "windows_only";
    return std::vector<std::uint64_t>{};
}
}
#endif
