// nfs-client: minimal TCP file-sharing client.
//
// Protocol: every message is a 4-byte big-endian length followed by its
// payload. Commands are newline-separated text frames; file data is sent raw
// after an OKAY handshake.

#include <algorithm>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>

#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#include <unistd.h>

namespace fs = std::filesystem;

// ---------------------------------------------------------------------------
// Framing helpers
// ---------------------------------------------------------------------------

// Receive exactly n bytes, looping over partial reads.
bool readn(int fd, void *buf, size_t n) {
    auto p = static_cast<char *>(buf);
    while (n) {
        ssize_t r = recv(fd, p, n, 0);
        if (r <= 0) return false;
        p += r;
        n -= r;
    }
    return true;
}

// Send exactly n bytes, looping over partial writes.
bool writen(int fd, const void *buf, size_t n) {
    auto p = static_cast<const char *>(buf);
    while (n) {
        ssize_t r = send(fd, p, n, 0);
        if (r <= 0) return false;
        p += r;
        n -= r;
    }
    return true;
}

// Send a length-prefixed text frame.
bool sendf(int fd, const std::string &s) {
    uint32_t n = htonl(s.size());
    return writen(fd, &n, 4) && writen(fd, s.data(), s.size());
}

// Receive a length-prefixed text frame (payload capped at 1 MiB).
bool recvf(int fd, std::string &s) {
    uint32_t n;
    if (!readn(fd, &n, 4)) return false;
    n = ntohl(n);
    if (n > 1024 * 1024) return false;
    s.resize(n);
    return !n || readn(fd, s.data(), n);
}

// Accept a plain file name, or return "" if it contains path separators,
// control characters, or is "." / "..".
std::string safe_remote(const std::string &s) {
    if (!s.empty() && s.find_first_of("/\\\n\r\t") == std::string::npos &&
        s != "." && s != "..")
        return s;
    return "";
}

int main(int argc, char **argv) {
    if (argc < 3) {
        std::cerr << "usage: nfs-client HOST PORT\n";
        return 1;
    }

    // Resolve the host and open a connected socket.
    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    addrinfo *res = nullptr;
    if (getaddrinfo(argv[1], argv[2], &hints, &res)) {
        std::cerr << "invalid host/port\n";
        return 1;
    }

    int fd = -1;
    for (auto *p = res; p; p = p->ai_next) {
        fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (fd >= 0 && connect(fd, p->ai_addr, p->ai_addrlen) == 0) break;
        if (fd >= 0) close(fd);
        fd = -1;
    }
    freeaddrinfo(res);
    if (fd < 0) {
        perror("connect");
        return 1;
    }

    // Log in.
    std::string user, pw;
    std::cout << "username: ";
    std::getline(std::cin, user);
    std::cout << "password: ";
    std::getline(std::cin, pw);

    std::string response;
    if (!sendf(fd, "AUTH\n" + user + "\n" + pw) || !recvf(fd, response)) {
        std::cerr << "connection failed\n";
        close(fd);
        return 1;
    }
    std::cout << response << '\n';
    if (response.rfind("OKAY", 0) != 0) {
        close(fd);
        return 1;
    }

    // Command loop.
    std::string line;
    while (std::cout << "nfs> " && std::getline(std::cin, line)) {
        std::istringstream in(line);
        std::string cmd, arg, extra;
        in >> cmd;
        if (cmd.empty()) continue;

        if (cmd == "exit" || cmd == "quit") {
            sendf(fd, "QUIT");
            recvf(fd, response);
            std::cout << response << '\n';
            break;
        }

        if (cmd == "list") {
            if (!sendf(fd, "LIST") || !recvf(fd, response)) break;
            std::cout << response << '\n';
            continue;
        }

        if (cmd == "upload") {
            in >> arg;
            if (in >> extra || arg.empty()) {
                std::cout << "usage: upload LOCAL_FILE\n";
                continue;
            }
            fs::path local = arg;
            std::string remote = safe_remote(local.filename().string());
            std::error_code ec;
            auto size = fs::file_size(local, ec);
            if (remote.empty() || ec) {
                std::cout << "cannot read local file or invalid filename\n";
                continue;
            }

            if (!sendf(fd, "UPLD\n" + remote + "\n" + std::to_string(size)) ||
                !recvf(fd, response))
                break;
            if (response.rfind("OKAY", 0) != 0) {
                std::cout << response << '\n';
                continue;
            }

            // Stream the file contents in chunks.
            std::ifstream f(local, std::ios::binary);
            char b[65536];
            uint64_t left = size;
            bool ok = static_cast<bool>(f);
            while (ok && left) {
                size_t n = std::min<uint64_t>(left, sizeof b);
                f.read(b, n);
                ok = static_cast<size_t>(f.gcount()) == n && writen(fd, b, n);
                left -= ok ? n : 0;
            }
            if (!ok || !recvf(fd, response)) {
                std::cerr << "upload connection failed\n";
                break;
            }
            std::cout << response << '\n';
            continue;
        }

        if (cmd == "download") {
            in >> arg;
            if (in >> extra || safe_remote(arg).empty()) {
                std::cout << "usage: download REMOTE_FILE\n";
                continue;
            }

            if (!sendf(fd, "DOWN\n" + arg) || !recvf(fd, response)) break;
            if (response.rfind("OKAY\n", 0) != 0) {
                std::cout << response << '\n';
                continue;
            }

            // Stream the response payload in chunks.
            uint64_t size = std::stoull(response.substr(5));
            std::ofstream f(arg, std::ios::binary | std::ios::trunc);
            char b[65536];
            bool ok = static_cast<bool>(f);
            while (ok && size) {
                size_t n = std::min<uint64_t>(size, sizeof b);
                if (!readn(fd, b, n)) {
                    ok = false;
                    break;
                }
                f.write(b, n);
                ok = static_cast<bool>(f);
                size -= n;
            }
            std::cout << (ok ? "OKAY downloaded" : "ERR! download failed") << '\n';
            continue;
        }

        if (cmd == "delete") {
            in >> arg;
            if (in >> extra || safe_remote(arg).empty()) {
                std::cout << "usage: delete REMOTE_FILE\n";
                continue;
            }
            if (!sendf(fd, "DELE\n" + arg) || !recvf(fd, response)) break;
            std::cout << response << '\n';
            continue;
        }

        std::cout << "commands: list, upload LOCAL_FILE, download REMOTE_FILE, "
                     "delete REMOTE_FILE, exit\n";
    }

    close(fd);
}
