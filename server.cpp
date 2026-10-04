// nfs-server: multi-threaded TCP file-sharing server.
//
// Protocol: every message is a 4-byte big-endian length followed by its
// payload. Commands (AUTH/LIST/UPLD/DOWN/DELE/QUIT) are newline-separated
// text frames; file data is transferred raw after an OKAY handshake.

#include <algorithm>
#include <cerrno>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#include <arpa/inet.h>
#include <crypt.h>
#include <netinet/in.h>
#include <unistd.h>

namespace fs = std::filesystem;

constexpr uint32_t MAX_FRAME = 1024 * 1024;         // largest message payload (bytes)
constexpr uint64_t MAX_FILE = 100ULL * 1024 * 1024; // largest transferable file (bytes)

std::mutex log_mutex;  // serializes writes to server.log
std::mutex file_mutex; // serializes storage access across client threads

fs::path root_dir = "storage";

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
        ssize_t r = send(fd, p, n, MSG_NOSIGNAL);
        if (r <= 0) return false;
        p += r;
        n -= r;
    }
    return true;
}

// Receive a length-prefixed frame (payload capped at MAX_FRAME).
bool recv_frame(int fd, std::string &s) {
    uint32_t net, n;
    if (!readn(fd, &net, 4)) return false;
    n = ntohl(net);
    if (n > MAX_FRAME) return false;
    s.resize(n);
    return !n || readn(fd, s.data(), n);
}

// Send a length-prefixed frame (payload capped at MAX_FRAME).
bool send_frame(int fd, const std::string &s) {
    if (s.size() > MAX_FRAME) return false;
    uint32_t n = htonl(static_cast<uint32_t>(s.size()));
    return writen(fd, &n, 4) && (s.empty() || writen(fd, s.data(), s.size()));
}

// ---------------------------------------------------------------------------
// Server helpers
// ---------------------------------------------------------------------------

// Append a line to server.log and mirror it to stderr.
void log(const std::string &s) {
    std::lock_guard<std::mutex> lock(log_mutex);
    std::ofstream f("server.log", std::ios::app);
    f << s << '\n';
    std::cerr << s << '\n';
}

// Reject empty names, "." / "..", and any path separator or control character.
bool valid_name(const std::string &name) {
    return !name.empty() && name != "." && name != ".." &&
           name.find('/') == std::string::npos &&
           name.find('\\') == std::string::npos &&
           name.find('\0') == std::string::npos &&
           name.find('\n') == std::string::npos &&
           name.find('\r') == std::string::npos &&
           name.find('\t') == std::string::npos;
}

// Map a file name to a path directly inside root_dir, or {} if invalid.
fs::path target(const std::string &name) {
    if (!valid_name(name)) return {};
    auto p = (root_dir / name).lexically_normal();
    return p.parent_path() == root_dir ? p : fs::path{};
}

// Check credentials against users.db ("name hash" per line, crypt hashes).
bool authenticate(const std::string &u, const std::string &pw) {
    std::ifstream db("users.db");
    std::string name, hash;
    while (db >> name >> hash) {
        if (name != u) continue;
        crypt_data data{};
        char *result = crypt_r(pw.c_str(), hash.c_str(), &data);
        return result && hash == result;
    }
    return false;
}

// Split a request into lines.
std::vector<std::string> lines(const std::string &s) {
    std::vector<std::string> out;
    std::istringstream in(s);
    std::string x;
    while (std::getline(in, x)) out.push_back(x);
    return out;
}

// ---------------------------------------------------------------------------
// Per-client session
// ---------------------------------------------------------------------------

// Serve one client until the connection drops or it sends QUIT.
void handle(int fd) {
    bool auth = false;
    std::string req;
    while (recv_frame(fd, req)) {
        auto v = lines(req);
        if (v.empty()) {
            send_frame(fd, "ERR! malformed request");
            continue;
        }

        if (v[0] == "AUTH" && v.size() == 3) {
            auth = authenticate(v[1], v[2]);
            send_frame(fd, auth ? "OKAY authenticated" : "ERR! invalid credentials");
            log(std::string(auth ? "login " : "failed login ") + v[1]);
        } else if (v[0] == "QUIT") {
            send_frame(fd, "OKAY bye");
            break;
        } else if (!auth) {
            send_frame(fd, "ERR! authenticate first");
        } else if (v[0] == "LIST" && v.size() == 1) {
            std::lock_guard<std::mutex> lock(file_mutex);
            std::ostringstream out;
            out << "OKAY\n";
            for (auto &e : fs::directory_iterator(root_dir)) {
                if (e.is_regular_file())
                    out << e.path().filename().string() << '\t'
                        << e.file_size() << '\n';
            }
            send_frame(fd, out.str());
            log("list");
        } else if (v[0] == "UPLD" && v.size() == 3) {
            auto p = target(v[1]);
            uint64_t size = 0;
            try {
                size = std::stoull(v[2]);
            } catch (...) {
                p.clear();
            }
            if (p.empty() || size > MAX_FILE) {
                send_frame(fd, "ERR! invalid filename or file too large");
                continue;
            }
            std::lock_guard<std::mutex> lock(file_mutex);
            if (fs::exists(p)) {
                send_frame(fd, "ERR! file exists");
                continue;
            }
            if (!send_frame(fd, "OKAY ready")) break;

            // Receive the file contents in chunks.
            std::ofstream out(p, std::ios::binary | std::ios::trunc);
            char buf[65536];
            uint64_t left = size;
            bool ok = static_cast<bool>(out);
            while (ok && left) {
                size_t n = static_cast<size_t>(std::min<uint64_t>(left, sizeof buf));
                if (!readn(fd, buf, n)) {
                    ok = false;
                    break;
                }
                out.write(buf, n);
                ok = static_cast<bool>(out);
                left -= n;
            }
            out.close();
            if (!ok || left) fs::remove(p);
            send_frame(fd, ok ? "OKAY uploaded" : "ERR! upload failed");
            log(ok ? "upload " + v[1] : "upload failed " + v[1]);
            if (!ok) break;
        } else if (v[0] == "DOWN" && v.size() == 2) {
            auto p = target(v[1]);
            std::lock_guard<std::mutex> lock(file_mutex);
            if (p.empty() || fs::is_symlink(fs::symlink_status(p)) ||
                !fs::is_regular_file(p)) {
                send_frame(fd, "ERR! file not found");
                continue;
            }
            uint64_t size = fs::file_size(p);
            if (size > MAX_FILE) {
                send_frame(fd, "ERR! file too large");
                continue;
            }
            if (!send_frame(fd, "OKAY\n" + std::to_string(size))) continue;

            // Send the file contents in chunks.
            std::ifstream in(p, std::ios::binary);
            char buf[65536];
            uint64_t left = size;
            bool ok = true;
            while (left) {
                size_t n = static_cast<size_t>(std::min<uint64_t>(left, sizeof buf));
                in.read(buf, n);
                if (static_cast<size_t>(in.gcount()) != n || !writen(fd, buf, n)) {
                    ok = false;
                    break;
                }
                left -= n;
            }
            log("download " + v[1]);
            if (!ok) break;
        } else if (v[0] == "DELE" && v.size() == 2) {
            auto p = target(v[1]);
            std::lock_guard<std::mutex> lock(file_mutex);
            bool ok = !p.empty() && !fs::is_symlink(fs::symlink_status(p)) &&
                      fs::is_regular_file(p) && fs::remove(p);
            send_frame(fd, ok ? "OKAY deleted" : "ERR! file not found");
            log(std::string(ok ? "delete " : "delete failed ") + v[1]);
        } else {
            send_frame(fd, "ERR! malformed or unknown command");
        }
    }
    close(fd);
}

// ---------------------------------------------------------------------------
// Startup
// ---------------------------------------------------------------------------

int main(int argc, char **argv) {
    int port = argc > 1 ? std::stoi(argv[1]) : 8080;
    if (port < 1 || port > 65535) {
        std::cerr << "invalid port\n";
        return 1;
    }

    fs::create_directories(root_dir);

    int s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) {
        perror("socket");
        return 1;
    }

    int yes = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof yes);

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(port);
    if (bind(s, reinterpret_cast<sockaddr *>(&addr), sizeof addr) ||
        listen(s, 16)) {
        perror("bind/listen");
        close(s);
        return 1;
    }

    log("listening on port " + std::to_string(port));

    // One detached thread per client connection.
    for (;;) {
        int c = accept(s, nullptr, nullptr);
        if (c < 0) {
            if (errno == EINTR) continue;
            perror("accept");
            continue;
        }
        std::thread([c] {
            try {
                handle(c);
            } catch (const std::exception &e) {
                log(std::string("client error: ") + e.what());
                close(c);
            }
        }).detach();
    }
}
