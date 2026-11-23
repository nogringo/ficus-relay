#include <cerrno>
#include <cstdlib>
#include <cstring>

#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <unistd.h>

#include "Net.h"


namespace banyan {


static bool isPrivateIpv4(uint32_t addr) {
    auto in = [&](uint32_t net, int bits){ return (addr >> (32 - bits)) == (net >> (32 - bits)); };

    return in(0x00000000, 8) || in(0x0A000000, 8) || in(0x64400000, 10) || in(0x7F000000, 8) || in(0xA9FE0000, 16)
        || in(0xAC100000, 12) || in(0xC0000000, 24) || in(0xC0A80000, 16) || in(0xC6120000, 15) || addr >= 0xE0000000;
}

bool isPrivateAddress(const sockaddr *sa) {
    if (sa->sa_family == AF_INET) return isPrivateIpv4(ntohl(((const sockaddr_in *)sa)->sin_addr.s_addr));
    if (sa->sa_family != AF_INET6) return true;

    const uint8_t *b = ((const sockaddr_in6 *)sa)->sin6_addr.s6_addr;
    static const uint8_t v4MappedPrefix[12] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF };
    static const uint8_t zeros[15] = {};

    if (memcmp(b, v4MappedPrefix, 12) == 0) return isPrivateIpv4(uint32_t(b[12]) << 24 | uint32_t(b[13]) << 16 | uint32_t(b[14]) << 8 | b[15]);
    if (memcmp(b, zeros, 15) == 0 && b[15] <= 1) return true;

    return (b[0] & 0xFE) == 0xFC || (b[0] == 0xFE && (b[1] & 0xC0) == 0x80) || b[0] == 0xFF;
}

bool isPrivateHost(std::string_view host) {
    if (auto pos = host.rfind(':'); pos != std::string_view::npos && host.find(']') == std::string_view::npos) host = host.substr(0, pos);
    if (host.ends_with('.')) host.remove_suffix(1);

    if (host.empty() || host.starts_with("[")) return true;
    if (host == "localhost" || host.ends_with(".localhost") || host.ends_with(".local") || host.ends_with(".internal") || host.ends_with(".onion")) return true;

    in_addr addr;
    if (inet_pton(AF_INET, std::string(host).c_str(), &addr) == 1) return isPrivateIpv4(ntohl(addr.s_addr));

    return false;
}

std::string numericAddress(const sockaddr *sa) {
    char buf[INET6_ADDRSTRLEN] = {};

    if (sa->sa_family == AF_INET) inet_ntop(AF_INET, &((const sockaddr_in *)sa)->sin_addr, buf, sizeof(buf));
    else if (sa->sa_family == AF_INET6) inet_ntop(AF_INET6, &((const sockaddr_in6 *)sa)->sin6_addr, buf, sizeof(buf));

    return buf;
}

HostPort splitHostPort(std::string_view hostAndPort, bool secure) {
    HostPort output{ std::string(hostAndPort), secure ? "443" : "80" };

    if (hostAndPort.starts_with("[")) {
        auto close = hostAndPort.find(']');
        if (close == std::string_view::npos) return output;
        output.host = std::string(hostAndPort.substr(1, close - 1));
        if (close + 1 < hostAndPort.size() && hostAndPort[close + 1] == ':') output.port = std::string(hostAndPort.substr(close + 2));
    } else if (auto colon = hostAndPort.rfind(':'); colon != std::string_view::npos) {
        output.host = std::string(hostAndPort.substr(0, colon));
        output.port = std::string(hostAndPort.substr(colon + 1));
    }

    return output;
}

ProbeOutcome probeTcp(std::string_view host, std::string_view port, int timeoutMs, bool allowPrivate) {
    ProbeOutcome output;

    addrinfo hints{}, *result = nullptr;
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(std::string(host).c_str(), std::string(port).c_str(), &hints, &result) != 0) return output;

    if (!allowPrivate && isPrivateAddress(result->ai_addr)) {
        freeaddrinfo(result);
        output.result = ProbeResult::PrivateAddress;
        return output;
    }

    bool ok = false;
    int fd = socket(result->ai_family, result->ai_socktype, result->ai_protocol);

    if (fd >= 0) {
        fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK);

        if (::connect(fd, result->ai_addr, result->ai_addrlen) == 0) {
            ok = true;
        } else if (errno == EINPROGRESS) {
            pollfd p{ fd, POLLOUT, 0 };
            if (poll(&p, 1, timeoutMs) == 1) {
                int err = 0;
                socklen_t len = sizeof(err);
                ok = getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &len) == 0 && err == 0;
            }
        }

        close(fd);
    }

    if (ok) {
        output.result = ProbeResult::Reachable;
        output.address = numericAddress(result->ai_addr);
        output.port = atoi(std::string(port).c_str());
    }

    freeaddrinfo(result);
    return output;
}


}
