#pragma once

#include <string>
#include <string_view>

#include <sys/socket.h>


namespace banyan {


// Private, loopback, link-local, CGNAT, multicast and reserved ranges, in both families
bool isPrivateAddress(const sockaddr *sa);

// Literal addresses and local names only: hostnames are checked again once resolved
bool isPrivateHost(std::string_view host);

std::string numericAddress(const sockaddr *sa);

struct HostPort {
    std::string host;
    std::string port;
};

// "host", "host:port" or "[v6]:port", with the scheme's default port
HostPort splitHostPort(std::string_view hostAndPort, bool secure);

enum class ProbeResult { Reachable, Unreachable, PrivateAddress };

struct ProbeOutcome {
    ProbeResult result = ProbeResult::Unreachable;
    std::string address; // numeric, the one the TCP connect reached
    int port = 0;
};

// Resolves and connects with a timeout, so callers can then connect to exactly the address that was checked
ProbeOutcome probeTcp(std::string_view host, std::string_view port, int timeoutMs, bool allowPrivate);


}
