#pragma once

#include <string>

#include <uWebSockets/src/uWS.h>
#include <uWebSockets/src/HTTPSocket.h>


namespace uWS {
    // Defined in Hub.cpp, not declared in its headers
    uS::Socket *allocateHttpSocket(uS::Socket *s);
}


namespace banyan {


// Protected members reached through pointers to members, which C++ allows from a derived class
struct SocketAccess : uS::Socket {
    static SSL *sslOf(uS::Socket *s) {
        return s->*(&SocketAccess::ssl);
    }

    template <void onTimeout(uS::Socket *, char *, size_t)>
    static void beginTimeout(uS::Socket *s, int timeoutMs) {
        void (uS::Socket::*fn)(int) = &SocketAccess::template startTimeout<onTimeout>;
        (s->*fn)(timeoutMs);
    }
};

struct ClientHttpAccess : uWS::HttpSocket<uWS::CLIENT> {
    static void onEnd(uS::Socket *s, char *message, size_t length) {
        uWS::HttpSocket<uWS::CLIENT>::onEnd(s, message, length);
    }
};


// uWS::Hub::connect() resolves the host again, so a DNS answer that changed since it was checked would be used.
// connectPinned() connects to the address that was checked, while TLS SNI and the Host header still name the host.
struct PinnedHub : uWS::Hub {
    using uWS::Hub::Hub;

    bool connectPinned(const std::string &address, int port, bool secure, const std::string &host, const std::string &path,
                       void *user, int timeoutMs, uWS::Group<uWS::CLIENT> *group, bool permessageDeflate) {
        uS::Socket *s = uS::Node::connect<uWS::allocateHttpSocket, uWS::Hub::onClientConnection>(address.c_str(), port, secure, group);
        if (!s) return false;

        if (secure) SSL_set_tlsext_host_name(SocketAccess::sslOf(s), host.c_str());

        auto *httpSocket = (uWS::HttpSocket<uWS::CLIENT> *) s;
        SocketAccess::beginTimeout<ClientHttpAccess::onEnd>(s, timeoutMs); // takes the user slot, hence httpUser
        httpSocket->httpUser = user;

        bool defaultPort = port == (secure ? 443 : 80);
        std::string hostHeader = host.find(':') != std::string::npos ? "[" + host + "]" : host;
        if (!defaultPort) hostHeader += ":" + std::to_string(port);

        httpSocket->httpBuffer = "GET /" + path + " HTTP/1.1\r\n"
                                 "Upgrade: websocket\r\n"
                                 "Connection: Upgrade\r\n"
                                 "Sec-WebSocket-Key: x3JJHMbDL1EzLkh9GBhXDw==\r\n"
                                 "Host: " + hostHeader + "\r\n"
                                 "Sec-WebSocket-Version: 13\r\n";

        if (permessageDeflate) {
            httpSocket->httpBuffer += "Sec-WebSocket-Extensions: permessage-deflate; server_no_context_takeover\r\n";
        }

        httpSocket->httpBuffer += "\r\n";
        return true;
    }
};


}
