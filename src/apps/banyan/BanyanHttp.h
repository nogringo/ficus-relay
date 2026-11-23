#pragma once

#include <string>

#include <tao/json.hpp>

#include "Tenants.h"


namespace banyan {


struct HttpRequestInfo {
    std::string method; // upper case
    std::string path;   // normalized, see normalizePath()
    std::string host;
    std::string accept;
    std::string authorization;
    std::string body;
};

struct HttpReply {
    int status = 200;
    std::string contentType = "application/json";
    std::string body;
};

std::string httpStatusText(int status);

HttpReply handleAdminRpc(const HttpRequestInfo &req);

HttpReply tenantLandingPage(const TenantView &tenant, const std::string &host);

// Public URL of a virtual relay, or empty if relay.auth.serviceUrl is not configured
std::string tenantRelayUrl(const TenantView &tenant);

tao::json::value tenantSummaryJson(const TenantView &tenant);
tao::json::value tenantDetailJson(const TenantView &tenant);

std::string htmlEscape(std::string_view s);

// Throws if the header is not a valid NIP-98 authorization for this request. Returns the signer.
Bytes32 verifyNip98(std::string_view authorization, std::string_view method, std::string_view expectedHost, std::string_view path, std::string_view body);

bool isAdmin(const Bytes32 &pubkey);

std::string_view adminPageHtml();


}
