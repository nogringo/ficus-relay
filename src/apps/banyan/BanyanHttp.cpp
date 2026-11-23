#include <secp256k1_schnorrsig.h>
#include <hoytech/time.h>
#include <hoytech/hex.h>

#include "BanyanHttp.h"
#include "TrustEngine.h"
#include "Harvester.h"
#include "RemoteSigner.h"
#include "events.h"
#include "DBQuery.h"
#include "Decompressor.h"
#include "BanyanAdminHtml.h"


namespace banyan {


std::string httpStatusText(int status) {
    switch (status) {
        case 200: return "OK";
        case 204: return "No Content";
        case 400: return "Bad Request";
        case 401: return "Unauthorized";
        case 403: return "Forbidden";
        case 404: return "Not Found";
        case 405: return "Method Not Allowed";
        case 413: return "Payload Too Large";
        default: return "Internal Server Error";
    }
}

std::string htmlEscape(std::string_view s) {
    std::string output;
    output.reserve(s.size());

    for (char c : s) {
        switch (c) {
            case '&': output += "&amp;"; break;
            case '<': output += "&lt;"; break;
            case '>': output += "&gt;"; break;
            case '"': output += "&quot;"; break;
            case '\'': output += "&#39;"; break;
            default: output += c;
        }
    }

    return output;
}

std::string_view adminPageHtml() {
    return banyanAdminHtml;
}


static std::string toLower(std::string_view s) {
    std::string output(s);
    std::transform(output.begin(), output.end(), output.begin(), [](unsigned char c){ return std::tolower(c); });
    return output;
}

static secp256k1_context *secpCtx() {
    static secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);
    return ctx;
}

Bytes32 verifyNip98(std::string_view authorization, std::string_view method, std::string_view expectedHost, std::string_view path, std::string_view body) {
    if (!authorization.starts_with("Nostr ")) throw herr("missing NIP-98 Authorization header");

    auto encoded = authorization.substr(6);
    while (encoded.size() && isspace((unsigned char)encoded.back())) encoded.remove_suffix(1);
    auto evJson = tao::json::from_string(base64Decode(encoded));

    std::string packedStr, jsonStr;
    parseAndVerifyEvent(evJson, secpCtx(), true, false, packedStr, jsonStr);
    PackedEventView packed(packedStr);

    if (packed.kind() != 27235) throw herr("NIP-98 event must be kind 27235");

    uint64_t now = hoytech::curr_time_s();
    if (packed.created_at() + 60 < now || packed.created_at() > now + 60) throw herr("NIP-98 event is too old or in the future");

    bool urlOk = false, methodOk = false;
    std::optional<std::string> payload;

    for (const auto &tagj : evJson.at("tags").get_array()) {
        if (!tagj.is_array()) continue;
        const auto &tag = tagj.get_array();
        if (tag.size() < 2 || !tag[0].is_string() || !tag[1].is_string()) continue;

        const auto &name = tag[0].get_string();
        const auto &val = tag[1].get_string();

        if (name == "u") {
            auto parts = parseRelayUrl(val);
            urlOk = parts.host == toLower(expectedHost) && parts.path == path;
        } else if (name == "method") {
            std::string upper(val);
            std::transform(upper.begin(), upper.end(), upper.begin(), [](unsigned char c){ return std::toupper(c); });
            methodOk = upper == method;
        } else if (name == "payload") {
            payload = toLower(val);
        }
    }

    if (!urlOk) throw herr("NIP-98 u tag does not match this URL");
    if (!methodOk) throw herr("NIP-98 method tag does not match");
    if (body.size() && (!payload || *payload != to_hex(sha256(body).sv()))) throw herr("NIP-98 payload tag does not match the body");

    static flat_hash_map<std::string, uint64_t> seenIds;
    for (auto it = seenIds.begin(); it != seenIds.end(); ) {
        if (it->second + 120 < now) seenIds.erase(it++);
        else ++it;
    }
    if (!seenIds.emplace(std::string(packed.id()), now).second) throw herr("NIP-98 event already used");

    return Bytes32(packed.pubkey());
}

bool isAdmin(const Bytes32 &pubkey) {
    static uint64_t cachedVersion = 0;
    static flat_hash_set<Bytes32> admins;

    if (cachedVersion != cfg().version()) {
        admins = parsePubkeyList(cfg().banyan__admins);
        cachedVersion = cfg().version();
    }

    return admins.contains(pubkey);
}


std::string tenantRelayUrl(const TenantView &tenant) {
    std::string base = cfg().relay__auth__serviceUrl;
    if (base.empty()) return "";
    while (base.size() && base.back() == '/') base.pop_back();
    return base + "/" + tenant.slug;
}

tao::json::value tenantSummaryJson(const TenantView &tenant) {
    auto relayUrl = tenantRelayUrl(tenant);

    return tao::json::value({
        { "slug", tenant.slug },
        { "pubkey", to_hex(tenant.pubkey.sv()) },
        { "npub", tenant.npub },
        { "addedAt", tenant.addedAt },
        { "relayUrl", relayUrl.size() ? tao::json::value(relayUrl) : tao::json::value(tao::json::null) },
        { "universeSize", tenant.universe.size() },
        { "primaryCount", tenant.countCircle(Circle::Primary) },
        { "secondaryCount", tenant.countCircle(Circle::Secondary) },
        { "pinnedCount", tenant.countCircle(Circle::Pinned) },
        { "computedAt", tenant.computedAt },
    });
}

static void addProfile(lmdb::txn &txn, Decompressor &decomp, tao::json::value &item, const Bytes32 &pk) {
    item["name"] = tao::json::null;
    item["picture"] = tao::json::null;

    tao::json::value filter = tao::json::value({
        { "authors", tao::json::value::array({ to_hex(pk.sv()) }) },
        { "kinds", tao::json::value::array({ uint64_t(0) }) },
        { "limit", uint64_t(1) },
    });

    foreachByFilter(txn, filter, [&](uint64_t levId){
        try {
            auto ev = tao::json::from_string(getEventJson(txn, decomp, levId));
            auto content = tao::json::from_string(ev.at("content").get_string());
            if (!content.is_object()) return;

            for (const char *k : { "display_name", "name" }) {
                if (auto *v = content.find(k); v && v->is_string() && v->get_string().size()) {
                    item["name"] = v->get_string();
                    break;
                }
            }

            if (auto *v = content.find("picture"); v && v->is_string() && v->get_string().starts_with("https://")) {
                item["picture"] = v->get_string();
            }
        } catch (std::exception &) {
        }
    });
}

tao::json::value tenantDetailJson(const TenantView &tenant) {
    auto output = tenantSummaryJson(tenant);
    output["settings"] = tenant.settings.toJson();
    output["muted"] = tao::json::value({
        { "fromMuteList", tenant.muted ? tenant.muted->fromMuteList : 0 },
        { "hiddenEvents", tenant.muted ? tenant.muted->events.size() : 0 },
    });

    auto txn = env.txn_ro();
    Decompressor decomp;

    tao::json::value members = tao::json::empty_array;

    for (const auto &m : tenant.members) {
        tao::json::value via = tao::json::empty_array;
        for (const auto &v : m.via) via.emplace_back(to_hex(v.sv()));

        tao::json::value item = tao::json::value({
            { "pubkey", to_hex(m.pubkey.sv()) },
            { "npub", toNpub(m.pubkey) },
            { "circle", std::string(circleName(m.circle)) },
            { "score", m.score },
            { "via", via },
        });

        addProfile(txn, decomp, item, m.pubkey);
        members.emplace_back(std::move(item));
    }

    output["members"] = std::move(members);
    output["signer"] = signerJson(txn, tenant.id);

    return output;
}


struct Forbidden : std::runtime_error {
    using std::runtime_error::runtime_error;
};

static TenantPtr ownTenant(const Bytes32 &pubkey) {
    if (!cfg().banyan__owners__enabled) return nullptr;

    for (const auto &t : TenantRegistry::get()->tenants) {
        if (t->pubkey == pubkey) return t;
    }

    return nullptr;
}

// Owners share the server's harvester, so the admin bounds what they can ask of it
static void checkOwnerPatch(const tao::json::value &patch) {
    auto number = [](const tao::json::value &v){
        return v.is_double() ? v.get_double() : v.is_signed() ? (double)v.get_signed() : v.is_unsigned() ? (double)v.get_unsigned() : -1.0;
    };

    for (const auto &[k, v] : patch.get_object()) {
        if (k == "slug") {
            throw Forbidden("only an admin can change the slug");
        } else if (k == "primaryCircleSize" && number(v) > (double)cfg().banyan__owners__maxPrimaryCircleSize) {
            throw herr("primaryCircleSize can be at most ", cfg().banyan__owners__maxPrimaryCircleSize);
        } else if (k == "secondaryPerPeer" && number(v) > (double)cfg().banyan__owners__maxSecondaryPerPeer) {
            throw herr("secondaryPerPeer can be at most ", cfg().banyan__owners__maxSecondaryPerPeer);
        } else if (k == "pinned" && v.is_array() && v.get_array().size() > cfg().banyan__owners__maxPinned) {
            throw herr("at most ", cfg().banyan__owners__maxPinned, " people can be pinned");
        } else if (k == "mutedThreads" && v.is_array() && v.get_array().size() > cfg().banyan__owners__maxMutedThreads) {
            throw herr("at most ", cfg().banyan__owners__maxMutedThreads, " threads can be muted");
        }
    }
}

static tao::json::value ownerLimitsJson() {
    return tao::json::value({
        { "primaryCircleSize", cfg().banyan__owners__maxPrimaryCircleSize },
        { "secondaryPerPeer", cfg().banyan__owners__maxSecondaryPerPeer },
        { "pinned", cfg().banyan__owners__maxPinned },
        { "mutedThreads", cfg().banyan__owners__maxMutedThreads },
    });
}

static TenantPtr lookupTenant(const std::string &slugOrPubkey) {
    auto snap = TenantRegistry::get();

    if (auto t = snap->findByPath(normalizePath(slugOrPubkey))) return t;

    try {
        auto pk = parsePubkey(slugOrPubkey);
        for (const auto &t : snap->tenants) {
            if (t->pubkey == pk) return t;
        }
    } catch (std::exception &) {
    }

    throw herr("unknown person: ", slugOrPubkey);
}

static bool patchAffectsTrust(const tao::json::value &patch) {
    for (const auto &[k, v] : patch.get_object()) {
        if (k != "slug" && k != "mutedThreads") return true;
    }
    return false;
}

static const std::vector<std::string> ownerMethods = { "supportedmethods", "whoami", "listtenants", "gettenant", "updatetenant", "recomputetrust", "connectsigner", "nostrconnect", "removesigner" };

static tao::json::value dispatchRpc(const std::string &method, const tao::json::value &params, const Bytes32 &signer, bool admin) {
    auto param = [&](size_t i) -> const tao::json::value & {
        if (i >= params.get_array().size()) throw herr("missing parameter ", i + 1);
        return params.get_array()[i];
    };

    auto strParam = [&](size_t i) -> std::string {
        const auto &v = param(i);
        if (!v.is_string()) throw herr("parameter ", i + 1, " must be a string");
        return v.get_string();
    };

    auto targetTenant = [&](size_t i){
        auto t = lookupTenant(strParam(i));
        if (!admin && t->pubkey != signer) throw Forbidden("you can only manage your own relay");
        return t;
    };

    if (method == "supportedmethods") {
        if (!admin) {
            tao::json::value output = tao::json::empty_array;
            for (const auto &m : ownerMethods) output.emplace_back(m);
            return output;
        }
        return tao::json::value::array({ "supportedmethods", "whoami", "listtenants", "addtenant", "removetenant", "gettenant", "updatetenant", "recomputetrust", "connectsigner", "nostrconnect", "removesigner", "harveststatus" });
    } else if (method == "whoami") {
        auto own = ownTenant(signer);
        tao::json::value output = tao::json::value({
            { "pubkey", to_hex(signer.sv()) },
            { "isAdmin", admin },
            { "tenant", own ? tao::json::value(own->slug) : tao::json::value(tao::json::null) },
        });
        if (own) output["ownerLimits"] = ownerLimitsJson();
        return output;
    } else if (method == "listtenants") {
        tao::json::value output = tao::json::empty_array;
        for (const auto &t : TenantRegistry::get()->tenants) {
            if (admin || t->pubkey == signer) output.emplace_back(tenantSummaryJson(*t));
        }
        return output;
    } else if (method == "addtenant") {
        auto pubkey = parsePubkey(strParam(0));
        auto slug = strParam(1);

        uint64_t tenantId;
        {
            auto txn = env.txn_rw();
            tenantId = addTenant(txn, pubkey, slug);
            txn.commit();
        }

        LI << "Banyan: admin " << to_hex(signer.sv()) << " added " << slug << " (" << toNpub(pubkey) << ")";

        TenantRegistry::reload();
        requestRecompute(tenantId);
        harvesterWake();

        auto t = TenantRegistry::get()->findById(tenantId);
        if (!t) throw herr("tenant disappeared");
        return tenantSummaryJson(*t);
    } else if (method == "removetenant") {
        auto t = lookupTenant(strParam(0));

        {
            auto txn = env.txn_rw();
            removeTenant(txn, t->id);
            txn.commit();
        }

        LI << "Banyan: admin " << to_hex(signer.sv()) << " removed " << t->slug;

        TenantRegistry::reload();
        harvesterWake();
        return true;
    } else if (method == "gettenant") {
        return tenantDetailJson(*targetTenant(0));
    } else if (method == "updatetenant") {
        auto t = targetTenant(0);
        const auto &patch = param(1);
        if (!patch.is_object()) throw herr("parameter 2 must be an object");
        if (!admin) checkOwnerPatch(patch);

        {
            auto txn = env.txn_rw();
            updateTenant(txn, t->id, patch);
            txn.commit();
        }

        TenantRegistry::reload();
        if (patchAffectsTrust(patch)) requestRecompute(t->id);
        harvesterWake();

        auto updated = TenantRegistry::get()->findById(t->id);
        if (!updated) throw herr("tenant disappeared");
        return tenantDetailJson(*updated);
    } else if (method == "recomputetrust") {
        requestRecompute(targetTenant(0)->id);
        return true;
    } else if (method == "connectsigner" || method == "nostrconnect" || method == "removesigner") {
        auto t = targetTenant(0);
        if (method != "removesigner" && !cfg().banyan__signer__enabled) throw herr("remote signers are disabled on this server");

        {
            auto txn = env.txn_rw();
            if (method == "connectsigner") setBunkerSigner(txn, t->id, parseBunkerUrl(strParam(1)));
            else if (method == "nostrconnect") startNostrConnect(txn, t->id);
            else removeSigner(txn, t->id);
            txn.commit();
        }

        signersChanged();

        auto txn = env.txn_ro();
        return signerJson(txn, t->id);
    } else if (method == "harveststatus") {
        return harvesterStatus();
    }

    throw herr("unknown method: ", method);
}

HttpReply handleAdminRpc(const HttpRequestInfo &req) {
    auto reply = [](int status, tao::json::value v){
        HttpReply r;
        r.status = status;
        r.body = tao::json::to_string(v);
        return r;
    };

    auto error = [&](int status, std::string_view msg){
        return reply(status, tao::json::value({ { "error", std::string(msg) } }));
    };

    Bytes32 signer;

    try {
        std::string host = req.host;
        if (cfg().relay__auth__serviceUrl.size()) host = parseRelayUrl(cfg().relay__auth__serviceUrl).host;
        signer = verifyNip98(req.authorization, "POST", host, req.path, req.body);
    } catch (std::exception &e) {
        return error(401, e.what());
    }

    std::string method;
    tao::json::value params = tao::json::empty_array;

    try {
        auto body = tao::json::from_string(req.body);
        method = body.at("method").get_string();
        if (auto *p = body.find("params")) params = *p;
        if (!params.is_array()) throw herr("params must be an array");
    } catch (std::exception &e) {
        return error(400, std::string("invalid request: ") + e.what());
    }

    bool admin = isAdmin(signer);

    if (!admin && method != "whoami" && method != "supportedmethods") {
        bool ownerMethod = std::find(ownerMethods.begin(), ownerMethods.end(), method) != ownerMethods.end();
        if (!ownerMethod || !ownTenant(signer)) return error(403, "this pubkey is not an admin of this relay");
    }

    try {
        return reply(200, tao::json::value({ { "result", dispatchRpc(method, params, signer, admin) } }));
    } catch (Forbidden &e) {
        return error(403, e.what());
    } catch (std::exception &e) {
        return error(200, e.what());
    }
}


HttpReply tenantLandingPage(const TenantView &tenant, const std::string &host) {
    std::string relayUrl = tenantRelayUrl(tenant);
    if (relayUrl.empty()) relayUrl = "wss://" + host + "/" + tenant.slug;

    std::string html = R"(<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>)" + htmlEscape(tenant.slug) + R"( on Banyan</title>
<style>
:root { --bg: #f7f5ef; --fg: #1f2a1f; --muted: #5b665b; --accent: #2f6b3a; --card: #ffffff; }
@media (prefers-color-scheme: dark) { :root { --bg: #141a15; --fg: #e6ece6; --muted: #9aa69a; --accent: #7cc48a; --card: #1d251e; } }
body { margin: 0; background: var(--bg); color: var(--fg); font: 16px/1.5 system-ui, sans-serif; }
main { max-width: 640px; margin: 0 auto; padding: 48px 16px; }
h1 { font-size: 1.6rem; margin: 0 0 8px; }
p { color: var(--muted); }
a { color: var(--accent); }
code { display: block; background: var(--card); padding: 12px; border-radius: 8px; color: var(--accent); overflow-wrap: anywhere; }
</style></head><body><main>
<h1>)" + htmlEscape(tenant.slug) + R"(</h1>
<p>Banyan relay of <span style="overflow-wrap:anywhere">)" + htmlEscape(tenant.npub) + R"(</span>. It serves the notes of their trust universe: )"
        + std::to_string(tenant.universe.size()) + R"( people.</p>
<p>Add this relay to your Nostr client:</p>
<code>)" + htmlEscape(relayUrl) + R"(</code>
)" + (cfg().banyan__owners__enabled ? R"(<p>Is this your relay? <a href="/admin">Manage it</a> with your Nostr key.</p>
)" : "") + R"(</main></body></html>
)";

    HttpReply r;
    r.contentType = "text/html; charset=utf-8";
    r.body = std::move(html);
    return r;
}


}
