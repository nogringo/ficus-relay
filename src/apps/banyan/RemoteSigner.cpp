#include <atomic>
#include <cctype>
#include <mutex>

#include <secp256k1.h>
#include <hoytech/hex.h>
#include <hoytech/time.h>

#include "RemoteSigner.h"
#include "Harvester.h"
#include "Tenants.h"
#include "events.h"


namespace banyan {


static const uint64_t requestTimeoutSeconds = 60;
static const uint64_t retrySeconds = 300;
static const char *requestedPerms = "sign_event:22242";

static std::atomic<uint64_t> configVersion = 1;
static std::mutex statusMutex;
static flat_hash_map<uint64_t, tao::json::value> liveStatus;


static std::string percentDecode(std::string_view s) {
    std::string output;

    for (size_t i = 0; i < s.size(); i++) {
        if (s[i] == '%' && i + 2 < s.size() && isxdigit((unsigned char)s[i + 1]) && isxdigit((unsigned char)s[i + 2])) {
            output += (char)std::stoi(std::string(s.substr(i + 1, 2)), nullptr, 16);
            i += 2;
        } else if (s[i] == '+') {
            output += ' ';
        } else {
            output += s[i];
        }
    }

    return output;
}

static std::string percentEncode(std::string_view s) {
    static const char *hexDigits = "0123456789ABCDEF";
    std::string output;

    for (unsigned char c : s) {
        if (isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') {
            output += (char)c;
        } else {
            output += '%';
            output += hexDigits[c >> 4];
            output += hexDigits[c & 15];
        }
    }

    return output;
}

static std::vector<std::string> splitRelays(std::string_view commaSeparated) {
    std::vector<std::string> output;
    size_t pos = 0;

    while (pos < commaSeparated.size()) {
        auto end = commaSeparated.find_first_of(", \t\n", pos);
        if (end == std::string_view::npos) end = commaSeparated.size();
        auto url = normalizeHarvestUrl(commaSeparated.substr(pos, end - pos));
        pos = end + 1;
        if (url.size() && std::find(output.begin(), output.end(), url) == output.end()) output.push_back(url);
    }

    return output;
}

static std::string joinRelays(const std::vector<std::string> &relays) {
    std::string output;
    for (const auto &r : relays) {
        if (output.size()) output += ",";
        output += r;
    }
    return output;
}


BunkerUrl parseBunkerUrl(std::string_view url) {
    while (url.size() && isspace((unsigned char)url.front())) url.remove_prefix(1);
    while (url.size() && isspace((unsigned char)url.back())) url.remove_suffix(1);

    if (!url.starts_with("bunker://")) throw herr("expected a bunker:// URL");
    url.remove_prefix(9);

    auto q = url.find('?');
    std::string pubkeyHex(url.substr(0, q));
    std::transform(pubkeyHex.begin(), pubkeyHex.end(), pubkeyHex.begin(), [](unsigned char c){ return std::tolower(c); });
    if (pubkeyHex.size() != 64) throw herr("bunker URL must start with the signer's hex pubkey");

    BunkerUrl output;

    try {
        output.signerPubkey = from_hex(pubkeyHex);
    } catch (std::exception &) {
        throw herr("bunker URL must start with the signer's hex pubkey");
    }

    std::string_view query = q == std::string_view::npos ? "" : url.substr(q + 1);

    while (query.size()) {
        auto amp = query.find('&');
        auto param = query.substr(0, amp);
        query = amp == std::string_view::npos ? "" : query.substr(amp + 1);

        auto eq = param.find('=');
        if (eq == std::string_view::npos) continue;
        auto key = param.substr(0, eq);
        auto value = percentDecode(param.substr(eq + 1));

        if (key == "relay") {
            auto relay = normalizeHarvestUrl(value);
            if (relay.size() && std::find(output.relays.begin(), output.relays.end(), relay) == output.relays.end()) output.relays.push_back(relay);
        } else if (key == "secret") {
            output.secret = value;
        }
    }

    if (output.relays.empty()) throw herr("bunker URL has no usable relay");
    if (output.relays.size() > 8) output.relays.resize(8);

    return output;
}

void setBunkerSigner(lmdb::txn &txn, uint64_t tenantId, const BunkerUrl &bunker) {
    auto client = KeyPair::generate();
    env.delete_TenantSigner(txn, tenantId);
    env.insert_TenantSigner(txn, tenantId, client.secretKey, bunker.signerPubkey, joinRelays(bunker.relays), bunker.secret, hoytech::curr_time_s(), 0);
}

void startNostrConnect(lmdb::txn &txn, uint64_t tenantId) {
    auto relays = splitRelays(cfg().banyan__signer__relays);
    if (relays.empty()) throw herr("banyan.signer.relays has no usable relay");

    auto client = KeyPair::generate();
    env.delete_TenantSigner(txn, tenantId);
    env.insert_TenantSigner(txn, tenantId, client.secretKey, "", joinRelays(relays), to_hex(randomBytes(16)), hoytech::curr_time_s(), 0);
}

void removeSigner(lmdb::txn &txn, uint64_t tenantId) {
    env.delete_TenantSigner(txn, tenantId);
}

tao::json::value signerJson(lmdb::txn &txn, uint64_t tenantId) {
    auto row = env.lookup_TenantSigner(txn, tenantId);
    if (!row) return tao::json::null;

    auto client = KeyPair::fromSecret(row->clientSecretKey());
    auto relays = splitRelays(row->relays());

    tao::json::value relaysJson = tao::json::empty_array;
    for (const auto &r : relays) relaysJson.emplace_back(r);

    tao::json::value output = tao::json::value({
        { "state", row->connectedAt() ? "ready" : row->signerPubkey().empty() ? "waiting" : "connecting" },
        { "signerPubkey", row->signerPubkey().size() ? tao::json::value(to_hex(row->signerPubkey())) : tao::json::value(tao::json::null) },
        { "relays", std::move(relaysJson) },
        { "connectedAt", row->connectedAt() },
        { "lastError", tao::json::null },
        { "authUrl", tao::json::null },
    });

    if (row->signerPubkey().empty()) {
        std::string url = "nostrconnect://" + to_hex(client.pubkey) + "?";
        for (const auto &r : relays) url += "relay=" + percentEncode(r) + "&";
        url += "secret=" + percentEncode(row->secret()) + "&perms=" + percentEncode(requestedPerms) + "&name=Banyan";
        output["nostrconnect"] = url;
    }

    {
        std::lock_guard<std::mutex> guard(statusMutex);
        if (auto it = liveStatus.find(tenantId); it != liveStatus.end()) {
            for (const auto &[k, v] : it->second.get_object()) output[k] = v;
        }
    }

    return output;
}

void signersChanged() {
    configVersion++;
    harvesterWake();
}

uint64_t signersVersion() {
    return configVersion;
}


static secp256k1_context *verifyCtx() {
    static secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);
    return ctx;
}

static std::string_view stateName(SignerState s) {
    switch (s) {
        case SignerState::Waiting: return "waiting";
        case SignerState::Connecting: return "connecting";
        case SignerState::Verifying: return "verifying";
        case SignerState::Ready: return "ready";
        case SignerState::Failed: return "failed";
    }
    return "?";
}


void RemoteSigners::load() {
    loadedVersion = signersVersion();
    loadedAt = hoytech::curr_time_s();

    std::map<uint64_t, Session> loaded;
    auto txn = env.txn_ro();

    env.foreach_TenantSigner(txn, [&](auto &row){
        auto tenant = env.lookup_Tenant(txn, row.primaryKeyId);
        if (!tenant) return true;

        try {
            Session s;
            s.tenantId = row.primaryKeyId;
            s.owner = Bytes32(tenant->pubkey());
            s.client = KeyPair::fromSecret(row.clientSecretKey());
            s.signerPubkey = std::string(row.signerPubkey());
            s.relays = splitRelays(row.relays());
            s.secret = std::string(row.secret());
            s.connectedAt = row.connectedAt();
            s.createdAt = row.createdAt();

            // Same configuration: keep the session and its requests in flight
            if (auto it = sessions.find(s.tenantId); it != sessions.end() && it->second.client.pubkey == s.client.pubkey) {
                loaded[s.tenantId] = std::move(it->second);
                return true;
            }

            if (s.signerPubkey.size()) s.conversationKey = nip44ConversationKey(s.client.secretKey, s.signerPubkey);
            s.needsConnect = s.signerPubkey.size() && !s.connectedAt;
            s.state = s.connectedAt ? SignerState::Ready : s.signerPubkey.empty() ? SignerState::Waiting : SignerState::Connecting;
            loaded[s.tenantId] = std::move(s);
        } catch (std::exception &e) {
            LE << "Banyan: invalid remote signer for tenant " << row.primaryKeyId << ": " << e.what();
        }

        return true;
    });

    for (auto &[id, s] : sessions) {
        if (loaded.contains(id)) continue;
        for (auto &[reqId, p] : s.pending) p.cb(false, "remote signer removed");
    }

    sessions = std::move(loaded);
    publishStatus();
}

std::map<std::string, std::string> RemoteSigners::subscriptions() const {
    std::map<std::string, std::vector<std::string>> clientsByRelay;

    for (const auto &[id, s] : sessions) {
        for (const auto &url : s.relays) clientsByRelay[url].push_back(to_hex(s.client.pubkey));
    }

    std::map<std::string, std::string> output;
    uint64_t since = loadedAt > 60 ? loadedAt - 60 : 0;

    for (auto &[url, clients] : clientsByRelay) {
        tao::json::value p = tao::json::empty_array;
        for (const auto &c : clients) p.emplace_back(c);

        output[url] = tao::json::to_string(tao::json::value::array({
            "REQ", "nip46",
            tao::json::value({ { "kinds", tao::json::value::array({ uint64_t(24133) }) }, { "#p", p }, { "since", since } }),
        }));
    }

    return output;
}

bool RemoteSigners::request(Session &s, const std::string &method, tao::json::value params, std::function<void(bool, const std::string &)> cb) {
    if (s.signerPubkey.empty()) return false;

    std::string id = to_hex(randomBytes(8));
    auto body = tao::json::to_string(tao::json::value({ { "id", id }, { "method", method }, { "params", std::move(params) } }));

    auto ev = s.client.sign(24133, tao::json::value::array({ tao::json::value::array({ "p", to_hex(s.signerPubkey) }) }), nip44Encrypt(body, s.conversationKey));
    auto msg = tao::json::to_string(tao::json::value::array({ "EVENT", ev }));

    bool sent = false;
    for (const auto &url : s.relays) {
        if (sendToRelay(url, msg)) sent = true;
    }
    if (!sent) return false;

    s.pending[id] = Pending{ method, hoytech::curr_time_s(), std::move(cb) };
    return true;
}

void RemoteSigners::fail(Session &s, const std::string &error, uint64_t retryInSeconds) {
    s.state = SignerState::Failed;
    s.lastError = error;
    s.nextAttemptAt = retryInSeconds ? hoytech::curr_time_s() + retryInSeconds : MAX_U64;
    LI << "Banyan: remote signer of " << toNpub(s.owner) << ": " << error;
    publishStatus();
}

void RemoteSigners::persistConnected(const Session &s) {
    auto txn = env.txn_rw();
    auto row = env.lookup_TenantSigner(txn, s.tenantId);

    if (row && row->clientSecretKey() == s.client.secretKey) {
        defaultDb::environment::Updates_TenantSigner upd;
        upd.signerPubkey = s.signerPubkey;
        upd.connectedAt = s.connectedAt;
        env.update_TenantSigner(txn, *row, upd);
        txn.commit();
    }
}

void RemoteSigners::connectSession(Session &s) {
    uint64_t tenantId = s.tenantId;

    request(s, "connect", tao::json::value::array({ to_hex(s.signerPubkey), s.secret, requestedPerms }), [this, tenantId](bool ok, const std::string &result){
        auto it = sessions.find(tenantId);
        if (it == sessions.end()) return;
        auto &s = it->second;

        if (!ok) return fail(s, "the signer refused to connect: " + result, retrySeconds);
        if (result != "ack" && result != s.secret) return fail(s, "unexpected answer to connect: " + result, retrySeconds);

        s.needsConnect = false;
        s.state = SignerState::Verifying;
        verifySession(s);
    });
}

void RemoteSigners::verifySession(Session &s) {
    uint64_t tenantId = s.tenantId;

    request(s, "get_public_key", tao::json::empty_array, [this, tenantId](bool ok, const std::string &result){
        auto it = sessions.find(tenantId);
        if (it == sessions.end()) return;
        auto &s = it->second;

        if (!ok) return fail(s, "get_public_key failed: " + result, retrySeconds);

        std::string lower = result;
        std::transform(lower.begin(), lower.end(), lower.begin(), [](unsigned char c){ return std::tolower(c); });
        if (lower != to_hex(s.owner.sv())) return fail(s, "this signer holds another key than " + toNpub(s.owner), 0);

        s.state = SignerState::Ready;
        s.connectedAt = hoytech::curr_time_s();
        s.lastError.clear();
        s.authUrl.clear();
        LI << "Banyan: remote signer of " << toNpub(s.owner) << " is connected";

        try {
            persistConnected(s);
        } catch (std::exception &e) {
            LE << "Banyan: unable to store remote signer state: " << e.what();
        }

        publishStatus();
        harvesterWake();
    });
}

void RemoteSigners::onEvent(const std::string &url, const tao::json::value &evJson) {
    std::string packedStr, jsonStr;

    try {
        parseAndVerifyEvent(evJson, verifyCtx(), true, false, packedStr, jsonStr);
    } catch (std::exception &) {
        return;
    }

    PackedEventView packed(packedStr);
    if (packed.kind() != 24133) return;

    std::string author(packed.pubkey());
    const auto &content = evJson.at("content").get_string();

    for (auto &[tenantId, s] : sessions) {
        bool forUs = false;
        packed.foreachTag([&](char tagName, std::string_view tagVal){
            if (tagName == 'p' && tagVal == s.client.pubkey) forUs = true;
            return !forUs;
        });
        if (!forUs) continue;

        if (s.signerPubkey.size() && author != s.signerPubkey) continue;

        tao::json::value body;
        std::string conversationKey = s.signerPubkey.size() ? s.conversationKey : nip44ConversationKey(s.client.secretKey, author);

        try {
            body = tao::json::from_string(nip44Decrypt(content, conversationKey));
        } catch (std::exception &) {
            if (content.find("?iv=") != std::string::npos) s.lastError = "the signer answered with NIP-04 encryption, which is not supported";
            continue;
        }

        if (!body.is_object()) continue;

        auto str = [&](const char *k) -> std::string {
            auto *v = body.find(k);
            return v && v->is_string() ? v->get_string() : "";
        };

        auto id = str("id"), result = str("result"), error = str("error");

        // nostrconnect://: the signer opens the session by answering with our secret
        if (s.signerPubkey.empty()) {
            if (result != s.secret) continue;

            s.signerPubkey = author;
            s.conversationKey = conversationKey;
            s.state = SignerState::Verifying;
            verifySession(s);
            publishStatus();
            continue;
        }

        auto pit = s.pending.find(id);
        if (pit == s.pending.end()) continue;

        if (result == "auth_url") {
            s.authUrl = error;
            publishStatus();
            continue;
        }

        auto cb = std::move(pit->second.cb);
        s.pending.erase(pit);

        if (error.size()) cb(false, error);
        else cb(true, result);
    }
}

void RemoteSigners::tick(uint64_t now) {
    if (signersVersion() != loadedVersion) load();

    for (auto &[tenantId, s] : sessions) {
        std::vector<std::string> expired;
        for (const auto &[id, p] : s.pending) {
            if (now > p.sentAt + requestTimeoutSeconds) expired.push_back(id);
        }

        for (const auto &id : expired) {
            auto cb = std::move(s.pending[id].cb);
            s.pending.erase(id);
            cb(false, "no answer from the remote signer");
        }

        if (s.state == SignerState::Failed && now >= s.nextAttemptAt) {
            if (s.connectedAt) s.state = SignerState::Ready;
            else if (s.signerPubkey.empty()) s.state = SignerState::Waiting;
            else s.state = s.needsConnect ? SignerState::Connecting : SignerState::Verifying;
        }

        if (s.pending.size()) continue;

        if (s.state == SignerState::Connecting) connectSession(s);
        else if (s.state == SignerState::Verifying) verifySession(s);
    }
}

bool RemoteSigners::ready(uint64_t tenantId) const {
    auto it = sessions.find(tenantId);
    return it != sessions.end() && it->second.connectedAt && it->second.signerPubkey.size();
}

std::vector<uint64_t> RemoteSigners::readyTenants() const {
    std::vector<uint64_t> output;
    for (const auto &[id, s] : sessions) {
        if (ready(id)) output.push_back(id);
    }
    return output;
}

void RemoteSigners::signAuth(uint64_t tenantId, const std::string &relayUrl, const std::string &challenge, Done done) {
    auto it = sessions.find(tenantId);
    if (it == sessions.end() || !ready(tenantId)) return done(false, tao::json::null, "remote signer not connected");
    auto &s = it->second;

    tao::json::value tags = tao::json::value::array({
        tao::json::value::array({ "relay", relayUrl }),
        tao::json::value::array({ "challenge", challenge }),
    });

    auto unsignedEvent = tao::json::value({
        { "kind", uint64_t(22242) },
        { "content", "" },
        { "tags", tags },
        { "created_at", hoytech::curr_time_s() },
    });

    Bytes32 owner = s.owner;

    bool sent = request(s, "sign_event", tao::json::value::array({ tao::json::to_string(unsignedEvent) }), [this, tenantId, owner, challenge, done](bool ok, const std::string &result){
        if (!ok) {
            if (auto it = sessions.find(tenantId); it != sessions.end()) {
                it->second.lastError = "sign_event refused: " + result;
                publishStatus();
            }
            return done(false, tao::json::null, result);
        }

        try {
            auto ev = tao::json::from_string(result);
            std::string packedStr, jsonStr;
            parseAndVerifyEvent(ev, verifyCtx(), true, false, packedStr, jsonStr);
            PackedEventView packed(packedStr);

            if (packed.kind() != 22242 || packed.pubkey() != owner.sv()) throw herr("signed the wrong event");

            bool challengeOk = false;
            for (const auto &tag : ev.at("tags").get_array()) {
                const auto &arr = tag.get_array();
                if (arr.size() >= 2 && arr[0] == "challenge" && arr[1] == challenge) challengeOk = true;
            }
            if (!challengeOk) throw herr("signed another challenge");

            done(true, ev, "");
        } catch (std::exception &e) {
            done(false, tao::json::null, std::string("invalid signature from the remote signer: ") + e.what());
        }
    });

    if (!sent) done(false, tao::json::null, "no signer relay connected");
}

void RemoteSigners::publishStatus() const {
    std::lock_guard<std::mutex> guard(statusMutex);
    liveStatus.clear();

    for (const auto &[id, s] : sessions) {
        liveStatus[id] = tao::json::value({
            { "state", std::string(stateName(s.state)) },
            { "lastError", s.lastError.size() ? tao::json::value(s.lastError) : tao::json::value(tao::json::null) },
            { "authUrl", s.authUrl.size() ? tao::json::value(s.authUrl) : tao::json::value(tao::json::null) },
        });
    }
}


}
