#include <atomic>
#include <cctype>
#include <cmath>
#include <mutex>
#include <thread>

#include <curl/curl.h>
#include <hoytech/hex.h>
#include <hoytech/time.h>

#include "Zaps.h"
#include "Net.h"
#include "Harvester.h"
#include "TrustEngine.h"
#include "Bech32Utils.h"
#include "DBQuery.h"
#include "Decompressor.h"
#include "events.h"


namespace banyan {


static const uint64_t keysRefreshSeconds = 7 * 86400;
static const uint64_t noKeysRefreshSeconds = 86400;
static const size_t maxKeysPerRecipient = 8;
static const size_t maxResponseBytes = 64 * 1024;
static const size_t maxUnresolved = 50'000;


std::optional<uint64_t> bolt11AmountMsats(std::string_view invoice) {
    std::string s(invoice);
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c){ return std::tolower(c); });
    if (s.starts_with("lightning:")) s = s.substr(10);

    auto sep = s.rfind('1');
    if (!s.starts_with("ln") || sep == std::string::npos || sep < 2) return std::nullopt;

    std::string_view hrp = std::string_view(s).substr(2, sep - 2);
    while (hrp.size() && hrp.front() >= 'a' && hrp.front() <= 'z') hrp.remove_prefix(1); // currency: bc, tb, tbs, bcrt
    if (hrp.empty()) return std::nullopt;

    char multiplier = 0;
    if (hrp.back() >= 'a' && hrp.back() <= 'z') {
        multiplier = hrp.back();
        hrp.remove_suffix(1);
    }

    if (hrp.empty() || hrp.size() > 15) return std::nullopt;
    uint64_t n = 0;
    for (char c : hrp) {
        if (c < '0' || c > '9') return std::nullopt;
        n = n * 10 + uint64_t(c - '0');
    }

    uint64_t perUnit;
    switch (multiplier) {
        case 0: perUnit = 100'000'000'000ULL; break;
        case 'm': perUnit = 100'000'000ULL; break;
        case 'u': perUnit = 100'000ULL; break;
        case 'n': perUnit = 100ULL; break;
        case 'p':
            if (n % 10) return std::nullopt;
            return n / 10;
        default: return std::nullopt;
    }

    uint64_t msats;
    if (__builtin_mul_overflow(n, perUnit, &msats)) return std::nullopt;
    return msats;
}

double zapUnits(uint64_t msats) {
    uint64_t reference = cfg().banyan__trust__zapReferenceSats;
    if (reference == 0) return 1.0;
    return std::log2(1.0 + ((double)msats / 1000.0) / (double)reference);
}


static std::vector<Bytes32> splitKeys(std::string_view packed) {
    std::vector<Bytes32> output;
    for (size_t i = 0; i + 32 <= packed.size(); i += 32) output.emplace_back(packed.substr(i, 32));
    return output;
}

ZapperCheck checkZapper(lmdb::txn &txn, const Bytes32 &recipient, const Bytes32 &receiptSigner) {
    auto row = env.lookup_ZapperKey__pubkey(txn, recipient.sv());
    if (!row) return ZapperCheck::Unknown;

    auto keys = splitKeys(row->nostrPubkeys());
    if (std::find(keys.begin(), keys.end(), receiptSigner) != keys.end()) return ZapperCheck::Valid;

    uint64_t refresh = keys.empty() ? noKeysRefreshSeconds : keysRefreshSeconds;
    return row->checkedAt() + refresh > hoytech::curr_time_s() ? ZapperCheck::Invalid : ZapperCheck::Unknown;
}


static std::mutex unresolvedMutex;
static flat_hash_map<Bytes32, flat_hash_set<Bytes32>> unresolved;

void noteUnresolvedZapper(const Bytes32 &recipient, const Bytes32 &seed) {
    std::lock_guard<std::mutex> guard(unresolvedMutex);
    if (unresolved.size() >= maxUnresolved && !unresolved.contains(recipient)) return;
    unresolved[recipient].insert(seed);
}

flat_hash_map<Bytes32, flat_hash_set<Bytes32>> takeUnresolvedZappers() {
    std::lock_guard<std::mutex> guard(unresolvedMutex);
    return std::move(unresolved);
}


static std::string lowercase(std::string_view s) {
    std::string output(s);
    std::transform(output.begin(), output.end(), output.begin(), [](unsigned char c){ return std::tolower(c); });
    return output;
}

static std::string trim(std::string_view s) {
    while (s.size() && isspace((unsigned char)s.front())) s.remove_prefix(1);
    while (s.size() && isspace((unsigned char)s.back())) s.remove_suffix(1);
    return std::string(s);
}

// LUD-16: name@domain is served at https://domain/.well-known/lnurlp/name
static std::string lightningAddressUrl(std::string_view address) {
    auto addr = lowercase(trim(address));
    auto at = addr.find('@');
    if (at == std::string::npos || at == 0 || at + 1 >= addr.size()) return "";

    std::string name = addr.substr(0, at), domain = addr.substr(at + 1);

    for (char c : name) {
        if (!isalnum((unsigned char)c) && c != '-' && c != '_' && c != '.' && c != '+') return "";
    }
    for (char c : domain) {
        if (!isalnum((unsigned char)c) && c != '-' && c != '.' && c != ':') return "";
    }

    return "https://" + domain + "/.well-known/lnurlp/" + name;
}

// LUD-01: bech32-encoded URL
static std::string lnurlUrl(std::string_view lnurl) {
    auto s = lowercase(trim(lnurl));
    if (s.starts_with("lightning:")) s = s.substr(10);
    if (!s.starts_with("lnurl1")) return "";

    try {
        auto url = decodeBech32(s);
        if (url.starts_with("https://") || url.starts_with("http://")) return url;
    } catch (std::exception &) {
    }

    return "";
}

// lud16 first, as most clients do when zapping
static std::string payUrlFromProfile(std::string_view profileContent) {
    try {
        auto content = tao::json::from_string(profileContent);
        if (!content.is_object()) return "";

        auto str = [&](const char *k) -> std::string {
            auto *v = content.find(k);
            return v && v->is_string() ? v->get_string() : "";
        };

        auto lud16 = str("lud16"), lud06 = str("lud06");

        if (auto url = lightningAddressUrl(lud16); url.size()) return url;
        if (auto url = lnurlUrl(lud06); url.size()) return url;
        if (auto url = lightningAddressUrl(lud06); url.size()) return url; // a lightning address put in the wrong field
    } catch (std::exception &) {
    }

    return "";
}


static void initCurl() {
    static std::once_flag once;
    std::call_once(once, []{ curl_global_init(CURL_GLOBAL_DEFAULT); });
}

static size_t curlWrite(char *ptr, size_t size, size_t nmemb, void *userdata) {
    auto *body = (std::string*)userdata;
    size_t n = size * nmemb;
    if (body->size() + n > maxResponseBytes) return 0;
    body->append(ptr, n);
    return n;
}

// Checked on the address curl is about to connect to, redirects included, so DNS rebinding can't reach a private network
static curl_socket_t curlOpenSocket(void *clientp, curlsocktype purpose, struct curl_sockaddr *address) {
    bool allowPrivate = *(bool*)clientp;
    if (purpose == CURLSOCKTYPE_IPCXN && !allowPrivate && isPrivateAddress(&address->addr)) return CURL_SOCKET_BAD;
    return socket(address->family, address->socktype, address->protocol);
}

static std::optional<std::string> httpGet(const std::string &url, std::string &error) {
    initCurl();

    CURL *c = curl_easy_init();
    if (!c) {
        error = "curl_easy_init failed";
        return std::nullopt;
    }

    bool allowPrivate = cfg().banyan__harvester__allowPrivateAddresses;
    // LUD-01 allows plain http for onion services only, which are private hosts here
    const char *protocols = allowPrivate ? "https,http" : "https";

    std::string body;
    curl_easy_setopt(c, CURLOPT_URL, url.c_str());
    curl_easy_setopt(c, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(c, CURLOPT_MAXREDIRS, 3L);
    curl_easy_setopt(c, CURLOPT_CONNECTTIMEOUT, 5L);
    curl_easy_setopt(c, CURLOPT_TIMEOUT, 10L);
    curl_easy_setopt(c, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(c, CURLOPT_USERAGENT, "ficus-relay");
    curl_easy_setopt(c, CURLOPT_WRITEFUNCTION, curlWrite);
    curl_easy_setopt(c, CURLOPT_WRITEDATA, &body);
    curl_easy_setopt(c, CURLOPT_OPENSOCKETFUNCTION, curlOpenSocket);
    curl_easy_setopt(c, CURLOPT_OPENSOCKETDATA, &allowPrivate);
#if LIBCURL_VERSION_NUM >= 0x075500
    curl_easy_setopt(c, CURLOPT_PROTOCOLS_STR, protocols);
    curl_easy_setopt(c, CURLOPT_REDIR_PROTOCOLS_STR, protocols);
#else
    long protoMask = CURLPROTO_HTTPS | (allowPrivate ? CURLPROTO_HTTP : 0);
    curl_easy_setopt(c, CURLOPT_PROTOCOLS, protoMask);
    curl_easy_setopt(c, CURLOPT_REDIR_PROTOCOLS, protoMask);
#endif

    auto res = curl_easy_perform(c);
    long status = 0;
    curl_easy_getinfo(c, CURLINFO_RESPONSE_CODE, &status);
    curl_easy_cleanup(c);

    if (res != CURLE_OK) {
        error = curl_easy_strerror(res);
        return std::nullopt;
    }

    if (status != 200) {
        error = "HTTP " + std::to_string(status);
        return std::nullopt;
    }

    return body;
}


struct Lookup {
    Bytes32 recipient;
    std::string url;
    enum { Pending, NoProfile, NoLnurl, Answered, Failed } state = Pending;
    std::optional<Bytes32> nostrPubkey; // when Answered: nullopt if the server doesn't support zaps
};

static void fetchPayEndpoint(Lookup &l) {
    std::string error;
    auto body = httpGet(l.url, error);

    if (!body) {
        LI << "Banyan: LNURL of " << toNpub(l.recipient) << " (" << l.url << ") failed: " << error;
        l.state = Lookup::Failed;
        return;
    }

    try {
        auto json = tao::json::from_string(*body);
        if (!json.is_object()) throw herr("not an object");

        l.state = Lookup::Answered;

        auto *allows = json.find("allowsNostr");
        auto *pk = json.find("nostrPubkey");
        if (allows && allows->is_boolean() && allows->get_boolean() && pk && pk->is_string() && pk->get_string().size() == 64) {
            l.nostrPubkey = Bytes32(from_hex(lowercase(pk->get_string())));
        }
    } catch (std::exception &e) {
        LI << "Banyan: LNURL of " << toNpub(l.recipient) << " answered invalid JSON: " << e.what();
        l.state = Lookup::Failed;
    }
}

ZapperResolution resolveZapperKeys(const std::vector<Bytes32> &recipients) {
    ZapperResolution output;
    std::vector<Lookup> lookups;

    {
        auto txn = env.txn_ro();
        Decompressor decomp;

        for (const auto &pk : recipients) {
            Lookup l;
            l.recipient = pk;
            l.state = Lookup::NoProfile;

            foreachByFilter(txn, tao::json::value({
                { "authors", tao::json::value::array({ to_hex(pk.sv()) }) },
                { "kinds", tao::json::value::array({ uint64_t(0) }) },
                { "limit", uint64_t(1) },
            }), [&](uint64_t levId){
                try {
                    auto ev = tao::json::from_string(getEventJson(txn, decomp, levId));
                    l.url = payUrlFromProfile(ev.at("content").get_string());
                    l.state = l.url.empty() ? Lookup::NoLnurl : Lookup::Pending;
                } catch (std::exception &) {
                    l.state = Lookup::NoLnurl;
                }
            });

            lookups.push_back(std::move(l));
        }
    }

    std::atomic<size_t> next = 0;
    std::vector<std::thread> workers;

    for (size_t i = 0; i < std::min<size_t>(8, lookups.size()); i++) {
        workers.emplace_back([&]{
            while (1) {
                size_t idx = next++;
                if (idx >= lookups.size()) return;
                if (lookups[idx].state == Lookup::Pending) fetchPayEndpoint(lookups[idx]);
            }
        });
    }

    for (auto &w : workers) w.join();

    uint64_t now = hoytech::curr_time_s();
    auto txn = env.txn_rw();

    for (const auto &l : lookups) {
        if (l.state == Lookup::NoProfile) {
            output.missingProfiles.push_back(l.recipient);
            continue;
        }

        if (l.state == Lookup::Failed) {
            output.failed.push_back(l.recipient);
            continue;
        }

        auto row = env.lookup_ZapperKey__pubkey(txn, l.recipient.sv());
        auto keys = row ? splitKeys(row->nostrPubkeys()) : std::vector<Bytes32>{};
        bool changed = false;

        // Earlier keys stay valid: receipts signed before a change of wallet are still genuine
        if (l.nostrPubkey && std::find(keys.begin(), keys.end(), *l.nostrPubkey) == keys.end()) {
            keys.push_back(*l.nostrPubkey);
            if (keys.size() > maxKeysPerRecipient) keys.erase(keys.begin());
            changed = true;
        }

        std::string packed;
        for (const auto &k : keys) packed += k.sv();

        if (row) {
            defaultDb::environment::Updates_ZapperKey upd;
            upd.nostrPubkeys = packed;
            upd.lnurl = l.url;
            upd.checkedAt = now;
            env.update_ZapperKey(txn, *row, upd);
        } else {
            env.insert_ZapperKey(txn, l.recipient.sv(), packed, l.url, now);
        }

        if (changed) output.changed.push_back(l.recipient);
    }

    txn.commit();

    return output;
}


void runZapResolver() {
    setThreadName("BanyanZaps");

    struct Backoff {
        uint64_t nextAt = 0;
        uint64_t delay = 0;
    };

    flat_hash_map<Bytes32, flat_hash_set<Bytes32>> waiting;
    flat_hash_map<Bytes32, Backoff> backoff;

    auto retryLater = [&](const Bytes32 &pk, uint64_t firstDelay, uint64_t now){
        auto &b = backoff[pk];
        b.delay = b.delay ? std::min<uint64_t>(b.delay * 2, 86400) : firstDelay;
        b.nextAt = now + b.delay;
    };

    while (1) {
        std::this_thread::sleep_for(std::chrono::seconds(5));

        try {
            auto fresh = takeUnresolvedZappers();
            if (!cfg().banyan__trust__verifyZapReceipts) {
                waiting.clear();
                continue;
            }

            for (auto &[pk, seeds] : fresh) waiting[pk].insert(seeds.begin(), seeds.end());
            if (waiting.size() > maxUnresolved) waiting.clear();

            uint64_t now = hoytech::curr_time_s();
            std::vector<Bytes32> batch;

            for (const auto &[pk, seeds] : waiting) {
                if (auto it = backoff.find(pk); it != backoff.end() && it->second.nextAt > now) continue;
                batch.push_back(pk);
                if (batch.size() >= 64) break;
            }

            if (batch.empty()) continue;

            auto res = resolveZapperKeys(batch);

            std::vector<Bytes32> affected;
            for (const auto &pk : res.changed) {
                affected.push_back(pk);
                for (const auto &seed : waiting[pk]) affected.push_back(seed);
            }

            for (const auto &pk : res.missingProfiles) retryLater(pk, 120, now);
            for (const auto &pk : res.failed) retryLater(pk, 600, now);
            if (res.missingProfiles.size()) harvesterWantProfiles(res.missingProfiles);

            for (const auto &pk : batch) {
                bool retrying = backoff.contains(pk) && backoff[pk].nextAt > now;
                if (!retrying) {
                    waiting.erase(pk);
                    backoff.erase(pk);
                }
            }

            if (affected.size()) notifyEngagementChanged(affected);

            for (auto it = backoff.begin(); it != backoff.end(); ) {
                if (!waiting.contains(it->first) && it->second.nextAt + 86400 < now) backoff.erase(it++);
                else ++it;
            }
        } catch (std::exception &e) {
            LE << "Banyan zap resolver error: " << e.what();
        }
    }
}


}
