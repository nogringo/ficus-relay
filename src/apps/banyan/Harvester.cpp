#include <atomic>
#include <condition_variable>
#include <deque>
#include <map>
#include <mutex>
#include <thread>

#include <hoytech/time.h>
#include <hoytech/hex.h>

#include "Harvester.h"
#include "Net.h"
#include "PinnedHub.h"
#include "Crypto.h"
#include "RemoteSigner.h"
#include "TrustEngine.h"
#include "Tenants.h"
#include "WriterPipeline.h"
#include "DBQuery.h"
#include "Decompressor.h"
#include "events.h"
#include "filters.h"


namespace banyan {


static const std::vector<uint64_t> inboxKinds = { 1, 6, 7, 16, 1111, 9735, 9802, 30023 };
// Mentions worth delivering: p tags of follow lists, mute lists and the like are not mentions
static const std::vector<uint64_t> deliveredKinds = { 1, 6, 7, 16, 1111, 9802, 30023 };
static const uint64_t reqTimeoutSeconds = 60;
static const uint64_t maxPagesPerChain = 1000;
static const uint64_t maxFiltersPerLiveReq = 10;
static const uint64_t maxFutureSeconds = 900;

static const uint64_t authTimeoutSeconds = 30;
static const uint64_t ownerAuthTimeoutSeconds = 120;
static const uint64_t maxDeliveryOnlyRelays = 20;
static const uint64_t maxOutboxPerRelay = 1000;
static const uint64_t maxInflightDeliveries = 20;
static const uint64_t deliveryTimeoutSeconds = 30;
static const uint64_t deliveryIdleSeconds = 120;
static const uint64_t maxEventsDistributedPerTick = 2000;
static const uint64_t seenOnSeconds = 600;
static const size_t maxSeenOn = 200'000;

static const size_t maxOwnerRelays = 8;
static const size_t maxOutboxRelaysPerAuthor = 8;
static const size_t maxPublishQueue = 10'000;
static const uint64_t wantedProfileSeconds = 600;
static const size_t maxWantedProfiles = 5000;
// NIP-59 gift wraps are dated up to two days in the past
static const uint64_t giftWrapJitterSeconds = 2 * 86400 + 3600;


static std::atomic<bool> wakeRequested = true;
static std::atomic<bool> running = false;
static std::mutex statusMutex;
static tao::json::value statusJson = tao::json::value({ { "targets", 0 }, { "relays", tao::json::empty_array }, { "authPubkey", tao::json::null } });

void harvesterWake() {
    wakeRequested = true;
}

tao::json::value harvesterStatus() {
    std::lock_guard<std::mutex> guard(statusMutex);
    return statusJson;
}


static std::mutex wantedMutex;
static flat_hash_map<Bytes32, uint64_t> wantedProfiles;

void harvesterWantProfiles(const std::vector<Bytes32> &pubkeys) {
    {
        std::lock_guard<std::mutex> guard(wantedMutex);
        uint64_t now = hoytech::curr_time_s();
        for (const auto &pk : pubkeys) {
            if (wantedProfiles.size() >= maxWantedProfiles && !wantedProfiles.contains(pk)) break;
            wantedProfiles[pk] = now;
        }
    }
    wakeRequested = true;
}


struct Published {
    uint64_t tenantId;
    std::string packedStr;
    std::string jsonStr;
};

static std::mutex publishMutex;
static std::deque<Published> publishQueue;

void harvesterPublish(uint64_t tenantId, std::string packedStr, std::string jsonStr) {
    if (!running || !cfg().banyan__distributor__enabled || !cfg().banyan__distributor__publishToOutbox) return;

    std::lock_guard<std::mutex> guard(publishMutex);
    if (publishQueue.size() >= maxPublishQueue) publishQueue.pop_front();
    publishQueue.push_back(Published{ tenantId, std::move(packedStr), std::move(jsonStr) });
}


std::string normalizeHarvestUrl(std::string_view input) {
    std::string url(input);
    while (url.size() && isspace((unsigned char)url.back())) url.pop_back();
    while (url.size() && isspace((unsigned char)url.front())) url.erase(url.begin());

    std::string lower = url;
    std::transform(lower.begin(), lower.end(), lower.begin(), [](unsigned char c){ return std::tolower(c); });

    std::string scheme;
    if (lower.starts_with("wss://")) scheme = "wss://";
    else if (lower.starts_with("ws://")) scheme = "ws://";
    else return "";

    if (url.find_first_of(" \t\"'<>") != std::string::npos) return "";

    auto parts = parseRelayUrl(url);
    if (!cfg().banyan__harvester__allowPrivateAddresses && isPrivateHost(parts.host)) return "";

    std::string output = scheme + parts.host;
    if (parts.path.size()) output += "/" + parts.path;
    return output;
}

static std::vector<std::string> parseUrlList(std::string_view commaSeparated) {
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

static tao::json::value hexArray(const std::vector<Bytes32> &pks) {
    tao::json::value arr = tao::json::empty_array;
    for (const auto &pk : pks) arr.emplace_back(to_hex(pk.sv()));
    return arr;
}


// uWS resolves DNS and, on macOS, connects with blocking calls inside its event loop, so one dead
// relay would freeze the harvester. Hosts are checked here first, on worker threads.
struct Prober {
    struct Result {
        std::string key;
        ProbeOutcome outcome;
    };

    std::mutex mutex;
    std::condition_variable cv;
    std::deque<std::pair<std::string, std::string>> pending; // key, url
    std::vector<Result> results;

    Prober(size_t numWorkers) {
        for (size_t i = 0; i < numWorkers; i++) {
            std::thread([this]{
                setThreadName("BanyanProbe");
                while (1) {
                    std::pair<std::string, std::string> job;
                    {
                        std::unique_lock<std::mutex> lk(mutex);
                        cv.wait(lk, [&]{ return pending.size() > 0; });
                        job = std::move(pending.front());
                        pending.pop_front();
                    }

                    auto hp = splitHostPort(parseRelayUrl(job.second).host, job.second.starts_with("wss://"));
                    auto outcome = probeTcp(hp.host, hp.port, 5'000, cfg().banyan__harvester__allowPrivateAddresses);

                    std::lock_guard<std::mutex> guard(mutex);
                    results.push_back(Result{ std::move(job.first), std::move(outcome) });
                }
            }).detach();
        }
    }

    void submit(const std::string &key, const std::string &url) {
        {
            std::lock_guard<std::mutex> guard(mutex);
            pending.emplace_back(key, url);
        }
        cv.notify_one();
    }

    std::vector<Result> takeResults() {
        std::lock_guard<std::mutex> guard(mutex);
        return std::move(results);
    }
};


// Signs NIP-42 AUTH events. Stored in the database so other relays always see the same pubkey.
static KeyPair loadOrCreateHarvesterKey() {
    {
        auto txn = env.txn_ro();
        std::string found;
        env.foreach_HarvesterKey(txn, [&](auto &view){
            found = std::string(view.secretKey());
            return false;
        });

        try {
            if (found.size() == 32) return KeyPair::fromSecret(found);
        } catch (std::exception &) {
        }
    }

    auto key = KeyPair::generate();

    auto txn = env.txn_rw();
    std::vector<uint64_t> old;
    env.foreach_HarvesterKey(txn, [&](auto &view){
        old.push_back(view.primaryKeyId);
        return true;
    });
    for (auto id : old) env.delete_HarvesterKey(txn, id);
    env.insert_HarvesterKey(txn, key.secretKey);
    txn.commit();

    return key;
}


struct RelayList {
    bool found = false;
    std::vector<std::string> write;
    std::vector<std::string> read;
};

static RelayList loadRelayList(lmdb::txn &txn, Decompressor &decomp, const Bytes32 &pk, const std::function<bool(const std::string &)> &allowed) {
    RelayList output;

    tao::json::value filter = tao::json::value({
        { "authors", tao::json::value::array({ to_hex(pk.sv()) }) },
        { "kinds", tao::json::value::array({ uint64_t(10002) }) },
        { "limit", uint64_t(1) },
    });

    foreachByFilter(txn, filter, [&](uint64_t levId){
        try {
            auto ev = tao::json::from_string(getEventJson(txn, decomp, levId));
            output.found = true;

            for (const auto &tagj : ev.at("tags").get_array()) {
                const auto &tag = tagj.get_array();
                if (tag.size() < 2 || tag[0].get_string() != "r") continue;

                auto url = normalizeHarvestUrl(tag[1].get_string());
                if (url.empty() || !allowed(url)) continue;

                std::string marker = tag.size() >= 3 ? tag[2].get_string() : "";
                if (marker != "read" && std::find(output.write.begin(), output.write.end(), url) == output.write.end()) output.write.push_back(url);
                if (marker != "write" && std::find(output.read.begin(), output.read.end(), url) == output.read.end()) output.read.push_back(url);
            }
        } catch (std::exception &) {
        }
    });

    return output;
}

// NIP-17: where someone receives their gift wraps (kind 10050)
static std::vector<std::string> loadDmRelays(lmdb::txn &txn, Decompressor &decomp, const Bytes32 &pk, const std::function<bool(const std::string &)> &allowed) {
    std::vector<std::string> output;

    tao::json::value filter = tao::json::value({
        { "authors", tao::json::value::array({ to_hex(pk.sv()) }) },
        { "kinds", tao::json::value::array({ uint64_t(10050) }) },
        { "limit", uint64_t(1) },
    });

    foreachByFilter(txn, filter, [&](uint64_t levId){
        try {
            auto ev = tao::json::from_string(getEventJson(txn, decomp, levId));

            for (const auto &tagj : ev.at("tags").get_array()) {
                const auto &tag = tagj.get_array();
                if (tag.size() < 2 || tag[0].get_string() != "relay") continue;

                auto url = normalizeHarvestUrl(tag[1].get_string());
                if (url.size() && allowed(url) && std::find(output.begin(), output.end(), url) == output.end()) output.push_back(url);
            }
        } catch (std::exception &) {
        }
    });

    return output;
}


struct Assignment {
    std::vector<Bytes32> authors;   // fetch what they publish
    std::vector<Bytes32> inbox;     // fetch what mentions or zaps them (trust evidence for seeds)
    std::vector<Bytes32> giftWraps; // fetch their gift wraps (owner sessions, authenticated as them)
    std::vector<Bytes32> meta;      // fetch their profile and relay list (bootstrap relays only)

    bool operator==(const Assignment &o) const {
        return authors == o.authors && inbox == o.inbox && giftWraps == o.giftWraps && meta == o.meta;
    }
};

enum class Scope { Authors, Inbox, ZapsSent, GiftWraps, Meta };

struct ReqSpec {
    Scope scope;
    bool live = false;
    std::vector<Bytes32> pubkeys;
    uint64_t since = 0;
    uint64_t until = 0; // 0 means open-ended
    uint64_t chainStartedAt = 0;
    uint64_t page = 0;
};

static tao::json::value buildFilter(const ReqSpec &r) {
    tao::json::value f = tao::json::empty_object;

    if (r.scope == Scope::Authors) {
        f["authors"] = hexArray(r.pubkeys);
    } else if (r.scope == Scope::Inbox) {
        f["#p"] = hexArray(r.pubkeys);
        f["kinds"] = tao::json::empty_array;
        for (auto k : inboxKinds) f["kinds"].emplace_back(k);
    } else if (r.scope == Scope::ZapsSent) {
        f["#P"] = hexArray(r.pubkeys);
        f["kinds"] = tao::json::value::array({ uint64_t(9735) });
    } else if (r.scope == Scope::GiftWraps) {
        f["#p"] = hexArray(r.pubkeys);
        f["kinds"] = tao::json::value::array({ uint64_t(1059) });
    } else {
        f["authors"] = hexArray(r.pubkeys);
        f["kinds"] = tao::json::value::array({ uint64_t(0), uint64_t(10002) });
    }

    if (r.since) f["since"] = r.since;
    if (r.until) f["until"] = r.until;

    if (r.scope == Scope::Meta) f["limit"] = r.pubkeys.size() * 2;
    else if (!r.live) f["limit"] = cfg().banyan__harvester__pageLimit;

    return f;
}

struct ActiveReq {
    std::vector<ReqSpec> specs; // a live REQ may carry several filters
    NostrFilterGroup compiled;
    uint64_t received = 0;
    uint64_t oldest = MAX_U64;
    uint64_t startedAt = 0;
};

enum class AuthState { None, Wanted, Signing, Sent, Ok, Failed };

static std::string_view authStateName(AuthState s) {
    switch (s) {
        case AuthState::None: return "none";
        case AuthState::Wanted: return "wanted";
        case AuthState::Signing: return "signing";
        case AuthState::Sent: return "sent";
        case AuthState::Ok: return "ok";
        case AuthState::Failed: return "failed";
    }
    return "?";
}

struct Delivery {
    std::string id; // hex
    std::string json;
    uint64_t createdAt = 0;
    uint64_t sentAt = 0;
    bool outbox = false; // to the author's own write relay, rather than the inbox of someone mentioned
};

// Harvest: shared by every universe. Owner: authenticated as one owner, through their remote signer. Signer: NIP-46 messages.
enum class Role { Harvest, Owner, Signer };

static std::string_view roleName(Role r) {
    switch (r) {
        case Role::Harvest: return "harvest";
        case Role::Owner: return "owner";
        case Role::Signer: return "signer";
    }
    return "?";
}

struct Relay {
    std::string key; // url, url#ownerhex or nip46|url
    std::string url;
    Role role = Role::Harvest;
    uint64_t tenantId = 0;
    Bytes32 authAs;
    std::string signerReq;

    uWS::WebSocket<uWS::CLIENT> *ws = nullptr;
    bool probing = false;
    bool connecting = false;
    uint64_t connectedAt = 0;
    uint64_t nextAttemptAt = 0;
    uint64_t failures = 0;

    Assignment assignment;
    flat_hash_set<Bytes32> backfilledAuthors, backfilledInbox, backfilledGiftWraps, metaDone;

    std::deque<ReqSpec> queue;
    std::map<std::string, ActiveReq> active;
    uint64_t nextSubId = 1;

    uint64_t eventsReceived = 0;
    std::string lastError;

    // NIP-42: what the relay refused before AUTH is replayed once it succeeds
    AuthState authState = AuthState::None;
    std::string authChallenge;
    std::string authEventId;
    uint64_t authSentAt = 0;
    std::vector<ReqSpec> authRetry;
    bool authRetryLive = false;

    // Events sent to this relay: inbox of someone they mention, or outbox of their author
    std::deque<Delivery> outbox;
    flat_hash_map<std::string, Delivery> inflight;
    flat_hash_set<std::string> deliveryIds;
    uint64_t delivered = 0;
    uint64_t deliveryRejected = 0;
    uint64_t lastDeliveryAt = 0;

    bool hasDeliveryWork() const {
        return outbox.size() || inflight.size();
    }

    bool deliveryOnly() const {
        return role == Role::Harvest && assignment == Assignment{};
    }

    void resetSession() {
        active.clear();
        queue.clear();
        authState = AuthState::None;
        authChallenge.clear();
        authEventId.clear();
        authRetry.clear();
        authRetryLive = false;

        for (auto &[id, d] : inflight) outbox.push_front(std::move(d));
        inflight.clear();
    }
};

struct PlanEntry {
    std::string url;
    Role role = Role::Harvest;
    uint64_t tenantId = 0;
    Bytes32 authAs;
    Assignment assignment;
    std::string signerReq;
};


struct Harvester {
    PinnedHub hub;
    uWS::Group<uWS::CLIENT> *group = nullptr;
    uS::Async *trigger = nullptr;
    WriterPipeline writer;
    Prober prober{8};
    RemoteSigners signers;

    std::map<std::string, Relay> relays;
    flat_hash_map<Bytes32, bool> targets; // pubkey -> is seed
    uint64_t lastPlanAt = 0;
    uint64_t lastUniverseVersion = 0;

    std::optional<KeyPair> key;

    // Distribution: the inbox and outbox relays of each universe member, and where harvested events already are
    struct SeenOn {
        uint64_t at = 0;
        std::vector<std::string> urls;
    };

    flat_hash_map<Bytes32, std::vector<std::string>> deliveryRelays;
    flat_hash_map<Bytes32, std::vector<std::string>> outboxRelays;
    flat_hash_map<Bytes32, SeenOn> seenOn;
    std::optional<uint64_t> distributedUpTo;
    uint64_t deliveredTotal = 0;
    uint64_t publishedTotal = 0;
    uint64_t lastHousekeepingAt = 0;
    Decompressor decomp;

    Harvester() {
        writer.verifyTime = false; // relay lists and profiles are often older than events.rejectEventsOlderThanSeconds
        writer.verboseReject = []{ return false; };
        writer.verboseCommit = []{ return false; };

        try {
            key = loadOrCreateHarvesterKey();
            LI << "Banyan harvester: NIP-42 AUTH as " << toNpub(Bytes32(key->pubkey));
        } catch (std::exception &e) {
            LE << "Banyan harvester: no key for NIP-42 AUTH: " << e.what();
        }

        signers.sendToRelay = [this](const std::string &url, const std::string &msg){
            auto it = relays.find(signerKey(url));
            if (it == relays.end() || !it->second.ws) return false;
            it->second.ws->send(msg.data(), msg.size(), uWS::OpCode::TEXT);
            return true;
        };

        try {
            signers.load();
        } catch (std::exception &e) {
            LE << "Banyan harvester: unable to load remote signers: " << e.what();
        }

        group = hub.createGroup<uWS::CLIENT>(uWS::PERMESSAGE_DEFLATE | uWS::SLIDING_DEFLATE_WINDOW);

        group->onConnection([&](uWS::WebSocket<uWS::CLIENT> *ws, uWS::HttpRequest){
            auto *key = (std::string*)ws->getUserData();
            auto it = relays.find(*key);

            if (it == relays.end()) {
                ws->close();
                return;
            }

            auto &r = it->second;
            r.ws = ws;
            r.connecting = false;
            r.connectedAt = hoytech::curr_time_s();
            LI << "Banyan harvester: connected to " << r.url << (r.role == Role::Harvest ? "" : std::string(" (") + std::string(roleName(r.role)) + ")");

            if (r.role == Role::Signer) sendRaw(r, r.signerReq);
            else startSession(r);
        });

        group->onDisconnection([&](uWS::WebSocket<uWS::CLIENT> *ws, int code, char *message, size_t length){
            auto *key = (std::string*)ws->getUserData();

            if (auto it = relays.find(*key); it != relays.end() && it->second.ws == ws) {
                auto &r = it->second;
                uint64_t now = hoytech::curr_time_s();
                if (now < r.connectedAt + 60) r.failures++;
                else r.failures = 0;
                r.ws = nullptr;
                r.resetSession();
                r.nextAttemptAt = now + backoffSeconds(r.failures);
                LI << "Banyan harvester: disconnected from " << r.url << " (" << code << ")";
            }

            delete key;
        });

        group->onError([&](void *userData){
            auto *key = (std::string*)userData;

            if (auto it = relays.find(*key); it != relays.end()) {
                auto &r = it->second;
                r.connecting = false;
                r.failures++;
                r.lastError = "connection failed";
                LI << "Banyan harvester: unable to connect to " << r.url << ", retrying in " << backoffSeconds(r.failures) << "s";
                r.nextAttemptAt = hoytech::curr_time_s() + backoffSeconds(r.failures);
            }

            delete key;
        });

        group->onMessage2([&](uWS::WebSocket<uWS::CLIENT> *ws, char *message, size_t length, uWS::OpCode, size_t){
            auto *key = (std::string*)ws->getUserData();
            auto it = relays.find(*key);
            if (it == relays.end() || it->second.ws != ws) return;

            try {
                if (it->second.role == Role::Signer) handleSignerMessage(it->second, std::string_view(message, length));
                else handleMessage(it->second, std::string_view(message, length));
            } catch (std::exception &e) {
                it->second.lastError = std::string("bad message: ") + e.what();
            }

            writer.wait();
        });
    }

    static std::string signerKey(const std::string &url) {
        return "nip46|" + url;
    }

    static std::string ownerKey(const std::string &url, const Bytes32 &owner) {
        return url + "#" + to_hex(owner.sv());
    }

    static constexpr uint64_t maxBackoffSeconds = 1800;

    static uint64_t backoffSeconds(uint64_t failures) {
        uint64_t delay = 10;
        for (uint64_t i = 0; i < failures && delay < maxBackoffSeconds; i++) delay *= 2;
        return std::min<uint64_t>(delay, maxBackoffSeconds);
    }


    void send(Relay &r, const tao::json::value &msg) {
        if (!r.ws) return;
        auto str = tao::json::to_string(msg);
        r.ws->send(str.data(), str.size(), uWS::OpCode::TEXT);
    }

    void sendRaw(Relay &r, const std::string &msg) {
        if (!r.ws || msg.empty()) return;
        r.ws->send(msg.data(), msg.size(), uWS::OpCode::TEXT);
    }

    void openReq(Relay &r, std::vector<ReqSpec> &&specs) {
        std::string subId = (specs[0].live ? "L" : "B") + std::to_string(r.nextSubId++);

        tao::json::value msg = tao::json::value::array({ "REQ", subId });
        auto &req = r.active[subId];

        for (const auto &spec : specs) {
            auto f = buildFilter(spec);
            req.compiled.addFilter(f, MAX_U64);
            msg.emplace_back(std::move(f));
        }

        req.specs = std::move(specs);
        req.startedAt = hoytech::curr_time_s();

        send(r, msg);
    }

    void closeReq(Relay &r, std::string subId) {
        send(r, tao::json::value::array({ "CLOSE", subId }));
        r.active.erase(subId);
    }

    uint64_t numBackfilling(const Relay &r) {
        uint64_t n = 0;
        for (const auto &[subId, req] : r.active) {
            if (!req.specs[0].live) n++;
        }
        return n;
    }

    void pump(Relay &r) {
        while (r.ws && r.queue.size() && numBackfilling(r) < cfg().banyan__harvester__maxConcurrentReqsPerRelay) {
            auto spec = std::move(r.queue.front());
            r.queue.pop_front();
            std::vector<ReqSpec> specs;
            specs.push_back(std::move(spec));
            openReq(r, std::move(specs));
        }
    }


    std::vector<std::vector<Bytes32>> chunk(const std::vector<Bytes32> &pks) {
        std::vector<std::vector<Bytes32>> output;
        uint64_t size = std::max<uint64_t>(1, cfg().banyan__harvester__authorsPerFilter);

        for (size_t i = 0; i < pks.size(); i += size) {
            output.emplace_back(pks.begin() + i, pks.begin() + std::min<size_t>(pks.size(), i + size));
        }

        return output;
    }

    // Groups pubkeys by where their backfill must resume, so one REQ never refetches years for a pubkey done yesterday
    void enqueueBackfill(Relay &r, Scope scope, const std::vector<Bytes32> &pks) {
        if (pks.empty()) return;

        uint64_t now = hoytech::curr_time_s();
        uint64_t window = cfg().banyan__harvester__backfillDays * 86400;
        uint64_t defaultSince = now > window ? now - window : 0;
        uint64_t margin = scope == Scope::GiftWraps ? giftWrapJitterSeconds : 3600;

        std::vector<std::pair<uint64_t, Bytes32>> bySince;

        {
            auto txn = env.txn_ro();
            for (const auto &pk : pks) {
                uint64_t since = defaultSince;
                if (auto st = env.lookup_HarvestState__pubkey(txn, pk.sv())) {
                    uint64_t done = scope == Scope::Authors ? st->authoredBackfilledAt() : scope == Scope::GiftWraps ? st->giftWrapsBackfilledAt() : st->inboxBackfilledAt();
                    if (done) since = std::max(defaultSince, done > margin ? done - margin : 0);
                }
                bySince.emplace_back(since, pk);
            }
        }

        std::sort(bySince.begin(), bySince.end(), [](const auto &a, const auto &b){ return a.first < b.first; });

        std::vector<Bytes32> sorted;
        for (const auto &[since, pk] : bySince) sorted.push_back(pk);

        size_t offset = 0;
        for (auto &c : chunk(sorted)) {
            ReqSpec spec;
            spec.scope = scope;
            spec.since = bySince[offset].first;
            spec.chainStartedAt = now;
            offset += c.size();
            spec.pubkeys = std::move(c);
            r.queue.push_back(std::move(spec));

            if (scope == Scope::Inbox) {
                ReqSpec zaps = r.queue.back();
                zaps.scope = Scope::ZapsSent;
                r.queue.push_back(std::move(zaps));
            }
        }
    }

    void openLiveReqs(Relay &r) {
        uint64_t now = hoytech::curr_time_s();
        std::vector<ReqSpec> specs;

        auto add = [&](Scope scope, const std::vector<Bytes32> &pks){
            for (auto &c : chunk(pks)) {
                ReqSpec spec;
                spec.scope = scope;
                spec.live = true;
                spec.since = scope == Scope::GiftWraps ? now - giftWrapJitterSeconds : now;
                spec.pubkeys = std::move(c);
                specs.push_back(std::move(spec));
            }
        };

        add(Scope::Authors, r.assignment.authors);
        add(Scope::Inbox, r.assignment.inbox);
        add(Scope::ZapsSent, r.assignment.inbox);
        add(Scope::GiftWraps, r.assignment.giftWraps);

        for (size_t i = 0; i < specs.size(); i += maxFiltersPerLiveReq) {
            std::vector<ReqSpec> group(std::make_move_iterator(specs.begin() + i), std::make_move_iterator(specs.begin() + std::min<size_t>(specs.size(), i + maxFiltersPerLiveReq)));
            openReq(r, std::move(group));
        }
    }

    void enqueueMissingWork(Relay &r) {
        flat_hash_set<Bytes32> pendingMeta, pendingAuthors, pendingInbox, pendingGiftWraps;

        auto collect = [&](const ReqSpec &spec){
            if (spec.live) return;
            flat_hash_set<Bytes32> *set = nullptr;
            if (spec.scope == Scope::Meta) set = &pendingMeta;
            else if (spec.scope == Scope::Authors) set = &pendingAuthors;
            else if (spec.scope == Scope::Inbox) set = &pendingInbox;
            else if (spec.scope == Scope::GiftWraps) set = &pendingGiftWraps;
            if (set) set->insert(spec.pubkeys.begin(), spec.pubkeys.end());
        };

        for (const auto &spec : r.queue) collect(spec);
        for (const auto &spec : r.authRetry) collect(spec);
        for (const auto &[subId, req] : r.active) {
            for (const auto &spec : req.specs) collect(spec);
        }

        auto missing = [](const std::vector<Bytes32> &assigned, const flat_hash_set<Bytes32> &done, const flat_hash_set<Bytes32> &pending){
            std::vector<Bytes32> output;
            for (const auto &pk : assigned) {
                if (!done.contains(pk) && !pending.contains(pk)) output.push_back(pk);
            }
            return output;
        };

        auto meta = missing(r.assignment.meta, r.metaDone, pendingMeta);

        // Relay lists first: they decide where everything else is fetched from
        for (auto &c : chunk(meta)) {
            ReqSpec spec;
            spec.scope = Scope::Meta;
            spec.pubkeys = std::move(c);
            r.queue.push_front(std::move(spec));
        }

        enqueueBackfill(r, Scope::Authors, missing(r.assignment.authors, r.backfilledAuthors, pendingAuthors));
        enqueueBackfill(r, Scope::Inbox, missing(r.assignment.inbox, r.backfilledInbox, pendingInbox));
        enqueueBackfill(r, Scope::GiftWraps, missing(r.assignment.giftWraps, r.backfilledGiftWraps, pendingGiftWraps));
    }

    void startSession(Relay &r) {
        r.active.clear();
        r.queue.clear();
        enqueueMissingWork(r);
        openLiveReqs(r);
        pump(r);
        pumpOutbox(r);
    }

    void closeLiveReqs(Relay &r) {
        std::vector<std::string> liveSubs;
        for (const auto &[subId, req] : r.active) {
            if (req.specs[0].live) liveSubs.push_back(subId);
        }
        for (const auto &subId : liveSubs) closeReq(r, subId);
    }

    void refreshAssignment(Relay &r) {
        closeLiveReqs(r);
        enqueueMissingWork(r);
        openLiveReqs(r);
        pump(r);
    }


    bool authEnabled(const Relay &r) {
        if (!cfg().banyan__harvester__auth) return false;
        if (r.role == Role::Owner) return cfg().banyan__signer__enabled;
        return key.has_value();
    }

    void sendAuth(Relay &r) {
        if (!authEnabled(r) || r.authChallenge.empty() || !r.ws) return;

        if (r.role == Role::Owner) {
            r.authState = AuthState::Signing;
            r.authSentAt = hoytech::curr_time_s();

            std::string relayKey = r.key, challenge = r.authChallenge;

            signers.signAuth(r.tenantId, r.url, challenge, [this, relayKey, challenge](bool ok, const tao::json::value &ev, const std::string &error){
                auto it = relays.find(relayKey);
                if (it == relays.end()) return;
                auto &r = it->second;
                if (r.authState != AuthState::Signing || r.authChallenge != challenge || !r.ws) return;

                if (!ok) return authDone(r, false, "remote signer: " + error);

                r.authEventId = ev.at("id").get_string();
                r.authState = AuthState::Sent;
                r.authSentAt = hoytech::curr_time_s();
                send(r, tao::json::value::array({ "AUTH", ev }));
            });

            return;
        }

        tao::json::value ev;

        try {
            ev = key->sign(22242, tao::json::value::array({
                tao::json::value::array({ "relay", r.url }),
                tao::json::value::array({ "challenge", r.authChallenge }),
            }), "");
        } catch (std::exception &e) {
            r.lastError = std::string("unable to sign AUTH: ") + e.what();
            return;
        }

        r.authEventId = ev.at("id").get_string();
        r.authState = AuthState::Sent;
        r.authSentAt = hoytech::curr_time_s();
        send(r, tao::json::value::array({ "AUTH", ev }));
    }

    // The relay refused something until we authenticate. Returns false when AUTH can't help.
    bool deferUntilAuth(Relay &r) {
        if (!authEnabled(r) || r.authState == AuthState::Ok || r.authState == AuthState::Failed) return false;

        if (r.authState == AuthState::None) {
            r.authState = AuthState::Wanted;
            r.authSentAt = hoytech::curr_time_s();
            sendAuth(r);
        }

        return r.authState != AuthState::Failed;
    }

    void authDone(Relay &r, bool ok, const std::string &reason) {
        r.authEventId.clear();

        if (!ok) {
            r.authState = AuthState::Failed;
            r.lastError = "AUTH refused: " + reason;
            r.authRetry.clear();
            r.authRetryLive = false;
            LI << "Banyan harvester: " << r.url << " refused our AUTH: " << reason;
            pumpOutbox(r);
            return;
        }

        r.authState = AuthState::Ok;
        LI << "Banyan harvester: authenticated to " << r.url << (r.role == Role::Owner ? " as " + toNpub(r.authAs) : "");

        if (r.role == Role::Signer) {
            sendRaw(r, r.signerReq);
            return;
        }

        for (auto it = r.authRetry.rbegin(); it != r.authRetry.rend(); ++it) r.queue.push_front(std::move(*it));
        r.authRetry.clear();

        if (r.authRetryLive) {
            r.authRetryLive = false;
            closeLiveReqs(r);
            openLiveReqs(r);
        }

        pump(r);
        pumpOutbox(r);
    }


    void pumpOutbox(Relay &r) {
        if (!r.ws || r.authState == AuthState::Wanted || r.authState == AuthState::Signing || r.authState == AuthState::Sent) return;

        uint64_t now = hoytech::curr_time_s();
        uint64_t maxAge = cfg().banyan__distributor__maxAgeSeconds;

        while (r.outbox.size() && r.inflight.size() < maxInflightDeliveries) {
            auto d = std::move(r.outbox.front());
            r.outbox.pop_front();

            if (d.createdAt + maxAge < now) {
                r.deliveryIds.erase(d.id);
                continue;
            }

            std::string msg = "[\"EVENT\"," + d.json + "]";
            r.ws->send(msg.data(), msg.size(), uWS::OpCode::TEXT);

            d.sentAt = now;
            std::string id = d.id;
            r.inflight.emplace(std::move(id), std::move(d));
        }
    }

    void deliveryDone(Relay &r, const std::string &id, bool ok, const std::string &reason) {
        auto it = r.inflight.find(id);
        if (it == r.inflight.end()) return;

        auto d = std::move(it->second);
        r.inflight.erase(it);
        r.lastDeliveryAt = hoytech::curr_time_s();

        if (ok || reason.starts_with("duplicate:")) {
            r.delivered++;
            if (d.outbox) publishedTotal++;
            else deliveredTotal++;
            r.deliveryIds.erase(d.id);
        } else if (reason.starts_with("auth-required:") && deferUntilAuth(r)) {
            r.outbox.push_front(std::move(d));
        } else {
            r.deliveryRejected++;
            r.deliveryIds.erase(d.id);
            r.lastError = "event refused: " + reason;
        }

        pumpOutbox(r);
    }

    size_t numDeliveryOnlyRelays() {
        return std::count_if(relays.begin(), relays.end(), [](const auto &p){ return p.second.deliveryOnly(); });
    }

    // Only shared connections are opened on demand: owner sessions exist because the plan wants them
    void queueDelivery(const std::string &relayKey, const std::string &url, const std::string &id, const std::string &json, uint64_t createdAt, bool outbox, size_t &deliveryOnlyCount) {
        auto it = relays.find(relayKey);

        if (it == relays.end()) {
            if (relayKey != url || deliveryOnlyCount >= maxDeliveryOnlyRelays) return;
            deliveryOnlyCount++;
            it = relays.try_emplace(url).first;
            it->second.key = url;
            it->second.url = url;
        }

        auto &r = it->second;
        if (!r.deliveryIds.insert(id).second) return;

        if (r.outbox.size() >= maxOutboxPerRelay) {
            r.deliveryIds.erase(r.outbox.front().id);
            r.outbox.pop_front();
        }

        r.outbox.push_back(Delivery{ id, json, createdAt, 0, outbox });
        r.lastDeliveryAt = hoytech::curr_time_s();
        pumpOutbox(r);
    }

    // The distribution side of the outbox model: events reach the inbox relays of the universe members they mention
    void distribute(uint64_t now) {
        if (!cfg().banyan__distributor__enabled) {
            distributedUpTo.reset();
            return;
        }

        auto txn = env.txn_ro();
        uint64_t latest = getMostRecentLevId(txn);

        // Starts from now: history is already where its authors put it
        if (!distributedUpTo || *distributedUpTo > latest) {
            distributedUpTo = latest;
            return;
        }

        if (latest == *distributedUpTo) return;

        auto snap = TenantRegistry::get();
        uint64_t maxAge = cfg().banyan__distributor__maxAgeSeconds;
        uint64_t minCreated = now > maxAge ? now - maxAge : 0;
        uint64_t processed = 0;
        size_t deliveryOnlyCount = numDeliveryOnlyRelays();

        env.foreach_Event(txn, [&](auto &ev){
            if (processed++ >= maxEventsDistributedPerTick) return false;
            distributedUpTo = ev.primaryKeyId;

            PackedEventView packed(ev.buf);
            if (std::find(deliveredKinds.begin(), deliveredKinds.end(), packed.kind()) == deliveredKinds.end()) return true;
            if (packed.created_at() < minCreated || packed.created_at() > now + maxFutureSeconds) return true;

            Bytes32 author(packed.pubkey());
            std::vector<Bytes32> mentioned;

            packed.foreachTag([&](char tagName, std::string_view tagVal){
                if (tagName == 'p' && tagVal.size() == 32 && Bytes32(tagVal) != author) mentioned.emplace_back(tagVal);
                return true;
            });

            if (mentioned.empty()) return true;

            flat_hash_set<Bytes32> recipients;

            for (const auto &t : snap->tenants) {
                if (!t->universe.contains(author)) continue;
                for (const auto &pk : mentioned) {
                    if (t->universe.contains(pk)) recipients.insert(pk);
                }
            }

            if (recipients.empty()) return true;

            auto seen = seenOn.find(Bytes32(packed.id()));
            std::string id = to_hex(packed.id());
            std::string json;

            for (const auto &pk : recipients) {
                auto it = deliveryRelays.find(pk);
                if (it == deliveryRelays.end()) continue;

                for (const auto &url : it->second) {
                    if (seen != seenOn.end() && std::find(seen->second.urls.begin(), seen->second.urls.end(), url) != seen->second.urls.end()) continue;
                    if (json.empty()) json = std::string(getEventJson(txn, decomp, ev.primaryKeyId));
                    queueDelivery(url, url, id, json, packed.created_at(), false, deliveryOnlyCount);
                }
            }

            return true;
        }, false, *distributedUpTo + 1);
    }

    // What clients publish on a virtual relay also reaches the author's own write relays, so the Banyan can be their only relay
    void publishToOutboxes(uint64_t now) {
        std::deque<Published> batch;
        {
            std::lock_guard<std::mutex> guard(publishMutex);
            batch.swap(publishQueue);
        }

        if (batch.empty() || !cfg().banyan__distributor__enabled || !cfg().banyan__distributor__publishToOutbox) return;

        auto snap = TenantRegistry::get();
        uint64_t maxAge = cfg().banyan__distributor__maxAgeSeconds;
        uint64_t minCreated = now > maxAge ? now - maxAge : 0;
        size_t deliveryOnlyCount = numDeliveryOnlyRelays();

        for (const auto &p : batch) {
            auto t = snap->findById(p.tenantId);
            if (!t) continue;

            PackedEventView packed(p.packedStr);
            uint64_t kind = packed.kind();

            if (!t->inUniverse(packed.pubkey())) continue;
            if (kind == 1059 || kind == 21059 || (kind >= 20000 && kind < 30000)) continue;
            if (packed.created_at() < minCreated || packed.created_at() > now + maxFutureSeconds) continue;

            // NIP-70: only the author may publish a protected event
            bool isProtected = false;
            packed.foreachTag([&](char tagName, std::string_view){
                if (tagName == '-') isProtected = true;
                return !isProtected;
            });
            if (isProtected) continue;

            Bytes32 author(packed.pubkey());
            auto it = outboxRelays.find(author);
            if (it == outboxRelays.end()) continue;

            std::string id = to_hex(packed.id());

            for (const auto &url : it->second) {
                auto key = ownerKey(url, author);
                queueDelivery(relays.contains(key) ? key : url, url, id, p.jsonStr, packed.created_at(), true, deliveryOnlyCount);
            }
        }
    }


    void markBackfilled(const std::vector<Bytes32> &pks, Scope scope, uint64_t at) {
        auto txn = env.txn_rw();

        for (const auto &pk : pks) {
            auto st = env.lookup_HarvestState__pubkey(txn, pk.sv());

            if (st) {
                defaultDb::environment::Updates_HarvestState upd;
                if (scope == Scope::Authors) upd.authoredBackfilledAt = at;
                else if (scope == Scope::GiftWraps) upd.giftWrapsBackfilledAt = at;
                else upd.inboxBackfilledAt = at;
                env.update_HarvestState(txn, *st, upd);
            } else {
                env.insert_HarvestState(txn, pk.sv(), scope == Scope::Authors ? at : 0, scope == Scope::Inbox ? at : 0, scope == Scope::GiftWraps ? at : 0);
            }
        }

        txn.commit();
    }

    void completeBackfill(Relay &r, const ReqSpec &spec) {
        if (spec.scope == Scope::Meta) {
            for (const auto &pk : spec.pubkeys) r.metaDone.insert(pk);
            wakeRequested = true;
            return;
        }

        if (spec.scope != Scope::ZapsSent) {
            auto &done = spec.scope == Scope::Authors ? r.backfilledAuthors : spec.scope == Scope::GiftWraps ? r.backfilledGiftWraps : r.backfilledInbox;
            for (const auto &pk : spec.pubkeys) done.insert(pk);

            try {
                markBackfilled(spec.pubkeys, spec.scope, spec.chainStartedAt);
            } catch (std::exception &e) {
                LE << "Banyan harvester: unable to store backfill progress: " << e.what();
            }
        }

        if (spec.scope != Scope::GiftWraps) notifyEngagementChanged(spec.pubkeys);
    }

    void handleMessage(Relay &r, std::string_view msg) {
        auto json = tao::json::from_string(msg);
        const auto &arr = json.get_array();
        if (arr.size() < 2 || !arr[0].is_string()) return;
        const auto &type = arr[0].get_string();

        if (type == "EVENT" && arr.size() >= 3) {
            auto it = r.active.find(arr[1].get_string());
            if (it == r.active.end()) return;
            auto &req = it->second;

            const auto &evJson = arr[2];
            std::string packedStr;

            try {
                packedStr = nostrJsonToPackedEvent(evJson);
            } catch (std::exception &) {
                return;
            }

            PackedEventView packed(packedStr);
            if (!req.compiled.doesMatch(packed)) return;
            uint64_t now = hoytech::curr_time_s();
            if (packed.created_at() > now + maxFutureSeconds) return;

            req.received++;
            if (packed.created_at() < req.oldest) req.oldest = packed.created_at();
            r.eventsReceived++;

            if (cfg().banyan__distributor__enabled && packed.created_at() + cfg().banyan__distributor__maxAgeSeconds >= now
                    && std::find(deliveredKinds.begin(), deliveredKinds.end(), packed.kind()) != deliveredKinds.end()) {
                auto &seen = seenOn[Bytes32(packed.id())];
                if (!seen.at) seen.at = now;
                if (std::find(seen.urls.begin(), seen.urls.end(), r.url) == seen.urls.end()) seen.urls.push_back(r.url);
            }

            writer.write({ evJson });
        } else if (type == "EOSE") {
            auto it = r.active.find(arr[1].get_string());
            if (it == r.active.end()) return;
            auto &req = it->second;
            if (req.specs[0].live) return;

            auto spec = req.specs[0];
            uint64_t received = req.received, oldest = req.oldest;
            closeReq(r, it->first);

            bool more = spec.scope != Scope::Meta && received > 0 && oldest != MAX_U64 && oldest > spec.since && spec.page + 1 < maxPagesPerChain;

            if (more) {
                // Same-second events can straddle a page boundary, so resume at oldest unless that makes no progress
                uint64_t nextUntil = oldest;
                if (spec.until && nextUntil >= spec.until) nextUntil = spec.until - 1;
                spec.until = nextUntil;
                spec.page++;
                r.queue.push_front(std::move(spec));
            } else {
                completeBackfill(r, spec);
            }

            pump(r);
        } else if (type == "CLOSED") {
            auto it = r.active.find(arr[1].get_string());
            if (it == r.active.end()) return;
            std::string reason = arr.size() >= 3 && arr[2].is_string() ? arr[2].get_string() : "closed by relay";

            if (reason.starts_with("auth-required:") && deferUntilAuth(r)) {
                auto specs = std::move(it->second.specs);
                r.active.erase(it);

                if (specs[0].live) r.authRetryLive = true;
                else for (auto &spec : specs) r.authRetry.push_back(std::move(spec));

                pump(r);
                return;
            }

            r.lastError = reason;
            r.active.erase(it);
            pump(r);
        } else if (type == "AUTH") {
            if (!arr[1].is_string()) return;
            r.authChallenge = arr[1].get_string();
            if (r.authState != AuthState::Failed && r.authState != AuthState::Sent && r.authState != AuthState::Signing) sendAuth(r);
        } else if (type == "OK" && arr.size() >= 3 && arr[1].is_string()) {
            const auto &id = arr[1].get_string();
            bool ok = arr[2].is_boolean() && arr[2].get_boolean();
            std::string reason = arr.size() >= 4 && arr[3].is_string() ? arr[3].get_string() : "";

            if (id == r.authEventId) authDone(r, ok, reason);
            else deliveryDone(r, id, ok, reason);
        } else if (type == "NOTICE") {
            r.lastError = arr[1].is_string() ? arr[1].get_string() : "notice";
        }
    }

    void handleSignerMessage(Relay &r, std::string_view msg) {
        auto json = tao::json::from_string(msg);
        const auto &arr = json.get_array();
        if (arr.size() < 2 || !arr[0].is_string()) return;
        const auto &type = arr[0].get_string();

        if (type == "EVENT" && arr.size() >= 3) {
            signers.onEvent(r.url, arr[2]);
        } else if (type == "AUTH" && arr[1].is_string()) {
            r.authChallenge = arr[1].get_string();
            if (r.authState != AuthState::Failed && r.authState != AuthState::Sent) sendAuth(r);
        } else if (type == "OK" && arr.size() >= 3 && arr[1].is_string()) {
            bool ok = arr[2].is_boolean() && arr[2].get_boolean();
            std::string reason = arr.size() >= 4 && arr[3].is_string() ? arr[3].get_string() : "";
            if (arr[1].get_string() == r.authEventId) authDone(r, ok, reason);
            else if (!ok) r.lastError = "request refused: " + reason;
        } else if (type == "CLOSED") {
            std::string reason = arr.size() >= 3 && arr[2].is_string() ? arr[2].get_string() : "closed by relay";
            if (!(reason.starts_with("auth-required:") && deferUntilAuth(r))) r.lastError = reason;
        } else if (type == "NOTICE") {
            r.lastError = arr[1].is_string() ? arr[1].get_string() : "notice";
        }
    }


    void plan() {
        auto snap = TenantRegistry::get();
        lastUniverseVersion = snap->universeVersion;
        lastPlanAt = hoytech::curr_time_s();

        targets.clear();
        for (const auto &t : snap->tenants) {
            for (const auto &m : t->members) targets[m.pubkey] = targets[m.pubkey] || t->isSeed(m);
        }

        std::vector<Bytes32> wanted;
        {
            std::lock_guard<std::mutex> guard(wantedMutex);
            for (auto it = wantedProfiles.begin(); it != wantedProfiles.end(); ) {
                if (it->second + wantedProfileSeconds < lastPlanAt) {
                    wantedProfiles.erase(it++);
                    continue;
                }
                if (!targets.contains(it->first)) wanted.push_back(it->first);
                ++it;
            }
        }

        auto bootstrap = parseUrlList(cfg().banyan__harvester__bootstrapRelays);
        auto excludedList = parseUrlList(cfg().banyan__harvester__excludedRelays);
        flat_hash_set<std::string> excluded(excludedList.begin(), excludedList.end());
        std::string ownHost = cfg().relay__auth__serviceUrl.size() ? parseRelayUrl(cfg().relay__auth__serviceUrl).host : "";

        auto allowed = [&](const std::string &url){
            if (excluded.contains(url)) return false;
            if (ownHost.size() && parseRelayUrl(url).host == ownHost) return false;
            return true;
        };

        std::erase_if(bootstrap, [&](const auto &url){ return !allowed(url); });

        flat_hash_map<Bytes32, RelayList> lists;
        flat_hash_map<std::string, uint64_t> popularity;
        flat_hash_map<uint64_t, std::vector<std::string>> ownerUrls;

        {
            auto txn = env.txn_ro();
            Decompressor decomp;

            for (const auto &[pk, seed] : targets) {
                auto rl = loadRelayList(txn, decomp, pk, allowed);
                for (const auto &url : rl.write) popularity[url]++;
                if (seed) {
                    for (const auto &url : rl.read) popularity[url]++;
                }
                lists[pk] = std::move(rl);
            }

            // DM relays first, where gift wraps wait, then the owner's inboxes and outboxes
            for (auto tenantId : signers.readyTenants()) {
                auto t = snap->findById(tenantId);
                if (!t) continue;

                const auto &rl = lists[t->pubkey];
                auto &urls = ownerUrls[tenantId];

                auto addAll = [&](const std::vector<std::string> &from){
                    for (const auto &url : from) {
                        if (urls.size() < maxOwnerRelays && std::find(urls.begin(), urls.end(), url) == urls.end()) urls.push_back(url);
                    }
                };

                addAll(loadDmRelays(txn, decomp, t->pubkey, allowed));
                addAll(rl.read);
                addAll(rl.write);
            }
        }

        // Prefer relays many targets share, so the same few connections cover most of the universe
        auto pick = [&](const std::vector<std::string> &candidates){
            std::vector<std::string> sorted = candidates;
            std::stable_sort(sorted.begin(), sorted.end(), [&](const auto &a, const auto &b){ return popularity[a] > popularity[b]; });
            if (sorted.size() > cfg().banyan__harvester__relaysPerPubkey) sorted.resize(cfg().banyan__harvester__relaysPerPubkey);
            return sorted;
        };

        deliveryRelays.clear();
        outboxRelays.clear();
        for (const auto &[pk, seed] : targets) {
            const auto &rl = lists[pk];
            if (rl.read.size()) deliveryRelays[pk] = pick(rl.read);
            if (rl.write.size()) {
                auto &out = outboxRelays[pk];
                out.assign(rl.write.begin(), rl.write.begin() + std::min(rl.write.size(), maxOutboxRelaysPerAuthor));
            }
        }

        std::map<std::string, Assignment> shared;

        for (const auto &[pk, seed] : targets) {
            const auto &rl = lists[pk];

            for (const auto &url : pick(rl.write.size() ? rl.write : bootstrap)) shared[url].authors.push_back(pk);

            if (seed) {
                for (const auto &url : pick(rl.read.size() ? rl.read : bootstrap)) shared[url].inbox.push_back(pk);
            }

            if (!rl.found) {
                for (const auto &url : bootstrap) shared[url].meta.push_back(pk);
            }
        }

        for (const auto &pk : wanted) {
            for (const auto &url : bootstrap) shared[url].meta.push_back(pk);
        }

        capRelays(shared, bootstrap);

        std::map<std::string, PlanEntry> entries;

        // An owner's own data on their relays is fetched through their session, authenticated as them
        for (const auto &[tenantId, urls] : ownerUrls) {
            auto t = snap->findById(tenantId);
            if (!t) continue;

            for (const auto &url : urls) {
                auto &e = entries[ownerKey(url, t->pubkey)];
                e.url = url;
                e.role = Role::Owner;
                e.tenantId = tenantId;
                e.authAs = t->pubkey;
                e.assignment.authors = { t->pubkey };
                e.assignment.inbox = { t->pubkey };
                e.assignment.giftWraps = { t->pubkey };

                if (auto it = shared.find(url); it != shared.end()) {
                    std::erase(it->second.authors, t->pubkey);
                    std::erase(it->second.inbox, t->pubkey);
                }
            }
        }

        for (auto &[url, a] : shared) {
            if (a == Assignment{}) continue;

            std::sort(a.authors.begin(), a.authors.end());
            std::sort(a.inbox.begin(), a.inbox.end());
            std::sort(a.meta.begin(), a.meta.end());

            auto &e = entries[url];
            e.url = url;
            e.assignment = std::move(a);
        }

        for (const auto &[url, req] : signers.subscriptions()) {
            auto &e = entries[signerKey(url)];
            e.url = url;
            e.role = Role::Signer;
            e.signerReq = req;
        }

        apply(entries);
    }

    void capRelays(std::map<std::string, Assignment> &plan, const std::vector<std::string> &bootstrap) {
        uint64_t maxRelays = std::max<uint64_t>(cfg().banyan__harvester__maxRelays, bootstrap.size());
        if (plan.size() <= maxRelays || bootstrap.empty()) return;

        std::vector<std::pair<std::string, size_t>> ranked;
        for (const auto &[url, a] : plan) {
            bool isBootstrap = std::find(bootstrap.begin(), bootstrap.end(), url) != bootstrap.end();
            ranked.emplace_back(url, isBootstrap ? MAX_U64 : a.authors.size() + a.inbox.size());
        }

        std::stable_sort(ranked.begin(), ranked.end(), [](const auto &a, const auto &b){ return a.second > b.second; });

        flat_hash_set<std::string> kept;
        for (size_t i = 0; i < ranked.size() && i < maxRelays; i++) kept.insert(ranked[i].first);

        flat_hash_set<Bytes32> coveredAuthors, coveredInbox;
        for (const auto &[url, a] : plan) {
            if (!kept.contains(url)) continue;
            for (const auto &pk : a.authors) coveredAuthors.insert(pk);
            for (const auto &pk : a.inbox) coveredInbox.insert(pk);
        }

        auto &fallback = plan[bootstrap[0]];

        for (auto it = plan.begin(); it != plan.end(); ) {
            if (kept.contains(it->first)) {
                ++it;
                continue;
            }

            for (const auto &pk : it->second.authors) {
                if (coveredAuthors.insert(pk).second) fallback.authors.push_back(pk);
            }
            for (const auto &pk : it->second.inbox) {
                if (coveredInbox.insert(pk).second) fallback.inbox.push_back(pk);
            }

            it = plan.erase(it);
        }
    }

    void apply(const std::map<std::string, PlanEntry> &entries) {
        for (auto it = relays.begin(); it != relays.end(); ) {
            if (entries.contains(it->first)) {
                ++it;
                continue;
            }

            // Out of the plan, but still delivering: it stays until its outbox is empty
            auto &r = it->second;
            if (r.role == Role::Harvest && r.hasDeliveryWork()) {
                if (!r.deliveryOnly()) {
                    r.assignment = Assignment{};
                    if (r.ws) refreshAssignment(r);
                }
                ++it;
                continue;
            }

            if (r.ws) r.ws->close();
            it = relays.erase(it);
        }

        for (const auto &[key, e] : entries) {
            auto [it, isNew] = relays.try_emplace(key);
            auto &r = it->second;

            if (isNew) {
                r.key = key;
                r.url = e.url;
                r.role = e.role;
                r.tenantId = e.tenantId;
                r.authAs = e.authAs;
            }

            if (r.role == Role::Signer) {
                if (r.signerReq != e.signerReq) {
                    r.signerReq = e.signerReq;
                    sendRaw(r, r.signerReq);
                }
                continue;
            }

            if (r.assignment == e.assignment) continue;
            r.assignment = e.assignment;
            if (r.ws) refreshAssignment(r);
        }
    }


    void tick() {
        uint64_t now = hoytech::curr_time_s();

        try {
            signers.tick(now);
        } catch (std::exception &e) {
            LE << "Banyan harvester: remote signers failed: " << e.what();
        }

        try {
            bool registryChanged = TenantRegistry::get()->universeVersion != lastUniverseVersion;

            if (wakeRequested.exchange(false) || registryChanged || now >= lastPlanAt + cfg().banyan__harvester__replanIntervalSeconds) {
                plan();
            }
        } catch (std::exception &e) {
            LE << "Banyan harvester: planning failed: " << e.what();
        }

        for (auto &res : prober.takeResults()) {
            auto it = relays.find(res.key);
            if (it == relays.end()) continue;
            auto &r = it->second;
            r.probing = false;

            if (res.outcome.result == ProbeResult::Reachable) {
                bool secure = r.url.starts_with("wss://");
                auto parts = parseRelayUrl(r.url);
                auto hp = splitHostPort(parts.host, secure);
                auto *userData = new std::string(r.key);

                r.connecting = true;
                if (!hub.connectPinned(res.outcome.address, res.outcome.port, secure, hp.host, parts.path, userData, 15'000, group, true)) {
                    delete userData;
                    r.connecting = false;
                    r.failures++;
                    r.lastError = "connection failed";
                    r.nextAttemptAt = now + backoffSeconds(r.failures);
                }
            } else if (res.outcome.result == ProbeResult::PrivateAddress) {
                r.lastError = "resolves to a private address";
                r.nextAttemptAt = now + maxBackoffSeconds;
                LW << "Banyan harvester: " << r.url << " resolves to a private address, skipped";
            } else {
                r.failures++;
                r.lastError = "unreachable";
                r.nextAttemptAt = now + backoffSeconds(r.failures);
                LI << "Banyan harvester: " << r.url << " is unreachable, retrying in " << backoffSeconds(r.failures) << "s";
            }
        }

        try {
            distribute(now);
            publishToOutboxes(now);
        } catch (std::exception &e) {
            LE << "Banyan harvester: distribution failed: " << e.what();
        }

        bool housekeeping = now >= lastHousekeepingAt + 60;
        if (housekeeping) {
            lastHousekeepingAt = now;
            if (seenOn.size() > maxSeenOn) seenOn.clear();
            for (auto it = seenOn.begin(); it != seenOn.end(); ) {
                if (it->second.at + seenOnSeconds < now) seenOn.erase(it++);
                else ++it;
            }
        }

        for (auto it = relays.begin(); it != relays.end(); ) {
            auto &r = it->second;

            if (r.deliveryOnly() && !r.hasDeliveryWork() && now > r.lastDeliveryAt + deliveryIdleSeconds && !r.probing) {
                if (r.ws) r.ws->close();
                it = relays.erase(it);
                continue;
            }

            if (housekeeping && !r.ws) {
                uint64_t maxAge = cfg().banyan__distributor__maxAgeSeconds;
                std::erase_if(r.outbox, [&](const Delivery &d){
                    if (d.createdAt + maxAge >= now) return false;
                    r.deliveryIds.erase(d.id);
                    return true;
                });
            }

            ++it;
        }

        for (auto &[relayKey, r] : relays) {
            if (!r.ws && !r.connecting && !r.probing && now >= r.nextAttemptAt) {
                r.probing = true;
                prober.submit(relayKey, r.url);
            }

            bool authPending = r.authState == AuthState::Sent || r.authState == AuthState::Wanted || r.authState == AuthState::Signing;
            uint64_t authTimeout = r.role == Role::Owner ? ownerAuthTimeoutSeconds : authTimeoutSeconds;

            if (r.ws && authPending && now > r.authSentAt + authTimeout) {
                authDone(r, false, r.authState == AuthState::Sent ? "no answer"
                                 : r.authState == AuthState::Signing ? "the remote signer did not answer"
                                 : "auth-required, but no challenge was sent");
            }

            if (r.ws && r.inflight.size()) {
                std::vector<std::string> expired;
                for (const auto &[id, d] : r.inflight) {
                    if (now > d.sentAt + deliveryTimeoutSeconds) expired.push_back(id);
                }
                for (const auto &id : expired) deliveryDone(r, id, false, "no answer");
            }

            if (r.ws) {
                std::vector<std::string> timedOut;
                for (const auto &[subId, req] : r.active) {
                    if (!req.specs[0].live && now > req.startedAt + reqTimeoutSeconds) timedOut.push_back(subId);
                }
                for (const auto &subId : timedOut) {
                    r.lastError = "backfill timed out";
                    closeReq(r, subId);
                }
                if (timedOut.size()) pump(r);
            }
        }

        updateStatus();
    }

    void updateStatus() {
        tao::json::value relaysJson = tao::json::empty_array;

        for (const auto &[relayKey, r] : relays) {
            relaysJson.emplace_back(tao::json::value({
                { "url", r.url },
                { "role", std::string(roleName(r.role)) },
                { "authAs", r.role == Role::Owner ? tao::json::value(to_hex(r.authAs.sv())) : tao::json::value(tao::json::null) },
                { "connected", r.ws != nullptr },
                { "subs", r.active.size() },
                { "queued", r.queue.size() },
                { "authors", r.assignment.authors.size() },
                { "inboxTargets", r.assignment.inbox.size() },
                { "eventsReceived", r.eventsReceived },
                { "auth", std::string(authStateName(r.authState)) },
                { "delivered", r.delivered },
                { "deliveryQueue", r.outbox.size() + r.inflight.size() },
                { "deliveryRejected", r.deliveryRejected },
                { "lastError", r.lastError.size() ? tao::json::value(r.lastError) : tao::json::value(tao::json::null) },
            }));
        }

        std::lock_guard<std::mutex> guard(statusMutex);
        statusJson = tao::json::value({
            { "targets", targets.size() },
            { "relays", std::move(relaysJson) },
            { "delivered", deliveredTotal },
            { "published", publishedTotal },
            { "authPubkey", key ? tao::json::value(to_hex(key->pubkey)) : tao::json::value(tao::json::null) },
        });
    }


    void run() {
        trigger = new uS::Async(hub.getLoop());

        std::function<void()> cb = [&]{ tick(); };
        trigger->setData(&cb);
        trigger->start([](uS::Async *a){
            (*static_cast<std::function<void()>*>(a->getData()))();
        });

        std::thread ticker([this]{
            setThreadName("BanyanTick");
            while (1) {
                std::this_thread::sleep_for(std::chrono::seconds(1));
                trigger->send();
            }
        });
        ticker.detach();

        running = true;
        hub.run();
    }
};


void runHarvester() {
    setThreadName("BanyanHarvest");

    Harvester h;
    h.run();
}


}
