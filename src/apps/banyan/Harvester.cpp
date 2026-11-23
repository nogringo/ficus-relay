#include <atomic>
#include <condition_variable>
#include <deque>
#include <map>
#include <mutex>
#include <thread>

#include <fcntl.h>
#include <netdb.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <hoytech/time.h>
#include <hoytech/hex.h>
#include <uWebSockets/src/uWS.h>

#include "Harvester.h"
#include "TrustEngine.h"
#include "Tenants.h"
#include "WriterPipeline.h"
#include "DBQuery.h"
#include "Decompressor.h"
#include "events.h"
#include "filters.h"


namespace banyan {


static const std::vector<uint64_t> inboxKinds = { 1, 6, 7, 16, 1111, 9735, 9802, 30023 };
static const uint64_t reqTimeoutSeconds = 60;
static const uint64_t maxPagesPerChain = 1000;
static const uint64_t maxFiltersPerLiveReq = 10;
static const uint64_t maxFutureSeconds = 900;


static std::atomic<bool> wakeRequested = true;
static std::mutex statusMutex;
static tao::json::value statusJson = tao::json::value({ { "targets", 0 }, { "relays", tao::json::empty_array } });

void harvesterWake() {
    wakeRequested = true;
}

tao::json::value harvesterStatus() {
    std::lock_guard<std::mutex> guard(statusMutex);
    return statusJson;
}


static bool isPrivateHost(std::string_view host) {
    if (auto pos = host.rfind(':'); pos != std::string_view::npos && host.find(']') == std::string_view::npos) host = host.substr(0, pos);

    return host == "localhost" || host.empty() || host.starts_with("127.") || host.starts_with("10.") || host.starts_with("192.168.")
        || host.starts_with("0.") || host.starts_with("[") || host.ends_with(".onion") || host.ends_with(".local");
}

// Returns an empty string for URLs the harvester should not use
static std::string normalizeHarvestUrl(std::string_view input) {
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
    if (isPrivateHost(parts.host)) return "";

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
static bool probeTcp(const std::string &url, int timeoutMs) {
    auto parts = parseRelayUrl(url);
    std::string host = parts.host;
    std::string port = url.starts_with("wss://") ? "443" : "80";

    if (auto colon = host.rfind(':'); colon != std::string::npos) {
        port = host.substr(colon + 1);
        host = host.substr(0, colon);
    }

    addrinfo hints{}, *result = nullptr;
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host.c_str(), port.c_str(), &hints, &result) != 0) return false;

    // Same address uWS will use: the first one
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

    freeaddrinfo(result);
    return ok;
}

struct Prober {
    std::mutex mutex;
    std::condition_variable cv;
    std::deque<std::string> pending;
    std::vector<std::pair<std::string, bool>> results;

    Prober(size_t numWorkers) {
        for (size_t i = 0; i < numWorkers; i++) {
            std::thread([this]{
                setThreadName("BanyanProbe");
                while (1) {
                    std::string url;
                    {
                        std::unique_lock<std::mutex> lk(mutex);
                        cv.wait(lk, [&]{ return pending.size() > 0; });
                        url = std::move(pending.front());
                        pending.pop_front();
                    }

                    bool ok = probeTcp(url, 5'000);

                    std::lock_guard<std::mutex> guard(mutex);
                    results.emplace_back(url, ok);
                }
            }).detach();
        }
    }

    void submit(const std::string &url) {
        {
            std::lock_guard<std::mutex> guard(mutex);
            pending.push_back(url);
        }
        cv.notify_one();
    }

    std::vector<std::pair<std::string, bool>> takeResults() {
        std::lock_guard<std::mutex> guard(mutex);
        return std::move(results);
    }
};


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


struct Assignment {
    std::vector<Bytes32> authors; // fetch what they publish
    std::vector<Bytes32> inbox;   // fetch what mentions or zaps them (trust evidence for seeds)
    std::vector<Bytes32> meta;    // fetch their profile and relay list (bootstrap relays only)

    bool operator==(const Assignment &o) const {
        return authors == o.authors && inbox == o.inbox && meta == o.meta;
    }
};

enum class Scope { Authors, Inbox, ZapsSent, Meta };

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

struct Relay {
    std::string url;
    uWS::WebSocket<uWS::CLIENT> *ws = nullptr;
    bool probing = false;
    bool connecting = false;
    uint64_t connectedAt = 0;
    uint64_t nextAttemptAt = 0;
    uint64_t failures = 0;

    Assignment assignment;
    flat_hash_set<Bytes32> backfilledAuthors, backfilledInbox, metaDone;

    std::deque<ReqSpec> queue;
    std::map<std::string, ActiveReq> active;
    uint64_t nextSubId = 1;

    uint64_t eventsReceived = 0;
    std::string lastError;
};


struct Harvester {
    uWS::Hub hub;
    uWS::Group<uWS::CLIENT> *group = nullptr;
    uS::Async *trigger = nullptr;
    WriterPipeline writer;
    Prober prober{8};

    std::map<std::string, Relay> relays;
    flat_hash_map<Bytes32, bool> targets; // pubkey -> is seed
    uint64_t lastPlanAt = 0;
    uint64_t lastSnapshotVersion = 0;

    Harvester() {
        writer.verifyTime = false; // relay lists and profiles are often older than events.rejectEventsOlderThanSeconds
        writer.verboseReject = []{ return false; };
        writer.verboseCommit = []{ return false; };

        group = hub.createGroup<uWS::CLIENT>(uWS::PERMESSAGE_DEFLATE | uWS::SLIDING_DEFLATE_WINDOW);

        group->onConnection([&](uWS::WebSocket<uWS::CLIENT> *ws, uWS::HttpRequest){
            auto *url = (std::string*)ws->getUserData();
            auto it = relays.find(*url);

            if (it == relays.end()) {
                ws->close();
                return;
            }

            auto &r = it->second;
            r.ws = ws;
            r.connecting = false;
            r.connectedAt = hoytech::curr_time_s();
            LI << "Banyan harvester: connected to " << r.url;
            startSession(r);
        });

        group->onDisconnection([&](uWS::WebSocket<uWS::CLIENT> *ws, int code, char *message, size_t length){
            auto *url = (std::string*)ws->getUserData();

            if (auto it = relays.find(*url); it != relays.end() && it->second.ws == ws) {
                auto &r = it->second;
                uint64_t now = hoytech::curr_time_s();
                if (now < r.connectedAt + 60) r.failures++;
                else r.failures = 0;
                r.ws = nullptr;
                r.active.clear();
                r.queue.clear();
                r.nextAttemptAt = now + backoffSeconds(r.failures);
                LI << "Banyan harvester: disconnected from " << r.url << " (" << code << ")";
            }

            delete url;
        });

        group->onError([&](void *userData){
            auto *url = (std::string*)userData;

            if (auto it = relays.find(*url); it != relays.end()) {
                auto &r = it->second;
                r.connecting = false;
                r.failures++;
                r.lastError = "connection failed";
                LI << "Banyan harvester: unable to connect to " << r.url << ", retrying in " << backoffSeconds(r.failures) << "s";
                r.nextAttemptAt = hoytech::curr_time_s() + backoffSeconds(r.failures);
            }

            delete url;
        });

        group->onMessage2([&](uWS::WebSocket<uWS::CLIENT> *ws, char *message, size_t length, uWS::OpCode, size_t){
            auto *url = (std::string*)ws->getUserData();
            auto it = relays.find(*url);
            if (it == relays.end() || it->second.ws != ws) return;

            try {
                handleMessage(it->second, std::string_view(message, length));
            } catch (std::exception &e) {
                it->second.lastError = std::string("bad message: ") + e.what();
            }

            writer.wait();
        });
    }

    static uint64_t backoffSeconds(uint64_t failures) {
        uint64_t delay = 10;
        for (uint64_t i = 0; i < failures && delay < 1800; i++) delay *= 2;
        return std::min<uint64_t>(delay, 1800);
    }


    void send(Relay &r, const tao::json::value &msg) {
        if (!r.ws) return;
        auto str = tao::json::to_string(msg);
        r.ws->send(str.data(), str.size(), uWS::OpCode::TEXT);
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

        std::vector<std::pair<uint64_t, Bytes32>> bySince;

        {
            auto txn = env.txn_ro();
            for (const auto &pk : pks) {
                uint64_t since = defaultSince;
                if (auto st = env.lookup_HarvestState__pubkey(txn, pk.sv())) {
                    uint64_t done = scope == Scope::Authors ? st->authoredBackfilledAt() : st->inboxBackfilledAt();
                    if (done) since = std::max(defaultSince, done > 3600 ? done - 3600 : 0);
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
                spec.since = now;
                spec.pubkeys = std::move(c);
                specs.push_back(std::move(spec));
            }
        };

        add(Scope::Authors, r.assignment.authors);
        add(Scope::Inbox, r.assignment.inbox);
        add(Scope::ZapsSent, r.assignment.inbox);

        for (size_t i = 0; i < specs.size(); i += maxFiltersPerLiveReq) {
            std::vector<ReqSpec> group(std::make_move_iterator(specs.begin() + i), std::make_move_iterator(specs.begin() + std::min<size_t>(specs.size(), i + maxFiltersPerLiveReq)));
            openReq(r, std::move(group));
        }
    }

    void enqueueMissingWork(Relay &r) {
        flat_hash_set<Bytes32> pendingMeta, pendingAuthors, pendingInbox;

        auto collect = [&](const ReqSpec &spec){
            if (spec.live) return;
            auto *set = spec.scope == Scope::Meta ? &pendingMeta : spec.scope == Scope::Authors ? &pendingAuthors : spec.scope == Scope::Inbox ? &pendingInbox : nullptr;
            if (set) set->insert(spec.pubkeys.begin(), spec.pubkeys.end());
        };

        for (const auto &spec : r.queue) collect(spec);
        for (const auto &[subId, req] : r.active) {
            for (const auto &spec : req.specs) collect(spec);
        }

        std::vector<Bytes32> meta, authors, inbox;

        for (const auto &pk : r.assignment.meta) {
            if (!r.metaDone.contains(pk) && !pendingMeta.contains(pk)) meta.push_back(pk);
        }
        for (const auto &pk : r.assignment.authors) {
            if (!r.backfilledAuthors.contains(pk) && !pendingAuthors.contains(pk)) authors.push_back(pk);
        }
        for (const auto &pk : r.assignment.inbox) {
            if (!r.backfilledInbox.contains(pk) && !pendingInbox.contains(pk)) inbox.push_back(pk);
        }

        // Relay lists first: they decide where everything else is fetched from
        for (auto &c : chunk(meta)) {
            ReqSpec spec;
            spec.scope = Scope::Meta;
            spec.pubkeys = std::move(c);
            r.queue.push_front(std::move(spec));
        }

        enqueueBackfill(r, Scope::Authors, authors);
        enqueueBackfill(r, Scope::Inbox, inbox);
    }

    void startSession(Relay &r) {
        r.active.clear();
        r.queue.clear();
        enqueueMissingWork(r);
        openLiveReqs(r);
        pump(r);
    }

    void refreshAssignment(Relay &r) {
        std::vector<std::string> liveSubs;
        for (const auto &[subId, req] : r.active) {
            if (req.specs[0].live) liveSubs.push_back(subId);
        }
        for (const auto &subId : liveSubs) closeReq(r, subId);

        enqueueMissingWork(r);
        openLiveReqs(r);
        pump(r);
    }


    void markBackfilled(const std::vector<Bytes32> &pks, Scope scope, uint64_t at) {
        auto txn = env.txn_rw();

        for (const auto &pk : pks) {
            auto st = env.lookup_HarvestState__pubkey(txn, pk.sv());

            if (st) {
                defaultDb::environment::Updates_HarvestState upd;
                if (scope == Scope::Authors) upd.authoredBackfilledAt = at;
                else upd.inboxBackfilledAt = at;
                env.update_HarvestState(txn, *st, upd);
            } else {
                env.insert_HarvestState(txn, pk.sv(), scope == Scope::Authors ? at : 0, scope == Scope::Authors ? 0 : at);
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

        if (spec.scope == Scope::ZapsSent) return;

        auto &done = spec.scope == Scope::Authors ? r.backfilledAuthors : r.backfilledInbox;
        for (const auto &pk : spec.pubkeys) done.insert(pk);

        try {
            markBackfilled(spec.pubkeys, spec.scope, spec.chainStartedAt);
        } catch (std::exception &e) {
            LE << "Banyan harvester: unable to store backfill progress: " << e.what();
        }

        requestRecompute(0);
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
            if (packed.created_at() > hoytech::curr_time_s() + maxFutureSeconds) return;

            req.received++;
            if (packed.created_at() < req.oldest) req.oldest = packed.created_at();
            r.eventsReceived++;

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
            r.lastError = arr.size() >= 3 && arr[2].is_string() ? arr[2].get_string() : "closed by relay";
            r.active.erase(it);
            pump(r);
        } else if (type == "NOTICE") {
            r.lastError = arr[1].is_string() ? arr[1].get_string() : "notice";
        }
    }


    void plan() {
        auto snap = TenantRegistry::get();
        lastSnapshotVersion = snap->version;
        lastPlanAt = hoytech::curr_time_s();

        targets.clear();
        for (const auto &t : snap->tenants) {
            for (const auto &m : t->members) targets[m.pubkey] = targets[m.pubkey] || t->isSeed(m);
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
        }

        // Prefer relays many targets share, so the same few connections cover most of the universe
        auto pick = [&](const std::vector<std::string> &candidates){
            std::vector<std::string> sorted = candidates;
            std::stable_sort(sorted.begin(), sorted.end(), [&](const auto &a, const auto &b){ return popularity[a] > popularity[b]; });
            if (sorted.size() > cfg().banyan__harvester__relaysPerPubkey) sorted.resize(cfg().banyan__harvester__relaysPerPubkey);
            return sorted;
        };

        std::map<std::string, Assignment> plan;

        for (const auto &[pk, seed] : targets) {
            const auto &rl = lists[pk];

            for (const auto &url : pick(rl.write.size() ? rl.write : bootstrap)) plan[url].authors.push_back(pk);

            if (seed) {
                for (const auto &url : pick(rl.read.size() ? rl.read : bootstrap)) plan[url].inbox.push_back(pk);
            }

            if (!rl.found) {
                for (const auto &url : bootstrap) plan[url].meta.push_back(pk);
            }
        }

        capRelays(plan, bootstrap);

        for (auto &[url, a] : plan) {
            std::sort(a.authors.begin(), a.authors.end());
            std::sort(a.inbox.begin(), a.inbox.end());
            std::sort(a.meta.begin(), a.meta.end());
        }

        apply(plan);
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

    void apply(const std::map<std::string, Assignment> &plan) {
        for (auto it = relays.begin(); it != relays.end(); ) {
            if (plan.contains(it->first)) {
                ++it;
                continue;
            }

            if (it->second.ws) it->second.ws->close();
            it = relays.erase(it);
        }

        for (const auto &[url, a] : plan) {
            auto [it, isNew] = relays.try_emplace(url);
            auto &r = it->second;
            if (isNew) r.url = url;

            if (r.assignment == a) continue;
            r.assignment = a;
            if (r.ws) refreshAssignment(r);
        }
    }


    void tick() {
        uint64_t now = hoytech::curr_time_s();

        try {
            bool registryChanged = TenantRegistry::get()->version != lastSnapshotVersion;

            if (wakeRequested.exchange(false) || registryChanged || now >= lastPlanAt + cfg().banyan__harvester__replanIntervalSeconds) {
                plan();
            }
        } catch (std::exception &e) {
            LE << "Banyan harvester: planning failed: " << e.what();
        }

        for (auto &[url, reachable] : prober.takeResults()) {
            auto it = relays.find(url);
            if (it == relays.end()) continue;
            auto &r = it->second;
            r.probing = false;

            if (reachable) {
                r.connecting = true;
                hub.connect(url, (void*)new std::string(url), {}, 15'000, group);
            } else {
                r.failures++;
                r.lastError = "unreachable";
                r.nextAttemptAt = now + backoffSeconds(r.failures);
                LI << "Banyan harvester: " << url << " is unreachable, retrying in " << backoffSeconds(r.failures) << "s";
            }
        }

        for (auto &[url, r] : relays) {
            if (!r.ws && !r.connecting && !r.probing && now >= r.nextAttemptAt) {
                r.probing = true;
                prober.submit(url);
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

        for (const auto &[url, r] : relays) {
            relaysJson.emplace_back(tao::json::value({
                { "url", url },
                { "connected", r.ws != nullptr },
                { "subs", r.active.size() },
                { "queued", r.queue.size() },
                { "authors", r.assignment.authors.size() },
                { "inboxTargets", r.assignment.inbox.size() },
                { "eventsReceived", r.eventsReceived },
                { "lastError", r.lastError.size() ? tao::json::value(r.lastError) : tao::json::value(tao::json::null) },
            }));
        }

        std::lock_guard<std::mutex> guard(statusMutex);
        statusJson = tao::json::value({
            { "targets", targets.size() },
            { "relays", std::move(relaysJson) },
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

        hub.run();
    }
};


void runHarvester() {
    setThreadName("BanyanHarvest");

    Harvester h;
    h.run();
}


}
