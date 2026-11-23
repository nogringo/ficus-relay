#include <cmath>
#include <condition_variable>
#include <mutex>

#include <hoytech/time.h>
#include <hoytech/hex.h>

#include "TrustEngine.h"
#include "Harvester.h"
#include "DBQuery.h"
#include "events.h"
#include "Decompressor.h"


namespace banyan {


enum class EngagementType { None, Reply, Repost, Reaction, Zap, Mention };

static const std::vector<uint64_t> engagementKinds = { 1, 6, 7, 16, 1111, 9735, 9802, 30023 };

// Upper bounds keep a very popular seed from pinning a read transaction for minutes; newest events come first.
static const uint64_t maxOutgoingEvents = 20'000;
static const uint64_t maxIncomingEvents = 50'000;


static bool hasTag(const PackedEventView &ev, char name) {
    bool found = false;
    ev.foreachTag([&](char tagName, std::string_view){
        if (tagName == name) {
            found = true;
            return false;
        }
        return true;
    });
    return found;
}

static EngagementType classify(const PackedEventView &ev) {
    switch (ev.kind()) {
        case 1: return hasTag(ev, 'e') ? EngagementType::Reply : EngagementType::Mention;
        case 1111: return EngagementType::Reply;
        case 6:
        case 16: return EngagementType::Repost;
        case 7: return EngagementType::Reaction;
        case 9735: return EngagementType::Zap;
        case 9802:
        case 30023: return EngagementType::Mention;
        default: return EngagementType::None;
    }
}

static double weightOf(EngagementType t, const TrustWeights &w) {
    switch (t) {
        case EngagementType::Reply: return w.reply;
        case EngagementType::Repost: return w.repost;
        case EngagementType::Reaction: return w.reaction;
        case EngagementType::Zap: return w.zap;
        case EngagementType::Mention: return w.mention;
        default: return 0;
    }
}

static std::vector<Bytes32> pTags(const PackedEventView &ev, const Bytes32 &exclude) {
    std::vector<Bytes32> output;

    ev.foreachTag([&](char tagName, std::string_view tagVal){
        if (tagName == 'p' && tagVal.size() == 32) {
            Bytes32 pk(tagVal);
            if (pk != exclude && std::find(output.begin(), output.end(), pk) == output.end()) output.push_back(pk);
        }
        return true;
    });

    return output;
}

static std::optional<Bytes32> zapSender(lmdb::txn &txn, Decompressor &decomp, uint64_t levId, const PackedEventView &ev) {
    std::optional<Bytes32> output;

    ev.foreachTag([&](char tagName, std::string_view tagVal){
        if (tagName == 'P' && tagVal.size() == 64) {
            try {
                output = Bytes32(from_hex(tagVal));
            } catch (std::exception &) {
            }
            return false;
        }
        return true;
    });

    if (output) return output;

    // Older zap receipts only carry the sender inside the embedded zap request
    try {
        auto json = tao::json::from_string(getEventJson(txn, decomp, levId));
        for (const auto &tag : json.at("tags").get_array()) {
            const auto &arr = tag.get_array();
            if (arr.size() < 2 || arr[0].get_string() != "description") continue;
            auto zapRequest = tao::json::from_string(arr[1].get_string());
            output = Bytes32(from_hex(zapRequest.at("pubkey").get_string()));
            break;
        }
    } catch (std::exception &) {
    }

    return output;
}

static tao::json::value kindsJson() {
    tao::json::value arr = tao::json::empty_array;
    for (auto k : engagementKinds) arr.emplace_back(k);
    return arr;
}


Engagement computeEngagement(lmdb::txn &txn, const Bytes32 &seed, const TenantSettings &settings, uint64_t now) {
    Engagement eng;
    Decompressor decomp;

    uint64_t window = cfg().banyan__trust__windowDays * 86400;
    uint64_t since = now > window ? now - window : 0;
    double halfLife = (double)cfg().banyan__trust__halfLifeDays * 86400;

    auto decay = [&](uint64_t created){
        if (halfLife <= 0 || created >= now) return 1.0;
        return std::pow(0.5, (double)(now - created) / halfLife);
    };

    std::string seedHex = to_hex(seed.sv());

    foreachByFilter(txn, tao::json::value({
        { "authors", tao::json::value::array({ seedHex }) },
        { "kinds", kindsJson() },
        { "since", since },
        { "limit", maxOutgoingEvents },
    }), [&](uint64_t levId){
        auto ev = lookupEventByLevId(txn, levId);
        PackedEventView packed(ev.buf);

        auto type = classify(packed);
        if (type == EngagementType::None || type == EngagementType::Zap) return;

        auto peers = pTags(packed, seed);
        if (peers.empty()) return;

        double w = weightOf(type, settings.weights) * decay(packed.created_at()) / (double)peers.size();
        for (const auto &p : peers) eng.out[p] += w;
    });

    foreachByFilter(txn, tao::json::value({
        { "kinds", tao::json::value::array({ uint64_t(9735) }) },
        { "#P", tao::json::value::array({ seedHex }) },
        { "since", since },
        { "limit", maxOutgoingEvents },
    }), [&](uint64_t levId){
        auto ev = lookupEventByLevId(txn, levId);
        PackedEventView packed(ev.buf);

        auto recipients = pTags(packed, seed);
        if (recipients.empty()) return;

        double w = settings.weights.zap * decay(packed.created_at()) / (double)recipients.size();
        for (const auto &r : recipients) eng.out[r] += w;
    });

    foreachByFilter(txn, tao::json::value({
        { "#p", tao::json::value::array({ seedHex }) },
        { "kinds", kindsJson() },
        { "since", since },
        { "limit", maxIncomingEvents },
    }), [&](uint64_t levId){
        auto ev = lookupEventByLevId(txn, levId);
        PackedEventView packed(ev.buf);

        auto type = classify(packed);
        if (type == EngagementType::None) return;

        double d = decay(packed.created_at());

        if (type == EngagementType::Zap) {
            auto sender = zapSender(txn, decomp, levId, packed);
            if (!sender || *sender == seed) return;
            eng.in[*sender] += settings.weights.zap * d;
            return;
        }

        Bytes32 author(packed.pubkey());
        if (author == seed) return;

        auto mentioned = pTags(packed, author);
        if (mentioned.empty()) return;

        eng.in[author] += weightOf(type, settings.weights) * d / (double)mentioned.size();
    });

    return eng;
}

std::vector<std::pair<Bytes32, double>> rankPeers(const Engagement &eng, double minScore) {
    std::vector<std::pair<Bytes32, double>> output;

    for (const auto &[peer, out] : eng.out) {
        auto it = eng.in.find(peer);
        if (it == eng.in.end()) continue;

        double score = std::sqrt(out * it->second);
        if (score > 0 && score >= minScore) output.emplace_back(peer, score);
    }

    std::sort(output.begin(), output.end(), [](const auto &a, const auto &b){
        if (a.second != b.second) return a.second > b.second;
        return a.first < b.first;
    });

    return output;
}

std::vector<UniverseMember> computeUniverse(lmdb::txn &txn, const TenantView &tenant, uint64_t now) {
    const auto &st = tenant.settings;

    // Blocked people are filtered when the registry loads, so blocking and unblocking need no recompute
    flat_hash_set<Bytes32> excluded;
    excluded.insert(tenant.pubkey);
    for (const auto &pk : st.pinned) excluded.insert(pk);

    std::vector<UniverseMember> primary;
    flat_hash_set<Bytes32> primarySet;

    for (const auto &[peer, score] : rankPeers(computeEngagement(txn, tenant.pubkey, st, now), st.minScore)) {
        if (primary.size() >= st.primaryCircleSize) break;
        if (excluded.contains(peer)) continue;
        primary.push_back(UniverseMember{ peer, Circle::Primary, score, {} });
        primarySet.insert(peer);
    }

    // Pinned people are trusted by hand, so their own peers count like those of primary members
    std::vector<Bytes32> secondarySeeds;
    for (const auto &m : primary) secondarySeeds.push_back(m.pubkey);
    for (const auto &pk : st.pinned) secondarySeeds.push_back(pk);

    std::vector<UniverseMember> secondary;
    flat_hash_map<Bytes32, size_t> secondaryIndex;

    if (st.secondaryPerPeer > 0) {
        for (const auto &seed : secondarySeeds) {
            uint64_t takenFromSeed = 0;

            for (const auto &[peer, score] : rankPeers(computeEngagement(txn, seed, st, now), st.minScore)) {
                if (takenFromSeed >= st.secondaryPerPeer) break;
                if (excluded.contains(peer) || primarySet.contains(peer)) continue;

                takenFromSeed++;

                if (auto it = secondaryIndex.find(peer); it != secondaryIndex.end()) {
                    auto &m = secondary[it->second];
                    m.score += score;
                    m.via.push_back(seed);
                } else {
                    secondaryIndex[peer] = secondary.size();
                    secondary.push_back(UniverseMember{ peer, Circle::Secondary, score, { seed } });
                }
            }
        }
    }

    std::sort(secondary.begin(), secondary.end(), [](const auto &a, const auto &b){
        if (a.score != b.score) return a.score > b.score;
        return a.pubkey < b.pubkey;
    });

    std::vector<UniverseMember> output = std::move(primary);
    for (auto &m : secondary) output.push_back(std::move(m));

    return output;
}


static std::mutex requestMutex;
static std::condition_variable requestCv;
static flat_hash_set<uint64_t> requestedTenants;
static bool requestedAll = false;

void requestRecompute(uint64_t tenantId) {
    {
        std::lock_guard<std::mutex> guard(requestMutex);
        if (tenantId == 0) requestedAll = true;
        else requestedTenants.insert(tenantId);
    }
    requestCv.notify_one();
}

void runTrustEngine() {
    setThreadName("BanyanTrust");

    const uint64_t minSecondsBetweenRuns = 30;
    flat_hash_map<uint64_t, uint64_t> lastRun;
    flat_hash_set<uint64_t> pending;

    while (1) {
        bool all = false;

        {
            std::unique_lock<std::mutex> lk(requestMutex);
            requestCv.wait_for(lk, std::chrono::seconds(5), [&]{ return requestedAll || requestedTenants.size(); });
            for (auto id : requestedTenants) pending.insert(id);
            requestedTenants.clear();
            all = requestedAll;
            requestedAll = false;
        }

        try {
            TenantRegistry::reload();
            auto snap = TenantRegistry::get();
            bool changed = false;

            if (all) {
                for (const auto &t : snap->tenants) pending.insert(t->id);
            }

            for (const auto &t : snap->tenants) {
                uint64_t now = hoytech::curr_time_s();
                bool due = now >= t->computedAt + cfg().banyan__trust__recomputeIntervalSeconds;
                bool asked = pending.contains(t->id);

                if (!due && !asked) continue;
                if (auto it = lastRun.find(t->id); it != lastRun.end() && now < it->second + minSecondsBetweenRuns) continue;

                auto t0 = hoytech::curr_time_us();
                std::vector<UniverseMember> members;

                {
                    auto txn = env.txn_ro();
                    members = computeUniverse(txn, *t, now);
                }

                {
                    auto txn = env.txn_rw();
                    if (env.lookup_Tenant(txn, t->id)) storeComputedUniverse(txn, t->id, now, members);
                    txn.commit();
                }

                uint64_t numPrimary = std::count_if(members.begin(), members.end(), [](const auto &m){ return m.circle == Circle::Primary; });

                LI << "Banyan: trust universe of " << t->slug << ": " << numPrimary << " primary, "
                   << (members.size() - numPrimary) << " secondary, in " << (hoytech::curr_time_us() - t0) / 1000 << "ms";

                lastRun[t->id] = now;
                pending.erase(t->id);
                changed = true;
            }

            for (auto it = pending.begin(); it != pending.end(); ) {
                if (!snap->findById(*it)) pending.erase(it++);
                else ++it;
            }

            if (changed) {
                TenantRegistry::reload();
                harvesterWake();
            }
        } catch (std::exception &e) {
            LE << "Banyan trust engine error: " << e.what();
        }
    }
}


}
