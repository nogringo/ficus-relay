#include <cmath>
#include <condition_variable>
#include <mutex>

#include <secp256k1_schnorrsig.h>
#include <hoytech/time.h>
#include <hoytech/hex.h>

#include "TrustEngine.h"
#include "Harvester.h"
#include "DBQuery.h"
#include "events.h"
#include "Decompressor.h"
#include "Zaps.h"


namespace banyan {


// Zap receipts (9735) are signed by neither side of the zap, so they are read separately
static const std::vector<uint64_t> engagementKinds = { 1, 6, 7, 16, 1111, 9802, 30023 };

// Upper bounds keep a very popular seed from pinning a read transaction for minutes; newest events come first.
static const uint64_t maxOutgoingEvents = 20'000;
static const uint64_t maxIncomingEvents = 50'000;
static const uint64_t maxZapReceipts = 20'000;

static const uint64_t engagementCacheSeconds = 600;


bool isEngagementKind(uint64_t kind) {
    return kind == 9735 || std::find(engagementKinds.begin(), engagementKinds.end(), kind) != engagementKinds.end();
}

uint64_t trustWindowStart(uint64_t now) {
    uint64_t window = cfg().banyan__trust__windowDays * 86400;
    return now > window ? now - window : 0;
}

// P tags are stored as hex, unlike p tags
static std::optional<Bytes32> hexPubkey(std::string_view hex) {
    if (hex.size() != 64) return std::nullopt;

    try {
        return Bytes32(from_hex(hex, false));
    } catch (std::exception &) {
        return std::nullopt;
    }
}

bool isEngagementWith(const PackedEventView &ev, const flat_hash_set<Bytes32> &seeds, uint64_t trustSince) {
    if (!isEngagementKind(ev.kind()) || ev.created_at() < trustSince) return false;

    bool found = false;

    ev.foreachTag([&](char tagName, std::string_view tagVal){
        if (tagName == 'p' && tagVal.size() == 32) {
            found = seeds.contains(Bytes32(tagVal));
        } else if (tagName == 'P' && ev.kind() == 9735) {
            auto sender = hexPubkey(tagVal);
            found = sender && seeds.contains(*sender);
        }
        return !found;
    });

    return found;
}


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

static double weighted(const std::array<double, numEngagementTypes> &v, const TrustWeights &w) {
    double total = 0;
    for (size_t i = 0; i < numEngagementTypes; i++) total += v[i] * weightOf(EngagementType(i), w);
    return total;
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

static std::optional<Bytes32> firstPTag(const PackedEventView &ev) {
    std::optional<Bytes32> output;

    ev.foreachTag([&](char tagName, std::string_view tagVal){
        if (tagName == 'p' && tagVal.size() == 32) {
            output = Bytes32(tagVal);
            return false;
        }
        return true;
    });

    return output;
}

static secp256k1_context *verifyCtx() {
    static secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);
    return ctx;
}

struct Zap {
    std::string requestId;
    Bytes32 sender;
    Bytes32 recipient;
    Bytes32 receiptSigner;
    uint64_t msats = 0;
};

// NIP-57: anyone can publish a receipt, so only the zap request it embeds, signed by the sender, says who zapped whom.
// Whether the zap was paid is checked separately: the receipt must come from the recipient's LNURL server.
static std::optional<Zap> parseZapReceipt(lmdb::txn &txn, Decompressor &decomp, uint64_t levId, const PackedEventView &receipt) {
    auto receiptRecipient = firstPTag(receipt);
    if (!receiptRecipient) return std::nullopt;

    try {
        auto json = tao::json::from_string(getEventJson(txn, decomp, levId));
        std::optional<std::string> description;
        std::optional<uint64_t> msats;

        for (const auto &tag : json.at("tags").get_array()) {
            const auto &arr = tag.get_array();
            if (arr.size() < 2 || !arr[0].is_string() || !arr[1].is_string()) continue;
            if (arr[0].get_string() == "description" && !description) description = arr[1].get_string();
            else if (arr[0].get_string() == "bolt11" && !msats) msats = bolt11AmountMsats(arr[1].get_string());
        }

        if (!description || !msats) return std::nullopt;

        std::string packedStr, jsonStr;
        auto requestJson = tao::json::from_string(*description);
        parseAndVerifyEvent(requestJson, verifyCtx(), true, false, packedStr, jsonStr);
        PackedEventView request(packedStr);

        if (request.kind() != 9734) return std::nullopt;
        if (firstPTag(request) != receiptRecipient) return std::nullopt;

        for (const auto &tag : requestJson.at("tags").get_array()) {
            const auto &arr = tag.get_array();
            if (arr.size() < 2 || !arr[0].is_string() || arr[0].get_string() != "amount" || !arr[1].is_string()) continue;
            if (arr[1].get_string() != std::to_string(*msats)) return std::nullopt;
        }

        return Zap{ std::string(request.id()), Bytes32(request.pubkey()), *receiptRecipient, Bytes32(receipt.pubkey()), *msats };
    } catch (std::exception &) {
    }

    return std::nullopt;
}

// Receipts that can't be checked yet are left out, and the seed is recomputed once the recipient's LNURL answered
static bool genuineZap(lmdb::txn &txn, const Zap &zap, const Bytes32 &seed) {
    if (!cfg().banyan__trust__verifyZapReceipts) return true;

    switch (checkZapper(txn, zap.recipient, zap.receiptSigner)) {
        case ZapperCheck::Valid: return true;
        case ZapperCheck::Invalid: return false;
        case ZapperCheck::Unknown:
            noteUnresolvedZapper(zap.recipient, seed);
            return false;
    }

    return false;
}

static tao::json::value uintArray(const std::vector<uint64_t> &v) {
    tao::json::value arr = tao::json::empty_array;
    for (auto n : v) arr.emplace_back(n);
    return arr;
}


std::vector<PeerEngagement> computeEngagement(const Bytes32 &seed, uint64_t now) {
    uint64_t since = trustWindowStart(now);
    double halfLife = (double)cfg().banyan__trust__halfLifeDays * 86400;

    auto decay = [&](uint64_t created){
        if (halfLife <= 0 || created >= now) return 1.0;
        return std::pow(0.5, (double)(now - created) / halfLife);
    };

    flat_hash_map<Bytes32, PeerEngagement> peers;

    auto entry = [&](const Bytes32 &pk) -> PeerEngagement & {
        auto &e = peers[pk];
        e.peer = pk;
        return e;
    };

    std::string seedHex = to_hex(seed.sv());
    auto txn = env.txn_ro();
    Decompressor decomp;

    foreachByFilter(txn, tao::json::value({
        { "authors", tao::json::value::array({ seedHex }) },
        { "kinds", uintArray(engagementKinds) },
        { "since", since },
        { "limit", maxOutgoingEvents },
    }), [&](uint64_t levId){
        auto ev = lookupEventByLevId(txn, levId);
        PackedEventView packed(ev.buf);

        auto type = classify(packed);
        if (type == EngagementType::None) return;

        auto mentioned = pTags(packed, seed);
        if (mentioned.empty()) return;

        double w = decay(packed.created_at()) / (double)mentioned.size();
        for (const auto &p : mentioned) entry(p).out[size_t(type)] += w;
    });

    flat_hash_set<std::string> seenZapRequests;

    struct OutgoingZap {
        Zap zap;
        double weight;
    };

    std::vector<OutgoingZap> outgoingZaps;

    foreachByFilter(txn, tao::json::value({
        { "kinds", tao::json::value::array({ uint64_t(9735) }) },
        { "#P", tao::json::value::array({ seedHex }) },
        { "since", since },
        { "limit", maxZapReceipts },
    }), [&](uint64_t levId){
        auto ev = lookupEventByLevId(txn, levId);
        PackedEventView packed(ev.buf);

        auto zap = parseZapReceipt(txn, decomp, levId, packed);
        if (!zap || zap->sender != seed || zap->recipient == seed) return;
        if (!seenZapRequests.insert(zap->requestId).second) return;

        outgoingZaps.push_back(OutgoingZap{ *zap, decay(packed.created_at()) * zapUnits(zap->msats) });
    });

    if (peers.empty() && outgoingZaps.empty()) return {};

    // Peers the seed never engaged with score zero, so they are left out of the scan itself:
    // a flood of mentions from strangers can't push real engagement past the limit.
    flat_hash_set<Bytes32> candidateSet;
    for (const auto &[pk, e] : peers) candidateSet.insert(pk);
    for (const auto &z : outgoingZaps) candidateSet.insert(z.zap.recipient);

    tao::json::value candidates = tao::json::empty_array;
    for (const auto &pk : candidateSet) candidates.emplace_back(to_hex(pk.sv()));

    foreachByFilter(txn, tao::json::value({
        { "#p", tao::json::value::array({ seedHex }) },
        { "authors", candidates },
        { "kinds", uintArray(engagementKinds) },
        { "since", since },
        { "limit", maxIncomingEvents },
    }), [&](uint64_t levId){
        auto ev = lookupEventByLevId(txn, levId);
        PackedEventView packed(ev.buf);

        auto type = classify(packed);
        if (type == EngagementType::None) return;

        Bytes32 author(packed.pubkey());
        auto mentioned = pTags(packed, author);
        if (mentioned.empty()) return;

        entry(author).in[size_t(type)] += decay(packed.created_at()) / (double)mentioned.size();
    });

    foreachByFilter(txn, tao::json::value({
        { "kinds", tao::json::value::array({ uint64_t(9735) }) },
        { "#p", tao::json::value::array({ seedHex }) },
        { "#P", candidates },
        { "since", since },
        { "limit", maxZapReceipts },
    }), [&](uint64_t levId){
        auto ev = lookupEventByLevId(txn, levId);
        PackedEventView packed(ev.buf);

        auto zap = parseZapReceipt(txn, decomp, levId, packed);
        if (!zap || zap->recipient != seed || zap->sender == seed || !candidateSet.contains(zap->sender)) return;
        if (!seenZapRequests.insert(zap->requestId).second) return;
        if (!genuineZap(txn, *zap, seed)) return;

        entry(zap->sender).in[size_t(EngagementType::Zap)] += decay(packed.created_at()) * zapUnits(zap->msats);
    });

    // Checked last, and only for mutual peers: the others score zero anyway, and checking means asking their LNURL server
    for (const auto &z : outgoingZaps) {
        auto it = peers.find(z.zap.recipient);
        if (it == peers.end() || std::none_of(it->second.in.begin(), it->second.in.end(), [](double v){ return v > 0; })) continue;
        if (!genuineZap(txn, z.zap, seed)) continue;
        it->second.out[size_t(EngagementType::Zap)] += z.weight;
    }

    std::vector<PeerEngagement> output;

    for (const auto &[pk, e] : peers) {
        bool mutual = std::any_of(e.in.begin(), e.in.end(), [](double v){ return v > 0; });
        if (mutual) output.push_back(e);
    }

    return output;
}

std::vector<std::pair<Bytes32, double>> rankPeers(const std::vector<PeerEngagement> &engagement, const TrustWeights &weights, double minScore) {
    std::vector<std::pair<Bytes32, double>> output;

    for (const auto &e : engagement) {
        double out = weighted(e.out, weights);
        double in = weighted(e.in, weights);

        double score = std::sqrt(out * std::min(in, out));
        if (score > 0 && score >= minScore) output.emplace_back(e.peer, score);
    }

    std::sort(output.begin(), output.end(), [](const auto &a, const auto &b){
        if (a.second != b.second) return a.second > b.second;
        return a.first < b.first;
    });

    return output;
}

std::vector<UniverseMember> computeUniverse(const TenantView &tenant, uint64_t now, EngagementCache &cache) {
    const auto &st = tenant.settings;

    auto ranked = [&](const Bytes32 &seed){
        auto it = cache.find(seed);

        if (it == cache.end() || now >= it->second.computedAt + engagementCacheSeconds) {
            auto &c = cache[seed];
            c.computedAt = now;
            c.peers = computeEngagement(seed, now);
            return rankPeers(c.peers, st.weights, st.minScore);
        }

        return rankPeers(it->second.peers, st.weights, st.minScore);
    };

    flat_hash_set<Bytes32> excluded;
    excluded.insert(tenant.pubkey);
    for (const auto &pk : st.pinned) excluded.insert(pk);

    // Blocked people take no slot but stay in the stored list: the registry hides them when it loads, so unblocking is immediate
    std::vector<UniverseMember> primary;
    flat_hash_set<Bytes32> primarySet;
    uint64_t primaryTaken = 0;

    for (const auto &[peer, score] : ranked(tenant.pubkey)) {
        if (primaryTaken >= st.primaryCircleSize) break;
        if (excluded.contains(peer)) continue;
        primary.push_back(UniverseMember{ peer, Circle::Primary, score, {} });
        primarySet.insert(peer);
        if (!st.isBlocked(peer)) primaryTaken++;
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

            for (const auto &[peer, score] : ranked(seed)) {
                if (takenFromSeed >= st.secondaryPerPeer) break;
                if (excluded.contains(peer) || primarySet.contains(peer)) continue;

                if (!st.isBlocked(peer)) takenFromSeed++;

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
static flat_hash_set<Bytes32> changedPubkeys;
static bool requestedAll = false;

void requestRecompute(uint64_t tenantId) {
    {
        std::lock_guard<std::mutex> guard(requestMutex);
        if (tenantId == 0) requestedAll = true;
        else requestedTenants.insert(tenantId);
    }
    requestCv.notify_one();
}

void notifyEngagementChanged(const std::vector<Bytes32> &pubkeys) {
    {
        std::lock_guard<std::mutex> guard(requestMutex);
        changedPubkeys.insert(pubkeys.begin(), pubkeys.end());
    }
    requestCv.notify_one();
}

void runTrustEngine() {
    setThreadName("BanyanTrust");

    const uint64_t minSecondsBetweenRuns = 30;
    flat_hash_map<uint64_t, uint64_t> lastRun;
    flat_hash_set<uint64_t> pending;
    flat_hash_set<Bytes32> changed;
    EngagementCache cache;

    while (1) {
        bool all = false;

        {
            std::unique_lock<std::mutex> lk(requestMutex);
            requestCv.wait_for(lk, std::chrono::seconds(5), [&]{ return requestedAll || requestedTenants.size() || changedPubkeys.size(); });
            for (auto id : requestedTenants) pending.insert(id);
            requestedTenants.clear();
            changed.insert(changedPubkeys.begin(), changedPubkeys.end());
            changedPubkeys.clear();
            all = requestedAll;
            requestedAll = false;
        }

        try {
            TenantRegistry::reload();
            auto snap = TenantRegistry::get();
            uint64_t now = hoytech::curr_time_s();
            bool universeChanged = false;

            for (const auto &pk : changed) cache.erase(pk);

            for (const auto &t : snap->tenants) {
                if (all) pending.insert(t->id);

                for (const auto &m : t->members) {
                    if (t->isSeed(m) && changed.contains(m.pubkey)) {
                        pending.insert(t->id);
                        break;
                    }
                }
            }

            changed.clear();

            for (auto it = cache.begin(); it != cache.end(); ) {
                if (now >= it->second.computedAt + engagementCacheSeconds) cache.erase(it++);
                else ++it;
            }

            for (const auto &t : snap->tenants) {
                bool due = now >= t->computedAt + cfg().banyan__trust__recomputeIntervalSeconds;
                bool asked = pending.contains(t->id);

                if (!due && !asked) continue;
                if (auto it = lastRun.find(t->id); it != lastRun.end() && now < it->second + minSecondsBetweenRuns) continue;

                auto t0 = hoytech::curr_time_us();
                auto members = computeUniverse(*t, now, cache);

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
                universeChanged = true;
            }

            for (auto it = pending.begin(); it != pending.end(); ) {
                if (!snap->findById(*it)) pending.erase(it++);
                else ++it;
            }

            if (universeChanged) {
                TenantRegistry::reload();
                harvesterWake();
            }
        } catch (std::exception &e) {
            LE << "Banyan trust engine error: " << e.what();
        }
    }
}


}
