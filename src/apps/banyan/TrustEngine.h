#pragma once

#include <array>
#include <vector>

#include "Tenants.h"


namespace banyan {


enum class EngagementType : uint8_t { Reply, Repost, Reaction, Zap, Mention, None };

static constexpr size_t numEngagementTypes = size_t(EngagementType::None);

// Decayed engagement between a seed and one peer, per type, before the tenant's weights are applied
struct PeerEngagement {
    Bytes32 peer;
    std::array<double, numEngagementTypes> out{}; // seed -> peer
    std::array<double, numEngagementTypes> in{};  // peer -> seed
};

// Kinds read as engagement, zap receipts included
bool isEngagementKind(uint64_t kind);

// Oldest created_at the trust engine reads (banyan.trust.windowDays)
uint64_t trustWindowStart(uint64_t now);

// What the trust engine reads about these seeds, whoever the author: engagement since trustSince
// that p-tags one of them, or a zap receipt one of them sent (P)
bool isEngagementWith(const PackedEventView &ev, const flat_hash_set<Bytes32> &seeds, uint64_t trustSince);

// Only peers with engagement in both directions, since the others always score zero
std::vector<PeerEngagement> computeEngagement(const Bytes32 &seed, uint64_t now);

// Mutual score: sqrt(out * min(in, out)). Only out is signed by the seed, so inflating in never lifts a peer above the seed's own engagement.
std::vector<std::pair<Bytes32, double>> rankPeers(const std::vector<PeerEngagement> &engagement, const TrustWeights &weights, double minScore);

struct CachedEngagement {
    uint64_t computedAt = 0;
    std::vector<PeerEngagement> peers;
};

// Engagement is independent of tenant settings, so a seed shared by several tenants is computed once
using EngagementCache = flat_hash_map<Bytes32, CachedEngagement>;

// Primary and secondary circles of a tenant, computed from the events already in the DB
std::vector<UniverseMember> computeUniverse(const TenantView &tenant, uint64_t now, EngagementCache &cache);

void runTrustEngine();

// 0 means every tenant
void requestRecompute(uint64_t tenantId);

// The harvester fetched new history for these pubkeys: drops their cached engagement and recomputes the tenants they are seeds of
void notifyEngagementChanged(const std::vector<Bytes32> &pubkeys);


}
