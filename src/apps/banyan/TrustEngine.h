#pragma once

#include <vector>

#include "Tenants.h"


namespace banyan {


struct Engagement {
    flat_hash_map<Bytes32, double> out; // seed -> peer
    flat_hash_map<Bytes32, double> in;  // peer -> seed
};

Engagement computeEngagement(lmdb::txn &txn, const Bytes32 &seed, const TenantSettings &settings, uint64_t now);

// Mutual score: geometric mean of both directions, so one-sided attention scores zero
std::vector<std::pair<Bytes32, double>> rankPeers(const Engagement &eng, double minScore);

// Primary and secondary circles of a tenant, computed from the events already in the DB
std::vector<UniverseMember> computeUniverse(lmdb::txn &txn, const TenantView &tenant, uint64_t now);

void runTrustEngine();

// 0 means every tenant
void requestRecompute(uint64_t tenantId);


}
