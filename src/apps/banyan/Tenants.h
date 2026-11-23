#pragma once

#include <memory>
#include <string>
#include <vector>

#include <tao/json.hpp>

#include "golpe.h"

#include "Bytes32.h"
#include "PackedEvent.h"


namespace banyan {


enum class Circle : uint8_t {
    Owner = 0,
    Pinned = 1,
    Primary = 2,
    Secondary = 3,
};

std::string_view circleName(Circle c);
Circle parseCircle(std::string_view s);


struct TrustWeights {
    double reply = 0;
    double repost = 0;
    double reaction = 0;
    double zap = 0;
    double mention = 0;
};

struct TenantSettings {
    TrustWeights weights;
    uint64_t primaryCircleSize = 0;
    uint64_t secondaryPerPeer = 0;
    double minScore = 0;
    std::vector<Bytes32> pinned;
    std::vector<Bytes32> blocked;

    // Stored settings only hold explicit overrides, so config defaults keep applying to the rest.
    static TenantSettings effective(std::string_view storedJson);
    static std::string mergePatch(std::string_view storedJson, const tao::json::value &patch);

    tao::json::value toJson() const;
    bool isBlocked(const Bytes32 &pk) const;
};


struct UniverseMember {
    Bytes32 pubkey;
    Circle circle;
    double score = 0;
    std::vector<Bytes32> via;
};

std::string serializeComputedMembers(const std::vector<UniverseMember> &members);
std::vector<UniverseMember> parseComputedMembers(std::string_view json);


struct TenantView {
    uint64_t id = 0;
    Bytes32 pubkey;
    std::string slug;
    std::string npub;
    uint64_t addedAt = 0;
    std::string settingsJson;
    TenantSettings settings;
    uint64_t computedAt = 0;

    std::vector<UniverseMember> members; // owner first, then pinned, primary, secondary
    flat_hash_set<Bytes32> universe;

    // Pruning keeps these too: blocked people and those reached only through them, so unblocking stays immediate
    flat_hash_set<Bytes32> retained;
    // Whose incoming engagement the trust engine reads: owner, pinned and primary, blocked ones included
    flat_hash_set<Bytes32> trustSeeds;

    bool inUniverse(std::string_view pubkey) const {
        return universe.contains(Bytes32(pubkey));
    }

    bool isGiftWrapForOwner(const PackedEventView &ev) const;

    bool canSee(const PackedEventView &ev) const {
        return inUniverse(ev.pubkey()) || isGiftWrapForOwner(ev);
    }

    // Also accepts, without serving them, what the trust engine needs from people outside the universe
    bool canWrite(lmdb::txn &txn, const PackedEventView &ev) const;

    // The owner, pinned and primary members are seeds: the harvester also fetches the
    // events that mention them, because that is where incoming engagement comes from.
    bool isSeed(const UniverseMember &m) const {
        return m.circle != Circle::Secondary;
    }

    size_t countCircle(Circle c) const;
};

using TenantPtr = std::shared_ptr<const TenantView>;


struct TenantSnapshot {
    uint64_t version = 0;
    std::vector<TenantPtr> tenants;
    flat_hash_map<uint64_t, TenantPtr> byId;
    flat_hash_map<std::string, TenantPtr> byPath; // slug and npub

    TenantPtr findById(uint64_t id) const {
        auto it = byId.find(id);
        return it == byId.end() ? nullptr : it->second;
    }

    TenantPtr findByPath(std::string_view path) const {
        auto it = byPath.find(std::string(path));
        return it == byPath.end() ? nullptr : it->second;
    }
};

using SnapshotPtr = std::shared_ptr<const TenantSnapshot>;


struct TenantRegistry {
    static SnapshotPtr get();
    static void reload();
};


// Helpers shared by the relay, the admin API and the CLI

Bytes32 parsePubkey(std::string_view input);
std::string toNpub(const Bytes32 &pk);

void validateSlug(std::string_view slug);

struct RelayUrlParts {
    std::string host;
    std::string path; // without leading or trailing slashes
};

RelayUrlParts parseRelayUrl(std::string_view url);

// Returns the request path without query string, leading or trailing slashes
std::string normalizePath(std::string_view url);

std::optional<defaultDb::environment::View_Tenant> findTenant(lmdb::txn &txn, std::string_view slugOrPubkey);

uint64_t addTenant(lmdb::txn &txn, const Bytes32 &pubkey, std::string_view slug);
void removeTenant(lmdb::txn &txn, uint64_t tenantId);
void updateTenant(lmdb::txn &txn, uint64_t tenantId, const tao::json::value &patch);
void storeComputedUniverse(lmdb::txn &txn, uint64_t tenantId, uint64_t computedAt, const std::vector<UniverseMember> &members);

flat_hash_set<Bytes32> parsePubkeyList(std::string_view commaSeparated);


}
