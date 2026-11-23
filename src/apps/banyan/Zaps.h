#pragma once

#include <optional>
#include <string_view>
#include <vector>

#include "golpe.h"

#include "Bytes32.h"


namespace banyan {


// Amount of a bolt11 invoice, from its human-readable part. nullopt for invoices without an amount.
std::optional<uint64_t> bolt11AmountMsats(std::string_view invoice);

// How many zaps one receipt counts as: 1 at banyan.trust.zapReferenceSats, about one more each time the amount doubles
double zapUnits(uint64_t msats);

enum class ZapperCheck { Valid, Invalid, Unknown };

// NIP-57: a receipt is genuine when signed by the nostrPubkey of the recipient's LNURL server
ZapperCheck checkZapper(lmdb::txn &txn, const Bytes32 &recipient, const Bytes32 &receiptSigner);

// Receipts the trust engine could not check yet, with the seeds whose engagement they change
void noteUnresolvedZapper(const Bytes32 &recipient, const Bytes32 &seed);
flat_hash_map<Bytes32, flat_hash_set<Bytes32>> takeUnresolvedZappers();

struct ZapperResolution {
    std::vector<Bytes32> changed;         // their known nostrPubkeys changed
    std::vector<Bytes32> missingProfiles; // no kind 0 stored, so no lud16 or lud06 to follow
    std::vector<Bytes32> failed;          // LNURL server unreachable or invalid answer
};

// Blocking: reads each recipient's profile, asks their LNURL server, and stores what it answers
ZapperResolution resolveZapperKeys(const std::vector<Bytes32> &recipients);

void runZapResolver();


}
