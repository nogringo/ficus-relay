#include <thread>

#include <hoytech/time.h>
#include <hoytech/hex.h>

#include "Pruner.h"
#include "Tenants.h"
#include "TrustEngine.h"
#include "events.h"


namespace banyan {


static const size_t deleteBatchSize = 10'000;


struct KeepRules {
    flat_hash_set<Bytes32> authors;
    flat_hash_set<Bytes32> giftWrapRecipients;
    flat_hash_set<Bytes32> seeds;
    flat_hash_set<std::string> seedsHex; // P tags are stored as hex, p tags as bytes
    uint64_t trustSince = 0;

    KeepRules(const TenantSnapshot &snap, uint64_t now) {
        uint64_t window = cfg().banyan__trust__windowDays * 86400;
        trustSince = now > window ? now - window : 0;

        for (const auto &t : snap.tenants) {
            authors.insert(t->retained.begin(), t->retained.end());
            seeds.insert(t->trustSeeds.begin(), t->trustSeeds.end());
            if (cfg().banyan__acceptGiftWrapsForOwner) giftWrapRecipients.insert(t->pubkey);
        }

        for (const auto &pk : seeds) seedsHex.insert(to_hex(pk.sv()));
    }

    // For events whose author is in no universe: gift wraps for an owner, and engagement the trust engine reads
    bool keepOther(const PackedEventView &ev) const {
        uint64_t kind = ev.kind();
        bool giftWrap = kind == 1059 || kind == 21059;
        bool evidence = isEngagementKind(kind) && ev.created_at() >= trustSince;
        if (!giftWrap && !evidence) return false;

        bool found = false;

        ev.foreachTag([&](char tagName, std::string_view tagVal){
            if (tagName == 'p' && tagVal.size() == 32) found = (giftWrap ? giftWrapRecipients : seeds).contains(Bytes32(tagVal));
            else if (tagName == 'P' && kind == 9735) found = seedsHex.contains(std::string(tagVal));
            return !found;
        });

        return found;
    }
};


static std::optional<std::string> nextPubkey(std::string_view pk) {
    std::string output(pk);

    for (size_t i = output.size(); i-- > 0; ) {
        if ((uint8_t)output[i] != 0xFF) {
            output[i] = (char)((uint8_t)output[i] + 1);
            return output;
        }
        output[i] = '\0';
    }

    return std::nullopt;
}


PruneResult pruneEvents(bool dryRun) {
    PruneResult result;
    NegentropyFilterCache neFilterCache;

    // The pubkey index groups events by author, so kept authors are skipped with one seek each
    std::string resumeKey = makeKey_StringUint64("", 0);
    uint64_t resumeVal = 0;
    bool done = false;

    while (!done) {
        // Reloaded for every batch, so people who just entered a universe are not pruned
        TenantRegistry::reload();
        auto snap = TenantRegistry::get();

        // Without any virtual relay every event would go
        if (snap->tenants.empty()) {
            LW << "Banyan: no virtual relays, pruning skipped";
            return result;
        }

        KeepRules rules(*snap, hoytech::curr_time_s());
        std::vector<uint64_t> batch;
        done = true;

        {
            auto txn = env.txn_ro();
            uint64_t mostRecent = getMostRecentLevId(txn); // deleting it would let its levId be reused

            while (true) {
                bool jumped = false, batchFull = false;

                env.generic_foreachFull(txn, env.dbi_Event__pubkey, resumeKey, lmdb::to_sv<uint64_t>(resumeVal), [&](std::string_view k, std::string_view v){
                    uint64_t levId = lmdb::from_sv<uint64_t>(v);

                    if (batch.size() >= deleteBatchSize) {
                        resumeKey = std::string(k);
                        resumeVal = levId;
                        batchFull = true;
                        return false;
                    }

                    ParsedKey_StringUint64 parsed(k);

                    if (parsed.s.size() == 32 && rules.authors.contains(Bytes32(parsed.s))) {
                        if (auto next = nextPubkey(parsed.s)) {
                            resumeKey = makeKey_StringUint64(*next, 0);
                            resumeVal = 0;
                            jumped = true;
                        }
                        return false;
                    }

                    result.scanned++;
                    if (levId == mostRecent) return true;

                    auto ev = env.lookup_Event(txn, levId);
                    if (ev && !rules.keepOther(PackedEventView(ev->buf))) {
                        if (dryRun) result.deleted++;
                        else batch.push_back(levId);
                    }

                    return true;
                });

                if (batchFull) {
                    done = false;
                    break;
                }

                if (!jumped) break;
            }
        }

        if (batch.size()) {
            auto txn = env.txn_rw();
            result.deleted += deleteEvents(txn, neFilterCache, batch);
            txn.commit();
        }

        if (done && !dryRun) {
            // Pruned people lose their history here, so the harvester backfills them again if they come back
            auto txn = env.txn_rw();
            std::vector<uint64_t> stale;

            env.foreach_HarvestState(txn, [&](auto &view){
                if (!rules.authors.contains(Bytes32(view.pubkey()))) stale.push_back(view.primaryKeyId);
                return true;
            });

            for (auto id : stale) env.delete_HarvestState(txn, id);
            txn.commit();

            result.harvestStatesReset = stale.size();
        }
    }

    return result;
}


void runPruner() {
    setThreadName("BanyanPrune");

    // Leaves time for the first trust computations after a start
    uint64_t nextRun = hoytech::curr_time_s() + 600;

    while (1) {
        std::this_thread::sleep_for(std::chrono::seconds(30));

        if (!cfg().banyan__prune__enabled || hoytech::curr_time_s() < nextRun) continue;

        try {
            auto t0 = hoytech::curr_time_us();
            auto r = pruneEvents(false);
            LI << "Banyan: pruned " << r.deleted << " events outside every universe (" << r.scanned << " checked) in "
               << (hoytech::curr_time_us() - t0) / 1000 << "ms";
        } catch (std::exception &e) {
            LE << "Banyan: pruning failed: " << e.what();
        }

        nextRun = hoytech::curr_time_s() + cfg().banyan__prune__intervalSeconds;
    }
}


}
