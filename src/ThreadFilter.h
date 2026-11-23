#pragma once

#include <deque>

#include <hoytech/hex.h>

#include "golpe.h"

#include "filters.h"
#include "events.h"
#include "apps/banyan/Tenants.h"


inline std::optional<std::string> addressOf(const PackedEventView &ev) {
    if (!isParamReplaceableKind(ev.kind())) return std::nullopt;

    std::string dTag;

    ev.foreachTag([&](char tagName, std::string_view tagVal){
        if (tagName != 'd') return true;
        dTag = std::string(tagVal);
        return false;
    });

    return std::to_string(ev.kind()) + ":" + to_hex(ev.pubkey()) + ":" + dTag;
}

using ThreadAdded = std::function<void(char tagName, std::string_view tagVal)>;
using ThreadFound = std::function<void(uint64_t levId, const PackedEventView &ev)>;

// Walks the e and a tag indexes from tagSpecs (tag name + value), adding every event below belowLevId that scope can see.
// Events the scope can't see are not followed, so a thread never grows through people outside the universe.
inline void growThread(lmdb::txn &txn, ThreadState &st, const banyan::TenantView *scope, std::deque<std::string> tagSpecs, uint64_t belowLevId, const ThreadAdded &added, const ThreadFound &found) {
    while (tagSpecs.size() && !st.full()) {
        std::string spec = std::move(tagSpecs.front());
        tagSpecs.pop_front();

        env.generic_foreachFull(txn, env.dbi_Event__tag, makeKey_StringUint64(spec, 0), lmdb::to_sv<uint64_t>(0), [&](std::string_view k, std::string_view v){
            ParsedKey_StringUint64 parsed(k);
            if (parsed.s != spec) return false;

            uint64_t levId = lmdb::from_sv<uint64_t>(v);
            if (levId >= belowLevId) return true;

            auto view = env.lookup_Event(txn, levId);
            if (!view) return true;
            PackedEventView packed(view->buf);
            if (scope && !scope->canSee(packed)) return true;

            if (!st.addNode(packed.id())) return !st.full();

            added('e', packed.id());
            tagSpecs.push_back(std::string("e") + std::string(packed.id()));

            if (auto coord = addressOf(packed); coord && st.coords.insert(*coord).second) {
                added('a', *coord);
                tagSpecs.push_back("a" + *coord);
            }

            found(levId, packed);
            return !st.full();
        });
    }
}

// Stored part of a thread, as of latestEventId: what came later reaches the subscription through absorbIntoThread()
inline void expandThread(lmdb::txn &txn, ThreadState &st, const banyan::TenantView *scope, uint64_t latestEventId) {
    if (st.expanded) return;
    st.expanded = true;

    std::deque<std::string> tagSpecs;

    for (const auto &id : st.roots) {
        tagSpecs.push_back("e" + id);

        auto root = lookupEventById(txn, id);
        if (!root || root->primaryKeyId > latestEventId) continue;

        if (auto coord = addressOf(PackedEventView(root->buf)); coord && st.coords.insert(*coord).second) tagSpecs.push_back("a" + *coord);
    }

    uint64_t below = latestEventId == MAX_U64 ? MAX_U64 : latestEventId + 1;
    growThread(txn, st, scope, std::move(tagSpecs), below, [](char, std::string_view){}, [](uint64_t, const PackedEventView &){});
}

// A new event is part of the thread: it joins it, and so do the stored replies that arrived before it, passed to found
inline void absorbIntoThread(lmdb::txn &txn, ThreadState &st, const banyan::TenantView *scope, const PackedEventView &ev, uint64_t levId, const ThreadAdded &added, const ThreadFound &found) {
    if (scope && !scope->canSee(ev)) return;

    std::deque<std::string> tagSpecs;

    if (st.addNode(ev.id())) {
        added('e', ev.id());
        tagSpecs.push_back(std::string("e") + std::string(ev.id()));
    }

    if (auto coord = addressOf(ev); coord && st.coords.insert(*coord).second) {
        added('a', *coord);
        tagSpecs.push_back("a" + *coord);
    }

    growThread(txn, st, scope, std::move(tagSpecs), levId, added, found);
}
