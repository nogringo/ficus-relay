#pragma once

#include <unordered_map>

#include "golpe.h"

#include "Bytes32.h"
#include "Subscription.h"
#include "filters.h"
#include "ThreadFilter.h"



struct ActiveMonitors : NonCopyable {
  private:
    struct Monitor : NonCopyable {
        Subscription sub;

        Monitor(Subscription &sub_) : sub(std::move(sub_)) {}
        Monitor(const Monitor&) = delete; // pointers to filters inside sub must be stable because they are stored in MonitorSets
    };

    using ConnMonitor = std::unordered_map<SubId, Monitor>;
    flat_hash_map<uint64_t, ConnMonitor> conns; // connId -> subId -> Monitor

    struct MonitorItem {
        Monitor *mon;
        uint64_t latestEventId;
    };

    using MonitorSet = flat_hash_map<NostrFilter*, MonitorItem>;
    btree_map<Bytes32, MonitorSet> allIds;
    btree_map<Bytes32, MonitorSet> allAuthors;
    btree_map<std::string, MonitorSet> allTags;
    btree_map<uint64_t, MonitorSet> allKinds;
    MonitorSet allOthers;

    std::string tagSpecBuf = std::string(256, '\0');
    const std::string &getTagSpec(uint8_t k, std::string_view val) {
        tagSpecBuf.clear();
        tagSpecBuf += (char)k;
        tagSpecBuf += val;
        return tagSpecBuf;
    }


  public:
    bool addSub(lmdb::txn &txn, Subscription &&sub, uint64_t currEventId) {
        if (sub.latestEventId != currEventId) throw herr("sub not up to date");

        {
            auto *existing = findMonitor(sub.connId, sub.subId);
            if (existing) removeSub(sub.connId, sub.subId);
        }

        auto res = conns.try_emplace(sub.connId);
        auto &connMonitors = res.first->second;

        if (connMonitors.size() >= cfg().relay__maxSubsPerConnection) {
            return false;
        }

        auto subId = sub.subId;
        auto *m = &connMonitors.try_emplace(subId, sub).first->second;

        installLookups(m, currEventId);
        return true;
    }

    void removeSub(uint64_t connId, const SubId &subId) {
        auto *monitor = findMonitor(connId, subId);
        if (!monitor) return;

        uninstallLookups(monitor);

        conns[connId].erase(subId);
        if (conns[connId].empty()) conns.erase(connId);
    }

    void closeConn(uint64_t connId) {
        auto f1 = conns.find(connId);
        if (f1 == conns.end()) return;

        for (auto &[k, v] : f1->second) uninstallLookups(&v);

        conns.erase(connId);
    }

    // cb may also receive older events for one subscription: replies a thread filter only reaches through this event
    void process(lmdb::txn &txn, defaultDb::environment::View_Event &ev, const std::function<void(RecipientList &&, uint64_t)> &cb) {
        RecipientList recipients;
        std::vector<std::pair<NostrFilter*, Monitor*>> threadMatches;

        auto processMonitorSet = [&](MonitorSet &ms){
            for (auto &[f, item] : ms) {
                if (item.latestEventId >= ev.primaryKeyId) continue;
                item.latestEventId = ev.primaryKeyId;

                // A thread grows through all its events, also those its other fields leave out or another filter already sent
                if (f->thread && f->thread->contains(PackedEventView(ev.buf))) threadMatches.emplace_back(f, item.mon);

                if (item.mon->sub.latestEventId >= ev.primaryKeyId) continue;

                if (f->doesMatch(PackedEventView(ev.buf))) {
                    recipients.emplace_back(item.mon->sub.connId, item.mon->sub.subId);
                    item.mon->sub.latestEventId = ev.primaryKeyId;
                    continue;
                }
            }
        };

        // Exact-key lookup only: installLookups keys monitors by id / author / tagSpec /
        // kind string. Prior code used upper_bound + prev + equality predicate; with
        // unique btree keys that is equivalent to find() without std::function per call.
        auto lookupMonitors = [&]<typename T>(btree_map<T, MonitorSet> &m, const T &key) {
            auto it = m.find(key);
            if (it != m.end()) processMonitorSet(it->second);
        };

        auto packed = PackedEventView(ev.buf);

        lookupMonitors(allIds, Bytes32(packed.id()));
        lookupMonitors(allAuthors, Bytes32(packed.pubkey()));

        packed.foreachTag([&](char tagName, std::string_view tagVal){
            lookupMonitors(allTags, getTagSpec(tagName, tagVal));
            return true;
        });

        lookupMonitors(allKinds, packed.kind());

        processMonitorSet(allOthers);

        // After the lookups: growing a thread inserts into the maps they iterate
        std::vector<std::pair<Monitor*, uint64_t>> lateEvents;

        for (auto &[f, m] : threadMatches) {
            absorbIntoThread(txn, *f->thread, m->sub.scope.get(), packed, ev.primaryKeyId,
                [&](char tagName, std::string_view tagVal){ installTagLookup(f, m, tagName, tagVal, ev.primaryKeyId); },
                [&](uint64_t levId, const PackedEventView &late){ if (f->doesMatch(late)) lateEvents.emplace_back(m, levId); });
        }

        if (recipients.size()) {
            cb(std::move(recipients), ev.primaryKeyId);
        }

        for (auto &[m, levId] : lateEvents) {
            RecipientList one;
            one.emplace_back(m->sub.connId, m->sub.subId);
            cb(std::move(one), levId);
        }
    }


  private:
    Monitor *findMonitor(uint64_t connId, const SubId &subId) {
        auto f1 = conns.find(connId);
        if (f1 == conns.end()) return nullptr;

        auto f2 = f1->second.find(subId);
        if (f2 == f1->second.end()) return nullptr;

        return &f2->second;
    }

    void installTagLookup(NostrFilter *f, Monitor *m, char tagName, std::string_view tagVal, uint64_t currEventId) {
        auto &tagSpec = getTagSpec(tagName, tagVal);
        auto res = allTags.try_emplace(tagSpec);
        res.first->second.try_emplace(f, MonitorItem{m, currEventId});
    }

    void uninstallTagLookup(NostrFilter *f, char tagName, std::string_view tagVal) {
        auto &tagSpec = getTagSpec(tagName, tagVal);
        auto it = allTags.find(tagSpec);
        if (it == allTags.end()) return;
        it->second.erase(f);
        if (it->second.empty()) allTags.erase(it);
    }

    void installLookups(Monitor *m, uint64_t currEventId) {
        for (auto &f : m->sub.filterGroup.filters) {
            if (f.thread) {
                // Roots by id, in case they arrive after the subscription, and every node by what replies to it
                for (const auto &id : f.thread->roots) {
                    auto res = allIds.try_emplace(Bytes32(id));
                    res.first->second.try_emplace(&f, MonitorItem{m, currEventId});
                }
                for (const auto &node : f.thread->nodes) installTagLookup(&f, m, 'e', node.sv(), currEventId);
                for (const auto &coord : f.thread->coords) installTagLookup(&f, m, 'a', coord, currEventId);
            } else if (f.ids) {
                for (size_t i = 0; i < f.ids->size(); i++) {
                    auto res = allIds.try_emplace(Bytes32(f.ids->at(i)));
                    res.first->second.try_emplace(&f, MonitorItem{m, currEventId});
                }
            } else if (f.authors) {
                for (size_t i = 0; i < f.authors->size(); i++) {
                    auto res = allAuthors.try_emplace(Bytes32(f.authors->at(i)));
                    res.first->second.try_emplace(&f, MonitorItem{m, currEventId});
                }
            } else if (f.tags.size()) {
                for (const auto &[tagName, filterSet] : f.tags) {
                    for (size_t i = 0; i < filterSet.size(); i++) {
                        auto &tagSpec = getTagSpec(tagName, filterSet.at(i));
                        auto res = allTags.try_emplace(tagSpec);
                        res.first->second.try_emplace(&f, MonitorItem{m, currEventId});
                    }
                }
            } else if (f.kinds) {
                for (size_t i = 0; i < f.kinds->size(); i++) {
                    auto res = allKinds.try_emplace(f.kinds->at(i));
                    res.first->second.try_emplace(&f, MonitorItem{m, currEventId});
                }
            } else {
                allOthers.try_emplace(&f, MonitorItem{m, currEventId});
            }
        }
    }

    void uninstallLookups(Monitor *m) {
        for (auto &f : m->sub.filterGroup.filters) {
            if (f.thread) {
                for (const auto &id : f.thread->roots) {
                    auto it = allIds.find(Bytes32(id));
                    if (it == allIds.end()) continue;
                    it->second.erase(&f);
                    if (it->second.empty()) allIds.erase(it);
                }
                for (const auto &node : f.thread->nodes) uninstallTagLookup(&f, 'e', node.sv());
                for (const auto &coord : f.thread->coords) uninstallTagLookup(&f, 'a', coord);
            } else if (f.ids) {
                for (size_t i = 0; i < f.ids->size(); i++) {
                    Bytes32 id(f.ids->at(i));
                    auto &monSet = allIds.at(id);
                    monSet.erase(&f);
                    if (monSet.empty()) allIds.erase(id);
                }
            } else if (f.authors) {
                for (size_t i = 0; i < f.authors->size(); i++) {
                    Bytes32 author(f.authors->at(i));
                    auto &monSet = allAuthors.at(author);
                    monSet.erase(&f);
                    if (monSet.empty()) allAuthors.erase(author);
                }
            } else if (f.tags.size()) {
                for (const auto &[tagName, filterSet] : f.tags) {
                    for (size_t i = 0; i < filterSet.size(); i++) {
                        auto &tagSpec = getTagSpec(tagName, filterSet.at(i));
                        auto &monSet = allTags.at(tagSpec);
                        monSet.erase(&f);
                        if (monSet.empty()) allTags.erase(tagSpec);
                    }
                }
            } else if (f.kinds) {
                for (size_t i = 0; i < f.kinds->size(); i++) {
                    uint64_t kind = f.kinds->at(i);
                    auto &monSet = allKinds.at(kind);
                    monSet.erase(&f);
                    if (monSet.empty()) allKinds.erase(kind);
                }
            } else {
                allOthers.erase(&f);
            }
        }
    }
};
