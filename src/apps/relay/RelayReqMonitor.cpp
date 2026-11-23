#include "RelayServer.h"

#include "ActiveMonitors.h"
#include "ReadRestrictor.h"
#include "apps/banyan/Tenants.h"



void RelayServer::runReqMonitor(ThreadPool<MsgReqMonitor>::Thread &thr) {
    auto dbChangeWatcher = hoytech::file_change_monitor(dbDir + "/data.mdb");

    dbChangeWatcher.setDebounce(100);

    dbChangeWatcher.run([&](){
        tpReqMonitor.dispatchToAll([]{ return MsgReqMonitor{MsgReqMonitor::DBChange{}}; });
    });


    Decompressor decomp;
    ActiveMonitors monitors;
    flat_hash_map<uint64_t, Bytes32> connIdToAuthedPubkey;
    flat_hash_map<uint64_t, uint64_t> connIdToTenantId;
    uint64_t currEventId = MAX_U64;

    // Looked up on every batch so universe changes apply to subscriptions that are already open
    auto tenantCanSee = [&](const banyan::TenantSnapshot &snap, uint64_t connId, const PackedEventView &packed){
        auto it = connIdToTenantId.find(connId);
        if (it == connIdToTenantId.end()) return true;
        auto tenant = snap.findById(it->second);
        return tenant && tenant->canSee(packed);
    };

    while (1) {
        auto newMsgs = thr.inbox.pop_all();

        auto txn = env.txn_ro();
        auto tenantSnap = banyan::TenantRegistry::get();

        uint64_t latestEventId = getMostRecentLevId(txn);
        if (currEventId > latestEventId) currEventId = latestEventId;

        for (auto &newMsg : newMsgs) {
            if (auto msg = std::get_if<MsgReqMonitor::NewSub>(&newMsg.msg)) {
                auto connId = msg->sub.connId;
                auto it = connIdToAuthedPubkey.find(connId);
                Bytes32 connAuthedPubkey = it == connIdToAuthedPubkey.end() ? Bytes32() : it->second;
                if (msg->sub.tenantId) connIdToTenantId[connId] = msg->sub.tenantId;

                auto deliver = [&](uint64_t levId){
                    auto view = env.lookup_Event(txn, levId);
                    if (!view) return;
                    PackedEventView packed(view->buf);
                    if (tenantCanSee(*tenantSnap, connId, packed) && ReadRestrictor::shouldSendToSubscriber(packed, connAuthedPubkey)) {
                        sendEvent(connId, msg->sub.subId, getEventJson(txn, decomp, levId));
                    }
                };

                env.foreach_Event(txn, [&](auto &ev){
                    PackedEventView packed(ev.buf);
                    bool matched = false;

                    for (auto &f : msg->sub.filterGroup.filters) {
                        if (f.thread && f.thread->contains(packed)) {
                            absorbIntoThread(txn, *f.thread, msg->sub.scope.get(), packed, ev.primaryKeyId, [](char, std::string_view){},
                                [&](uint64_t levId, const PackedEventView &late){ if (f.doesMatch(late)) deliver(levId); });
                        }

                        if (f.doesMatch(packed)) matched = true;
                    }

                    if (matched) deliver(ev.primaryKeyId);

                    return true;
                }, false, msg->sub.latestEventId + 1);

                msg->sub.latestEventId = latestEventId;

                if (!monitors.addSub(txn, std::move(msg->sub), latestEventId)) {
                    sendNoticeError(connId, std::string("too many concurrent REQs"));
                }
            } else if (auto msg = std::get_if<MsgReqMonitor::SetAuth>(&newMsg.msg)) {
                connIdToAuthedPubkey[msg->connId] = msg->authed;
            } else if (auto msg = std::get_if<MsgReqMonitor::RemoveSub>(&newMsg.msg)) {
                monitors.removeSub(msg->connId, msg->subId);
            } else if (auto msg = std::get_if<MsgReqMonitor::CloseConn>(&newMsg.msg)) {
                connIdToAuthedPubkey.erase(msg->connId);
                connIdToTenantId.erase(msg->connId);
                monitors.closeConn(msg->connId);
            } else if (std::get_if<MsgReqMonitor::DBChange>(&newMsg.msg)) {
                env.foreach_Event(txn, [&](auto &ev){
                    monitors.process(txn, ev, [&](RecipientList &&recipients, uint64_t levId){
                        std::optional<defaultDb::environment::View_Event> other;
                        if (levId != ev.primaryKeyId) {
                            other = env.lookup_Event(txn, levId);
                            if (!other) return;
                        }
                        PackedEventView packed(other ? other->buf : ev.buf);

                        if (connIdToTenantId.size()) {
                            std::erase_if(recipients, [&](const auto &r){ return !tenantCanSee(*tenantSnap, r.connId, packed); });
                            if (recipients.empty()) return;
                        }

                        if (ReadRestrictor::restrictedKinds().contains(packed.kind())) {
                            RecipientList filteredRecipients;
                            for (const auto &recipient : recipients) {
                                auto it = connIdToAuthedPubkey.find(recipient.connId);
                                Bytes32 authedPubkey = it == connIdToAuthedPubkey.end() ? Bytes32() : it->second;
                                if (ReadRestrictor::shouldSendToSubscriber(packed, authedPubkey)) {
                                    filteredRecipients.emplace_back(recipient);
                                }
                            }
                            if (!filteredRecipients.empty()) {
                                sendEventToBatch(std::move(filteredRecipients), std::string(getEventJson(txn, decomp, levId)));
                            }
                        } else {
                            sendEventToBatch(std::move(recipients), std::string(getEventJson(txn, decomp, levId)));
                        }
                    });
                    return true;
                }, false, currEventId + 1);

                currEventId = latestEventId;
            }
        }
    }
}
