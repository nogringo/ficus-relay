#include "RelayServer.h"


// Admin calls open write transactions and read every member's profile, so they stay off the websocket thread
void RelayServer::runBanyanAdmin(ThreadPool<MsgBanyanAdmin>::Thread &thr) {
    while (1) {
        auto newMsgs = thr.inbox.pop_all();

        for (auto &newMsg : newMsgs) {
            if (auto msg = std::get_if<MsgBanyanAdmin::Rpc>(&newMsg.msg)) {
                banyan::HttpReply reply;

                try {
                    reply = banyan::handleAdminRpc(msg->request);
                } catch (std::exception &e) {
                    LE << "Banyan admin RPC failed: " << e.what();
                    reply = { 500, "application/json", R"({"error":"internal error"})" };
                }

                tpWebsocket.dispatch(0, MsgWebsocket{MsgWebsocket::BanyanAdminReply{msg->requestId, std::move(reply)}});
                hubTrigger->send();
            }
        }
    }
}
