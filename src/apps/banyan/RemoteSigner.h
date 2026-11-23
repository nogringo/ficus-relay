#pragma once

#include <functional>
#include <map>
#include <string>
#include <vector>

#include <tao/json.hpp>

#include "golpe.h"

#include "Bytes32.h"
#include "Crypto.h"


// NIP-46 remote signers, so the harvester can answer NIP-42 AUTH as an owner without holding their key
namespace banyan {


struct BunkerUrl {
    std::string signerPubkey; // 32 bytes
    std::vector<std::string> relays;
    std::string secret;
};

BunkerUrl parseBunkerUrl(std::string_view url); // throws

void setBunkerSigner(lmdb::txn &txn, uint64_t tenantId, const BunkerUrl &bunker);
void startNostrConnect(lmdb::txn &txn, uint64_t tenantId);
void removeSigner(lmdb::txn &txn, uint64_t tenantId);

// For the admin API: configuration, nostrconnect:// link while waiting, and the harvester's live state
tao::json::value signerJson(lmdb::txn &txn, uint64_t tenantId);

// Tells the harvester to reload the signers' configuration
void signersChanged();
uint64_t signersVersion();


enum class SignerState { Waiting, Connecting, Verifying, Ready, Failed };

// Lives on the harvester thread, which carries the messages to and from the signers' relays
struct RemoteSigners {
    using Done = std::function<void(bool ok, const tao::json::value &eventOrNull, const std::string &error)>;

    // Sends a message to a signer relay, returns false if it is not connected
    std::function<bool(const std::string &url, const std::string &msg)> sendToRelay;

    void load();

    // Signer relays to stay connected to, each with the REQ that receives the answers
    std::map<std::string, std::string> subscriptions() const;

    void onEvent(const std::string &url, const tao::json::value &ev);
    void tick(uint64_t now);

    bool ready(uint64_t tenantId) const;
    std::vector<uint64_t> readyTenants() const;

    void signAuth(uint64_t tenantId, const std::string &relayUrl, const std::string &challenge, Done done);

    void publishStatus() const;

  private:
    struct Pending {
        std::string method;
        uint64_t sentAt = 0;
        std::function<void(bool ok, const std::string &result)> cb;
    };

    struct Session {
        uint64_t tenantId = 0;
        Bytes32 owner;
        KeyPair client;
        std::string signerPubkey;
        std::string conversationKey;
        std::vector<std::string> relays;
        std::string secret;
        uint64_t connectedAt = 0;
        uint64_t createdAt = 0;
        bool needsConnect = false; // bunker:// sessions start with a connect request, nostrconnect:// ones with the signer's answer

        SignerState state = SignerState::Waiting;
        std::string lastError;
        std::string authUrl;
        uint64_t nextAttemptAt = 0;
        std::map<std::string, Pending> pending;
    };

    std::map<uint64_t, Session> sessions;
    uint64_t loadedVersion = 0;
    uint64_t loadedAt = 0; // keeps the REQ the same until the next reload

    bool request(Session &s, const std::string &method, tao::json::value params, std::function<void(bool, const std::string &)> cb);
    void connectSession(Session &s);
    void verifySession(Session &s);
    void fail(Session &s, const std::string &error, uint64_t retryInSeconds);
    void persistConnected(const Session &s);
};


}
