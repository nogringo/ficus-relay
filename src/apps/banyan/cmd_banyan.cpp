#include <iostream>

#include <docopt.h>
#include <hoytech/time.h>

#include "golpe.h"

#include "Tenants.h"
#include "TrustEngine.h"
#include "BanyanHttp.h"


static const char USAGE[] =
R"(
    Usage:
      banyan list
      banyan add <pubkey> <slug>
      banyan remove <person>
      banyan show <person>
      banyan set <person> <settingsJson>
      banyan recompute <person>

    <person> is a slug, an npub or a hex pubkey.
    <settingsJson> is a JSON object, for example '{"pinned":["npub1..."],"minScore":1}'.
)";


static banyan::TenantPtr findLoaded(const std::string &person) {
    banyan::TenantRegistry::reload();
    auto snap = banyan::TenantRegistry::get();

    if (auto t = snap->findByPath(banyan::normalizePath(person))) return t;

    auto pk = banyan::parsePubkey(person);
    for (const auto &t : snap->tenants) {
        if (t->pubkey == pk) return t;
    }

    throw herr("unknown person: ", person);
}


void cmd_banyan(const std::vector<std::string> &subArgs) {
    std::map<std::string, docopt::value> args = docopt::docopt(USAGE, subArgs, true, "");

    if (args["list"].asBool()) {
        banyan::TenantRegistry::reload();
        for (const auto &t : banyan::TenantRegistry::get()->tenants) {
            std::cout << tao::json::to_string(banyan::tenantSummaryJson(*t)) << "\n";
        }
    } else if (args["add"].asBool()) {
        auto pubkey = banyan::parsePubkey(args["<pubkey>"].asString());
        auto txn = env.txn_rw();
        banyan::addTenant(txn, pubkey, args["<slug>"].asString());
        txn.commit();
        std::cout << "Added " << args["<slug>"].asString() << " (" << banyan::toNpub(pubkey) << ")\n";
    } else if (args["remove"].asBool()) {
        auto t = findLoaded(args["<person>"].asString());
        auto txn = env.txn_rw();
        banyan::removeTenant(txn, t->id);
        txn.commit();
        std::cout << "Removed " << t->slug << "\n";
    } else if (args["show"].asBool()) {
        auto t = findLoaded(args["<person>"].asString());
        std::cout << tao::json::to_string(banyan::tenantDetailJson(*t), 2) << "\n";
    } else if (args["set"].asBool()) {
        auto t = findLoaded(args["<person>"].asString());
        auto patch = tao::json::from_string(args["<settingsJson>"].asString());
        auto txn = env.txn_rw();
        banyan::updateTenant(txn, t->id, patch);
        txn.commit();
        std::cout << "Updated " << t->slug << "\n";
    } else if (args["recompute"].asBool()) {
        auto t = findLoaded(args["<person>"].asString());
        uint64_t now = hoytech::curr_time_s();

        banyan::EngagementCache cache;
        auto members = banyan::computeUniverse(*t, now, cache);

        auto txn = env.txn_rw();
        banyan::storeComputedUniverse(txn, t->id, now, members);
        txn.commit();

        for (const auto &m : members) {
            std::cout << banyan::circleName(m.circle) << " " << banyan::toNpub(m.pubkey) << " " << m.score << "\n";
        }
    }
}
