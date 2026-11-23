#include <mutex>

#include <hoytech/hex.h>

#include "Tenants.h"
#include "Bech32Utils.h"


namespace banyan {


std::string_view circleName(Circle c) {
    switch (c) {
        case Circle::Owner: return "owner";
        case Circle::Pinned: return "pinned";
        case Circle::Primary: return "primary";
        case Circle::Secondary: return "secondary";
    }
    return "?";
}

Circle parseCircle(std::string_view s) {
    if (s == "owner") return Circle::Owner;
    if (s == "pinned") return Circle::Pinned;
    if (s == "primary") return Circle::Primary;
    if (s == "secondary") return Circle::Secondary;
    throw herr("unknown circle: ", s);
}


static double jsonNumber(const tao::json::value &v, std::string_view what) {
    if (v.is_double()) return v.get_double();
    if (v.is_signed()) return (double)v.get_signed();
    if (v.is_unsigned()) return (double)v.get_unsigned();
    throw herr(what, " must be a number");
}

static tao::json::value parseStoredSettings(std::string_view storedJson) {
    if (storedJson.empty()) return tao::json::empty_object;
    auto v = tao::json::from_string(storedJson);
    if (!v.is_object()) return tao::json::empty_object;
    return v;
}

static std::vector<Bytes32> parsePubkeyArray(const tao::json::value &v, std::string_view what) {
    if (!v.is_array()) throw herr(what, " must be an array of pubkeys");

    std::vector<Bytes32> output;
    flat_hash_set<Bytes32> seen;

    for (const auto &e : v.get_array()) {
        if (!e.is_string()) throw herr(what, " must be an array of pubkeys");
        auto pk = parsePubkey(e.get_string());
        if (seen.insert(pk).second) output.push_back(pk);
    }

    return output;
}

static tao::json::value pubkeyArrayToJson(const std::vector<Bytes32> &pks) {
    tao::json::value arr = tao::json::empty_array;
    for (const auto &pk : pks) arr.emplace_back(to_hex(pk.sv()));
    return arr;
}


TenantSettings TenantSettings::effective(std::string_view storedJson) {
    TenantSettings s;

    s.weights.reply = (double)cfg().banyan__trust__weightReply;
    s.weights.repost = (double)cfg().banyan__trust__weightRepost;
    s.weights.reaction = (double)cfg().banyan__trust__weightReaction;
    s.weights.zap = (double)cfg().banyan__trust__weightZap;
    s.weights.mention = (double)cfg().banyan__trust__weightMention;
    s.primaryCircleSize = cfg().banyan__trust__primaryCircleSize;
    s.secondaryPerPeer = cfg().banyan__trust__secondaryPerPeer;
    s.minScore = (double)cfg().banyan__trust__minScore;

    auto stored = parseStoredSettings(storedJson);
    const auto &obj = stored.get_object();

    if (auto it = obj.find("weights"); it != obj.end() && it->second.is_object()) {
        const auto &w = it->second.get_object();
        auto get = [&](const char *k, double &out){
            if (auto wit = w.find(k); wit != w.end()) out = jsonNumber(wit->second, k);
        };
        get("reply", s.weights.reply);
        get("repost", s.weights.repost);
        get("reaction", s.weights.reaction);
        get("zap", s.weights.zap);
        get("mention", s.weights.mention);
    }

    if (auto it = obj.find("primaryCircleSize"); it != obj.end()) s.primaryCircleSize = (uint64_t)jsonNumber(it->second, "primaryCircleSize");
    if (auto it = obj.find("secondaryPerPeer"); it != obj.end()) s.secondaryPerPeer = (uint64_t)jsonNumber(it->second, "secondaryPerPeer");
    if (auto it = obj.find("minScore"); it != obj.end()) s.minScore = jsonNumber(it->second, "minScore");
    if (auto it = obj.find("pinned"); it != obj.end()) s.pinned = parsePubkeyArray(it->second, "pinned");
    if (auto it = obj.find("blocked"); it != obj.end()) s.blocked = parsePubkeyArray(it->second, "blocked");

    return s;
}

std::string TenantSettings::mergePatch(std::string_view storedJson, const tao::json::value &patch) {
    if (!patch.is_object()) throw herr("settings patch must be an object");

    auto stored = parseStoredSettings(storedJson);

    for (const auto &[k, v] : patch.get_object()) {
        if (k == "slug") {
            continue;
        } else if (k == "weights") {
            if (!v.is_object()) throw herr("weights must be an object");
            if (!stored.get_object().contains("weights")) stored["weights"] = tao::json::empty_object;
            for (const auto &[wk, wv] : v.get_object()) {
                if (wk != "reply" && wk != "repost" && wk != "reaction" && wk != "zap" && wk != "mention") throw herr("unknown weight: ", wk);
                double n = jsonNumber(wv, wk);
                if (n < 0 || n > 1000) throw herr("weight out of range: ", wk);
                stored["weights"][wk] = n;
            }
        } else if (k == "primaryCircleSize" || k == "secondaryPerPeer") {
            double n = jsonNumber(v, k);
            if (n < 0 || n > 10000) throw herr(k, " out of range");
            stored[k] = (uint64_t)n;
        } else if (k == "minScore") {
            double n = jsonNumber(v, k);
            if (n < 0) throw herr("minScore must be positive");
            stored[k] = n;
        } else if (k == "pinned" || k == "blocked") {
            stored[k] = pubkeyArrayToJson(parsePubkeyArray(v, k));
        } else {
            throw herr("unknown setting: ", k);
        }
    }

    return tao::json::to_string(stored);
}

tao::json::value TenantSettings::toJson() const {
    return tao::json::value({
        { "weights", tao::json::value({
            { "reply", weights.reply },
            { "repost", weights.repost },
            { "reaction", weights.reaction },
            { "zap", weights.zap },
            { "mention", weights.mention },
        }) },
        { "primaryCircleSize", primaryCircleSize },
        { "secondaryPerPeer", secondaryPerPeer },
        { "minScore", minScore },
        { "pinned", pubkeyArrayToJson(pinned) },
        { "blocked", pubkeyArrayToJson(blocked) },
    });
}

bool TenantSettings::isBlocked(const Bytes32 &pk) const {
    return std::find(blocked.begin(), blocked.end(), pk) != blocked.end();
}


std::string serializeComputedMembers(const std::vector<UniverseMember> &members) {
    tao::json::value arr = tao::json::empty_array;

    for (const auto &m : members) {
        tao::json::value item = tao::json::value({
            { "pk", to_hex(m.pubkey.sv()) },
            { "c", std::string(circleName(m.circle)) },
            { "s", m.score },
        });
        if (m.via.size()) item["via"] = pubkeyArrayToJson(m.via);
        arr.emplace_back(std::move(item));
    }

    return tao::json::to_string(arr);
}

std::vector<UniverseMember> parseComputedMembers(std::string_view json) {
    std::vector<UniverseMember> output;
    if (json.empty()) return output;

    auto arr = tao::json::from_string(json);
    if (!arr.is_array()) return output;

    for (const auto &item : arr.get_array()) {
        UniverseMember m;
        m.pubkey = Bytes32(from_hex(item.at("pk").get_string()));
        m.circle = parseCircle(item.at("c").get_string());
        m.score = jsonNumber(item.at("s"), "score");
        if (auto *via = item.find("via")) m.via = parsePubkeyArray(*via, "via");
        output.push_back(std::move(m));
    }

    return output;
}


bool TenantView::isGiftWrapForOwner(const PackedEventView &ev) const {
    if (!cfg().banyan__acceptGiftWrapsForOwner) return false;
    if (ev.kind() != 1059 && ev.kind() != 21059) return false;

    bool found = false;

    ev.foreachTag([&](char tagName, std::string_view tagVal){
        if (tagName == 'p' && tagVal == pubkey.sv()) {
            found = true;
            return false;
        }
        return true;
    });

    return found;
}

size_t TenantView::countCircle(Circle c) const {
    return std::count_if(members.begin(), members.end(), [&](const auto &m){ return m.circle == c; });
}


static std::mutex registryMutex;
static SnapshotPtr registryCurrent = std::make_shared<TenantSnapshot>();

SnapshotPtr TenantRegistry::get() {
    std::lock_guard<std::mutex> guard(registryMutex);
    return registryCurrent;
}

static TenantPtr buildTenantView(uint64_t id, std::string_view pubkey, std::string_view slug, uint64_t addedAt, std::string_view settingsJson, uint64_t computedAt, std::string_view computedJson) {
    auto t = std::make_shared<TenantView>();

    t->id = id;
    t->pubkey = Bytes32(pubkey);
    t->slug = std::string(slug);
    t->npub = toNpub(t->pubkey);
    t->addedAt = addedAt;
    t->settingsJson = std::string(settingsJson);
    t->computedAt = computedAt;

    try {
        t->settings = TenantSettings::effective(settingsJson);
    } catch (std::exception &e) {
        LE << "Banyan: invalid settings for tenant " << slug << ", using defaults: " << e.what();
        t->settings = TenantSettings::effective("");
    }

    auto add = [&](UniverseMember &&m){
        if (t->universe.contains(m.pubkey)) return;
        if (m.circle != Circle::Owner && t->settings.isBlocked(m.pubkey)) return;

        if (m.via.size()) {
            std::erase_if(m.via, [&](const Bytes32 &v){ return t->settings.isBlocked(v); });
            if (m.via.empty()) return;
        }

        t->universe.insert(m.pubkey);
        t->members.push_back(std::move(m));
    };

    add(UniverseMember{ t->pubkey, Circle::Owner, 0, {} });

    for (const auto &pk : t->settings.pinned) add(UniverseMember{ pk, Circle::Pinned, 0, {} });

    try {
        for (auto &m : parseComputedMembers(computedJson)) add(std::move(m));
    } catch (std::exception &e) {
        LE << "Banyan: invalid computed universe for tenant " << slug << ": " << e.what();
    }

    return t;
}

static std::mutex reloadMutex;

// Callers hold reloadMutex and opened txn after taking it, so a reload never publishes data older than the previous one
static void reloadLocked(lmdb::txn &txn) {
    auto prev = TenantRegistry::get();
    auto snap = std::make_shared<TenantSnapshot>();
    snap->version = prev->version + 1;

    env.foreach_Tenant(txn, [&](auto &view){
        uint64_t computedAt = 0;
        std::string_view computedJson;

        auto uni = env.lookup_TenantUniverse(txn, view.primaryKeyId);
        if (uni) {
            computedAt = uni->computedAt();
            computedJson = uni->members();
        }

        TenantPtr t;

        if (auto old = prev->findById(view.primaryKeyId); old && old->slug == view.slug() && old->settingsJson == view.settings() && old->computedAt == computedAt) {
            t = old;
        } else {
            t = buildTenantView(view.primaryKeyId, view.pubkey(), view.slug(), view.addedAt(), view.settings(), computedAt, computedJson);
        }

        snap->tenants.push_back(t);
        snap->byId[t->id] = t;
        snap->byPath[t->slug] = t;
        snap->byPath[t->npub] = t;

        return true;
    });

    bool changed = prev->tenants.size() != snap->tenants.size();
    for (size_t i = 0; !changed && i < snap->tenants.size(); i++) {
        if (prev->tenants[i] != snap->tenants[i]) changed = true;
    }

    if (!changed) return;

    std::lock_guard<std::mutex> guard(registryMutex);
    registryCurrent = snap;
}

void TenantRegistry::reload() {
    std::lock_guard<std::mutex> guard(reloadMutex);
    auto txn = env.txn_ro();
    reloadLocked(txn);
}


Bytes32 parsePubkey(std::string_view input) {
    while (input.size() && isspace((unsigned char)input.front())) input.remove_prefix(1);
    while (input.size() && isspace((unsigned char)input.back())) input.remove_suffix(1);

    if (input.starts_with("npub1")) return Bytes32(decodeBech32Simple(input));

    if (input.size() == 64) {
        std::string lower(input);
        std::transform(lower.begin(), lower.end(), lower.begin(), [](unsigned char c){ return std::tolower(c); });
        return Bytes32(from_hex(lower));
    }

    throw herr("invalid pubkey, expected npub or 64 hex characters");
}

std::string toNpub(const Bytes32 &pk) {
    return encodeBech32Simple("npub", pk.sv());
}

void validateSlug(std::string_view slug) {
    if (slug.empty() || slug.size() > 32) throw herr("slug must be 1 to 32 characters");

    auto isAlnum = [](char c){ return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9'); };

    if (!isAlnum(slug[0])) throw herr("slug must start with a lowercase letter or a digit");

    for (char c : slug) {
        if (!isAlnum(c) && c != '-' && c != '_') throw herr("slug may only contain lowercase letters, digits, '-' and '_'");
    }

    if (slug.starts_with("npub1")) throw herr("slug can't start with npub1");

    static const std::vector<std::string_view> reserved = { "admin", "api", "metrics", "nodeinfo" };
    if (std::find(reserved.begin(), reserved.end(), slug) != reserved.end()) throw herr("slug is reserved: ", slug);
}

RelayUrlParts parseRelayUrl(std::string_view url) {
    if (auto pos = url.find("://"); pos != std::string_view::npos) url.remove_prefix(pos + 3);
    if (auto pos = url.find_first_of("?#"); pos != std::string_view::npos) url = url.substr(0, pos);

    RelayUrlParts output;

    auto slash = url.find('/');
    output.host = std::string(url.substr(0, slash));
    std::transform(output.host.begin(), output.host.end(), output.host.begin(), [](unsigned char c){ return std::tolower(c); });

    if (slash != std::string_view::npos) output.path = normalizePath(url.substr(slash));

    return output;
}

std::string normalizePath(std::string_view url) {
    if (auto pos = url.find_first_of("?#"); pos != std::string_view::npos) url = url.substr(0, pos);
    while (url.size() && url.front() == '/') url.remove_prefix(1);
    while (url.size() && url.back() == '/') url.remove_suffix(1);

    std::string output(url);
    std::transform(output.begin(), output.end(), output.begin(), [](unsigned char c){ return std::tolower(c); });
    return output;
}

std::optional<defaultDb::environment::View_Tenant> findTenant(lmdb::txn &txn, std::string_view slugOrPubkey) {
    if (slugOrPubkey.starts_with("npub1") || slugOrPubkey.size() == 64) {
        try {
            auto pk = parsePubkey(slugOrPubkey);
            return env.lookup_Tenant__pubkey(txn, pk.sv());
        } catch (std::exception &) {
        }
    }

    return env.lookup_Tenant__slug(txn, normalizePath(slugOrPubkey));
}

uint64_t addTenant(lmdb::txn &txn, const Bytes32 &pubkey, std::string_view slug) {
    validateSlug(slug);

    if (env.lookup_Tenant__pubkey(txn, pubkey.sv())) throw herr("this pubkey already has a virtual relay");
    if (env.lookup_Tenant__slug(txn, slug)) throw herr("slug already taken: ", slug);

    return env.insert_Tenant(txn, pubkey.sv(), slug, hoytech::curr_time_s(), "{}");
}

void removeTenant(lmdb::txn &txn, uint64_t tenantId) {
    env.delete_TenantUniverse(txn, tenantId);
    env.delete_Tenant(txn, tenantId);
}

void updateTenant(lmdb::txn &txn, uint64_t tenantId, const tao::json::value &patch) {
    auto view = env.lookup_Tenant(txn, tenantId);
    if (!view) throw herr("unknown tenant");

    std::string newSettings = TenantSettings::mergePatch(view->settings(), patch);
    std::optional<std::string> newSlug;

    if (auto *slugVal = patch.find("slug")) {
        if (!slugVal->is_string()) throw herr("slug must be a string");
        std::string slug = slugVal->get_string();

        if (slug != view->slug()) {
            validateSlug(slug);
            if (env.lookup_Tenant__slug(txn, slug)) throw herr("slug already taken: ", slug);
            newSlug = slug;
        }
    }

    defaultDb::environment::Updates_Tenant upd;
    upd.settings = newSettings;
    if (newSlug) upd.slug = *newSlug;

    env.update_Tenant(txn, *view, upd);
}

void storeComputedUniverse(lmdb::txn &txn, uint64_t tenantId, uint64_t computedAt, const std::vector<UniverseMember> &members) {
    env.delete_TenantUniverse(txn, tenantId);
    env.insert_TenantUniverse(txn, tenantId, computedAt, serializeComputedMembers(members));
}

flat_hash_set<Bytes32> parsePubkeyList(std::string_view commaSeparated) {
    flat_hash_set<Bytes32> output;

    size_t pos = 0;
    while (pos < commaSeparated.size()) {
        auto end = commaSeparated.find_first_of(", \t\n", pos);
        if (end == std::string_view::npos) end = commaSeparated.size();
        auto item = commaSeparated.substr(pos, end - pos);
        pos = end + 1;
        if (item.empty()) continue;

        try {
            output.insert(parsePubkey(item));
        } catch (std::exception &e) {
            LW << "Banyan: ignoring invalid pubkey in list: " << item;
        }
    }

    return output;
}


}
