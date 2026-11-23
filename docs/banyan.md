# Banyan relay

This fork of strfry implements the Banyan relay described by Jay in [Conceptualizing the Banyan Relay](https://njump.me/naddr1qqsxxmmwvdjhqar4v9kxj7nfdenj6argv5kkyctw09skuttjv4kxz7gzypld04wr40cxlgwqpacls7v9va5lg6kfyd2vz2dna42ky5rfyl3qqqcyqqq823c9lrxc8): a relay that collects the notes of the people you trust, where trust comes from mutual engagement rather than follow lists.

One server hosts many Banyan relays. An admin adds people, and each person gets a virtual relay:

    wss://relay.example.com/alice
    wss://relay.example.com/npub1...

The article builds on Neo4j. This implementation does not: the engagement graph is read straight from strfry's LMDB indexes (`#p`, `#P`, author and kind indexes), which is enough for the two-hop traversal the trust machine needs.

## How it works

### Virtual relays

All events live once in the shared LMDB database. A virtual relay is a view over it, scoped to its owner's **universe**:

* the owner,
* the people the admin pinned,
* the primary trust circle,
* the secondary trust circle.

Reads (`REQ`, `COUNT`, `NEG-OPEN` and live events) only return events whose author is in the universe. The scope is applied inside the DB scanner before `limit` is counted, so a `limit: 50` query returns 50 visible events. Filters on kinds alone walk the universe's authors instead of the whole kind index, up to 10,000 author and kind pairs.

Gift wraps (`kind:1059`) are signed by random keys, so they are also served and accepted when their `p` tag is the owner (`banyan.acceptGiftWrapsForOwner`).

Writes (`EVENT`) are accepted only when they would be visible: authored by a universe member, or a gift wrap for the owner. Everything else gets `OK false` with `blocked: author is not in this relay's trust universe`.

NIP-42 AUTH checks the path: the `relay` tag must name this virtual relay (`wss://relay.example.com/alice` or its npub form), so a signature for one virtual relay never opens another.

`GET /<slug>` with `Accept: application/nostr+json` returns a NIP-11 document for that virtual relay. Without it, a small landing page shows the relay URL.

WebSocket connections on `/` and on unknown paths get a `NOTICE` and are closed. Over HTTP, `/` keeps strfry's landing page and NIP-11 and also receives the admin API calls, `/admin` serves the admin page, and `/metrics` is unchanged.

### Trust machine

For a seed `S`, the engine reads what `S` published and what mentions `S`, within `banyan.trust.windowDays`:

| Engagement | Outgoing (S to X) | Incoming (X to S) |
|---|---|---|
| Reply (kind 1 with `e`, kind 1111) | `p` tags of S's event | X's event `p`-tags S |
| Repost (6, 16) | same | same |
| Reaction (7) | same | same |
| Mention, quote, article, highlight (1 without `e`, 30023, 9802) | same | same |
| Zap (9735) | receipts whose zap request S signed | receipts for S whose zap request X signed |

Each engagement is weighted (per-person weights, defaults in `banyan.trust.weight*`), divided by the number of `p` tags of the event, and decays with a half-life of `banyan.trust.halfLifeDays`.

Anyone can publish a zap receipt, so a zap only counts when the zap request in its `description` tag is validly signed by the sender and names the receipt's recipient. Each zap request counts once, however many receipts carry it.

The mutual score is `sqrt(out * min(in, out))`, so one-sided attention (a stranger replying a lot, or you zapping someone who never answers) scores zero. Only `out` is signed by S, while anyone can publish events that mention S, so `in` never counts for more than `out`: flooding S with reactions can't lift someone above S's own engagement with them. For the same reason, incoming engagement is only read from people S engaged with, and a flood of mentions from strangers can't push real engagement out of the scan.

* **Primary circle**: the owner's top `primaryCircleSize` peers with a score of at least `minScore`.
* **Secondary circle**: for each primary or pinned person, their top `secondaryPerPeer` peers. A secondary member keeps the list of people it came through (`via`).

Blocking is applied when the universe is loaded, not when it is computed, so blocking and unblocking take effect immediately. A secondary member whose every `via` is blocked disappears too. Blocked people take no slot in the circles: blocking triggers a recompute, and the next peer moves up.

The universe is recomputed every `banyan.trust.recomputeIntervalSeconds`, when an admin changes the settings, and shortly after the harvester finishes a backfill for one of its seeds (at most every 30 seconds per person). Engagement does not depend on settings, so it is cached per pubkey for 10 minutes and shared by every universe that pubkey seeds. A backfill drops the cached engagement of the pubkeys it fetched.

### Harvester

The harvester fetches the universe's events from the rest of the network, following the outbox model:

* the owner, pinned and primary members are **seeds**: the harvester fetches what they publish, from their NIP-65 write relays, and what mentions or zaps them, from their read relays. That incoming engagement is what the trust machine needs to find the next circle;
* secondary members: only what they publish.

Pubkeys without a known relay list are looked up on `banyan.harvester.bootstrapRelays` (kinds 0 and 10002), which also serve as a fallback. Relays shared by many targets are preferred, and at most `banyan.harvester.maxRelays` connections are kept.

On each relay, the harvester opens live subscriptions (`since: now`) and pages backward through history (`until` pagination, `banyan.harvester.backfillDays` on the first run). Progress is stored per pubkey in the `HarvestState` table, so a restart only fetches what is new. Events are checked against the filter that requested them and their signatures are verified before being written.

uWS resolves DNS and, on macOS, connects with blocking calls, so every relay is first probed on worker threads (DNS plus a TCP connect with a 5 second timeout). Dead relays back off exponentially up to 30 minutes. Relays on private, loopback, link-local or reserved addresses are skipped, both as written in relay lists and once the probe has resolved them.

The loop that makes a Banyan grow:

1. A person is added: their universe is just themselves.
2. The harvester fetches their relay list, their notes and the notes that mention them.
3. The trust machine finds the primary circle.
4. The harvester fetches the primary circle's notes and mentions.
5. The trust machine finds the secondary circle, whose notes are then fetched.

On a first run seeded with a well-connected npub and `backfillDays = 60`, this reached about 145 people and 190k events from 31 relays in three minutes.

## Setup

```
relay {
    bind = "127.0.0.1"
    port = 7777

    auth {
        # Public base URL, without a path. Required for NIP-42, and NIP-98 checks this host.
        serviceUrl = "wss://relay.example.com"
    }
}

banyan {
    admins = "npub1youradminkey..."
}
```

Behind a reverse proxy, open the admin page on the public host (`https://relay.example.com/admin`): NIP-98 requests must name the host of `relay.auth.serviceUrl`, not `localhost`. The page needs a NIP-07 browser extension, and a secure context (https or localhost) for `crypto.subtle`.

Run `make` as usual: the `banyan` app is part of `APPS`. The full list of settings, with defaults, is in the `banyan` section of [strfry.conf](../strfry.conf).

## Admin API

The admin page uses a NIP-86 style JSON-RPC endpoint: `POST /` with `Content-Type: application/nostr+json+rpc` and a NIP-98 `Authorization` header (kind 27235, `u` = `https://<host>/`, `method` = `POST`, `payload` = sha256 of the body). Responses are `{"result": ...}` or `{"error": "..."}`, with status 401 for a bad signature and 403 for a pubkey that is not in `banyan.admins`. Calls run on their own thread, off the WebSocket event loop.

| Method | Params | Result |
|---|---|---|
| `supportedmethods` | | method names |
| `whoami` | | `{ pubkey, isAdmin }` (any signer) |
| `listtenants` | | summaries |
| `addtenant` | `[pubkey, slug]` | summary |
| `removetenant` | `[person]` | `true` |
| `gettenant` | `[person]` | summary, settings, members with circle, score, `via`, name and picture |
| `updatetenant` | `[person, patch]` | detail. `patch` keys: `slug`, `weights` (`reply`, `repost`, `reaction`, `zap`, `mention`), `primaryCircleSize`, `secondaryPerPeer`, `minScore`, `pinned`, `blocked` |
| `recomputetrust` | `[person]` | `true`, runs in the background |
| `harveststatus` | | targets and per-relay connection, subscriptions, events received, last error |

`person` is a slug, an npub or a hex pubkey. Stored settings only hold what was changed, so the config defaults keep applying to the rest.

## CLI

```
strfry banyan list
strfry banyan add <pubkey> <slug>
strfry banyan remove <person>
strfry banyan show <person>
strfry banyan set <person> '{"pinned":["npub1..."]}'
strfry banyan recompute <person>
```

A running relay picks up CLI changes within 5 seconds.

## Tests

`test/tests/banyanTest.js` covers path routing, scoped reads, writes and live events, gift wraps, AUTH bound to the path, per-relay NIP-11, the admin API with NIP-98, and the trust circles on a small engagement graph, including forged and duplicated zap receipts, one-sided floods and blocked members freeing their slot. It needs [nak](https://github.com/fiatjaf/nak) on `PATH` to generate keys and sign events, and runs as part of `test/runTests.sh`. The other test suites run with `banyan.enabled = false`.

## Not done yet

* Graph queries from the article, such as subscribing to a whole thread in one request.
* Sending events to the inbox relays of the people they mention (the distribution side of the outbox model).
* Pruning events that are in no universe. They are trust evidence today, so they stay.
* NIP-42 AUTH towards upstream relays: relays that require it are skipped.
* Letting owners manage their own virtual relay (pins, blocks, weights) through the API.
* Weighting zaps by amount.
* Checking zap receipts against the recipient's LNURL `nostrPubkey`: a signed zap request proves who meant to zap whom, not that the invoice was paid.
* Connecting to the address the probe checked: uWS resolves the host again, so a DNS answer that changes in between (rebinding) is not caught.
