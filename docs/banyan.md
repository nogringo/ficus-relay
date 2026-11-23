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

Reads (`REQ`, `COUNT`, `NEG-OPEN` and live events) only return events whose author is in the universe, and leave out the threads the owner muted (see [Muting threads](#muting-threads)). The scope is applied inside the DB scanner before `limit` is counted, so a `limit: 50` query returns 50 visible events. Filters on kinds alone walk the universe's authors instead of the whole kind index, up to 10,000 author and kind pairs.

Gift wraps (`kind:1059`) are signed by random keys, so they are also served and accepted when their `p` tag is the owner (`banyan.acceptGiftWrapsForOwner`).

Writes (`EVENT`) are accepted when they would be visible: authored by a universe member, or a gift wrap for the owner. Two other kinds of events are accepted and stored, but not served:

* engagement the trust machine reads (see the table below) that mentions the owner, a pinned person or a primary member, within `banyan.trust.windowDays` (`banyan.acceptIncomingEngagement`). Without it, someone whose Banyan is their only inbox would never get a newcomer's replies, and the newcomer could never enter a circle;
* a `kind:5` deleting an event its signer has stored here, since that engagement, and what the harvester fetches, can come from people outside the universe.

Everything else gets `OK false` with `blocked: author is not in this relay's trust universe`.

NIP-42 AUTH checks the path: the `relay` tag must name this virtual relay (`wss://relay.example.com/alice` or its npub form), so a signature for one virtual relay never opens another.

`GET /<slug>` with `Accept: application/nostr+json` returns a NIP-11 document for that virtual relay. Without it, a small landing page shows the relay URL and links the owner to the management page.

WebSocket connections on `/` and on unknown paths get a `NOTICE` and are closed. Over HTTP, `/` keeps strfry's landing page and NIP-11 and also receives the admin API calls, `/admin` serves the admin page, and `/metrics` is unchanged.

### Thread filters

The article asks for a thread in one request instead of recursive filters or the `root` tag hack. A filter can carry a `thread` key with event ids:

    ["REQ", "t", {"thread": ["<event id>"]}]

It matches those events and, recursively, every event that references one of them: through an `e` tag (replies, NIP-22 comments, reactions, reposts, zap receipts), or through an `a` tag when the event is addressable, so comments on an article are found by its address. Any id works as a root, so a sub-thread is asked for the same way. The other filter fields narrow what is sent (`{"thread": [id], "kinds": [1]}` returns the replies without the reactions), and `limit` keeps the newest events of the thread.

The subscription stays open like any other: a new reply to any event of the thread is sent, and becomes part of the thread. Harvested backfills arrive newest first, so a reply can be stored before its parent; when the parent arrives, the replies already waiting for it are sent too. A narrowed subscription still grows through the events it does not send.

On a virtual relay, a thread only grows through events of the universe: a friend's answer to a stranger's reply is not reached through that reply. A thread follows at most `banyan.threads.maxEvents` events (10,000 by default, 0 refuses thread filters). `COUNT` and `NEG-OPEN` accept thread filters too. With `relay.filterValidation.requireAuthorOrTag`, a thread with one root counts like an `e` tag.

### Muting threads

The other half of the article's thread queries: a person can mute a whole thread or a sub-thread, and their relay stops serving the muted event and everything under it, the same tree a thread filter would return. Muted threads come from two places:

* the `mutedThreads` setting of their relay, managed on the admin page or through `updatetenant` (event ids as hex, `note1` or `nevent1`),
* the `e` tags of their NIP-51 mute list (`kind:10000`), so a thread muted in their Nostr client is muted on their Banyan too.

Unlike thread filters, the muted tree also grows through people outside the universe, so a friend's answer to a stranger's reply in a muted thread stays hidden. The muted events are kept in memory per person, at most `banyan.threads.maxMutedEvents` (100,000 by default). A new reply to a muted event is hidden as soon as it arrives, and joins the muted tree within 5 seconds, which hides the replies to it in turn.

Muting only hides: events in a muted thread are still accepted and stored, the trust engine still reads them, and unmuting shows them again.

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

A signed zap request only proves who meant to zap whom. To be counted as paid, the receipt must also be signed by the `nostrPubkey` of the recipient's LNURL server, as NIP-57 asks (`banyan.trust.verifyZapReceipts`). That key comes from the `lud16` or `lud06` of the recipient's profile: the relay asks their LNURL server once, then every 7 days, and keeps the keys it saw, so receipts signed before a change of wallet stay valid. Receipts that can't be checked yet are left out, and the seeds they concern are recomputed once the answer comes. A missing profile is fetched from the bootstrap relays. Outgoing zaps are only checked for people who engaged back, since the others score zero anyway.

Zaps are weighted by amount, read from the receipt's `bolt11` invoice, which must match the `amount` of the zap request when it has one. A zap of `banyan.trust.zapReferenceSats` (100 by default) counts once, and each doubling of the amount adds about one more: `log2(1 + sats / zapReferenceSats)`. 21 sats count 0.3 zaps, 1,000 sats 3.5, 100,000 sats 10. Setting it to 0 counts every zap once.

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

uWS resolves DNS and, on macOS, connects with blocking calls, so every relay is first probed on worker threads (DNS plus a TCP connect with a 5 second timeout). Dead relays back off exponentially up to 30 minutes. Relays on private, loopback, link-local or reserved addresses are skipped, both as written in relay lists and once the probe has resolved them (`banyan.harvester.allowPrivateAddresses` lifts this, for tests and private networks). The WebSocket then connects to the very address the probe checked, while TLS SNI and the `Host` header still name the relay, so a DNS answer that changes in between (rebinding) can't send it to a private address.

#### NIP-42 AUTH

Relays that require NIP-42 get an answer: the harvester signs the `kind:22242` event with its own key, generated on the first start and stored in the `HarvesterKey` table, so other relays always see the same pubkey. It is shown in `harveststatus` and on the admin page, to whitelist it on paid or private relays. A REQ or an event refused with `auth-required:` waits for the AUTH result and is sent again once it succeeds. A relay that refuses the AUTH, or asks for it without a challenge within 30 seconds, is treated as before: the refused requests are dropped and the error shows in the status. `banyan.harvester.auth = false` turns this off.

#### AUTH as the owner, through a remote signer

Some relays only serve a person their own data, like the NIP-17 inbox relays where their direct messages wait, and only after NIP-42 AUTH with that person's key. The server never holds an owner's key, so an owner can connect a NIP-46 remote signer instead (`banyan.signer.enabled`), from the admin page or the API:

* `bunker://` URL: the owner pastes the URL their signer gives them. The relay sends `connect` with its secret, asking only for `sign_event:22242`;
* `nostrconnect://` link: the relay makes one, with the relays of `banyan.signer.relays`, and the owner pastes it in their signer app, which answers with the link's secret.

Either way, the relay then checks with `get_public_key` that the signer holds the owner's key. The client key and the session are stored in the `TenantSigner` table, so a restart does not ask again. Messages are encrypted with NIP-44.

Once the signer is connected, the harvester opens a session of the owner's own on each of their relays: NIP-17 DM relays (`kind:10050`) first, then their read and write relays, at most 8. Each session asks the signer to sign the `kind:22242` for its challenge, so these relays see the owner signing in, and fetches what the owner publishes, what mentions them, and their gift wraps, which are dated up to two days in the past (NIP-59) and are fetched with that margin. The owner's data on those relays is fetched only through these sessions, and the owner's own events published there go through them too. A signer that does not answer within 60 seconds counts as a refused AUTH, and an `auth_url` it sends back shows on the admin page.

#### Inbox and outbox delivery

The harvester also distributes, as the article's outbox model suggests. When an event is stored, from a client or from the harvester, and its author is in a universe, it is sent to the NIP-65 read relays of the members of that universe it mentions (`p` tags). Only mentions count: replies, reposts, reactions, comments, highlights and articles (kinds 1, 6, 7, 16, 1111, 9802, 30023), not follow or mute lists. People outside the author's universe get nothing, and an event is not sent back to a relay the harvester received it from.

What people of a universe publish on a virtual relay also goes to their own NIP-65 write relays (`banyan.distributor.publishToOutbox`), at most 8 of them, so a client can use its Banyan as its only relay and still be read elsewhere. This covers every kind but gift wraps and ephemeral events, and skips NIP-70 protected events, which only their author may publish. Events accepted from outside the universe are not sent.

Delivery starts from the relay's start and covers events newer than `banyan.distributor.maxAgeSeconds` (one day by default). It reuses the harvester's connections, and opens at most 20 others, closed after two minutes without work. Each relay gets at most 20 events in flight and 1,000 waiting. `harveststatus` counts the events sent to each relay, and in total those delivered to inboxes and those published to their authors' relays. `banyan.distributor.enabled = false` turns both off.

The loop that makes a Banyan grow:

1. A person is added: their universe is just themselves.
2. The harvester fetches their relay list, their notes and the notes that mention them.
3. The trust machine finds the primary circle.
4. The harvester fetches the primary circle's notes and mentions.
5. The trust machine finds the secondary circle, whose notes are then fetched.

On a first run seeded with a well-connected npub and `backfillDays = 60`, this reached about 145 people and 190k events from 31 relays in three minutes.

### Pruning

Events stay in the database when no virtual relay serves them, because the trust machine may need them. Pruning deletes the others, and keeps:

* everything authored by someone in a universe, and by the people blocked or hidden behind a blocked member, so unblocking stays immediate;
* gift wraps for an owner;
* engagement the trust machine reads: events of an engagement kind, within `banyan.trust.windowDays`, that mention (`p`) the owner, a pinned person or a primary member of some universe, blocked ones included, and zap receipts that name one of them as sender (`P`);
* deletions (`kind:5`) within `banyan.trust.windowDays`, so the harvester can't store a deleted event again.

So what goes is the history of people who left every universe, and what strangers published without mentioning a seed. When someone's history is pruned, their harvester progress is reset, so if they come back into a universe their history is fetched again.

Pruning is off by default, since it deletes data: `banyan.prune.enabled = true` runs it 10 minutes after the start, then every `banyan.prune.intervalSeconds`. `strfry banyan prune --dry-run` tells what would go. With no virtual relay at all, nothing is pruned. It scans the pubkey index and skips each kept author with one seek, and deletes in batches of 10,000 so writes are not blocked for long.

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

Run `make` as usual: the `banyan` app is part of `APPS`. Zap checks need libcurl (`libcurl4-openssl-dev` on Debian and Ubuntu). The full list of settings, with defaults, is in the `banyan` section of [strfry.conf](../strfry.conf).

## Admin API

The admin page uses a NIP-86 style JSON-RPC endpoint: `POST /` with `Content-Type: application/nostr+json+rpc` and a NIP-98 `Authorization` header (kind 27235, `u` = `https://<host>/`, `method` = `POST`, `payload` = sha256 of the body). Responses are `{"result": ...}` or `{"error": "..."}`, with status 401 for a bad signature and 403 for a pubkey that may not make that call. Calls run on their own thread, off the WebSocket event loop.

Owners manage their own relay with the same API and the same page, signing with their own key: `listtenants` returns only their relay, and `gettenant`, `updatetenant`, `recomputetrust` and the signer methods only accept it. They can change weights, circle sizes, the minimum score, pins, blocks and muted threads, and connect a remote signer, within the server's limits (`banyan.owners.maxPrimaryCircleSize`, `maxSecondaryPerPeer`, `maxPinned`, `maxMutedThreads`), since everyone shares one harvester. Only admins add or remove people, change a slug or see the harvester. `banyan.owners.enabled = false` keeps the API admin-only.

| Method | Params | Result |
|---|---|---|
| `supportedmethods` | | method names |
| `whoami` | | `{ pubkey, isAdmin, tenant }`, plus `ownerLimits` for an owner (any signer) |
| `listtenants` | | summaries |
| `addtenant` | `[pubkey, slug]` | summary |
| `removetenant` | `[person]` | `true` |
| `gettenant` | `[person]` | summary, settings, members with circle, score, `via`, name and picture, `muted` (`hiddenEvents`, `fromMuteList`) and `signer` |
| `updatetenant` | `[person, patch]` | detail. `patch` keys: `slug`, `weights` (`reply`, `repost`, `reaction`, `zap`, `mention`), `primaryCircleSize`, `secondaryPerPeer`, `minScore`, `pinned`, `blocked`, `mutedThreads` |
| `recomputetrust` | `[person]` | `true`, runs in the background |
| `connectsigner` | `[person, bunkerUrl]` | signer |
| `nostrconnect` | `[person]` | signer, with the `nostrconnect://` link to paste in a signer app |
| `removesigner` | `[person]` | `null` |
| `harveststatus` | | targets, AUTH pubkey, events delivered to inboxes and published to outboxes, and per relay: role (`harvest`, `owner` with `authAs`, `signer`), connection, AUTH state, subscriptions, events received and sent, last error |

`person` is a slug, an npub or a hex pubkey. Stored settings only hold what was changed, so the config defaults keep applying to the rest.

`signer` is `null`, or `{ state, signerPubkey, relays, connectedAt, lastError, authUrl }`, plus `nostrconnect` while waiting for a signer app. `state` is `waiting`, `connecting`, `verifying`, `ready` or `failed`.

## CLI

```
strfry banyan list
strfry banyan add <pubkey> <slug>
strfry banyan remove <person>
strfry banyan show <person>
strfry banyan set <person> '{"pinned":["npub1..."]}'
strfry banyan recompute <person>
strfry banyan prune [--dry-run]
```

A running relay picks up CLI changes within 5 seconds. `recompute` asks the LNURL servers of the zap recipients it can't check yet before printing the circles, so it can take a few seconds.

## Tests

`test/tests/banyanTest.js` covers path routing, scoped reads, writes and live events, engagement and deletions accepted from outside the universe, gift wraps, AUTH bound to the path, per-relay NIP-11, the admin API with NIP-98, owners managing their own relay, the trust circles on a small engagement graph (including forged and duplicated zap receipts, receipts not signed by the recipient's LNURL server, which a fake LNURL server answers, amounts that differ from the request, bigger zaps weighing more, one-sided floods and blocked members freeing their slot), thread filters (stored, live, out of order, through an article's address), muted threads (by setting and by mute list, live, growing, unmuted), and pruning. A last phase restarts the relay with the harvester pointed at fake relays: an upstream that refuses everything before NIP-42 AUTH, where the harvester authenticates, fetches, delivers a reply to the inbox of the person it mentions, and publishes notes to their authors' write relays; a bunker holding the owner's key, connected through `bunker://` then `nostrconnect://`; and a DM relay that only serves gift wraps to their recipient, where the harvester signs in as the owner through the bunker. It signs its events with nostr-tools (installed by `npm ci` in `test/`), and runs as part of `test/runTests.sh`. The other test suites run with `banyan.enabled = false`. The relay's logs are left in `strfry-banyan-tests/relay.log` under the system temp directory.

## Limits

* The private part of a NIP-51 mute list is encrypted to its owner, so only its public `e` tags mute threads here.
* A reply to a muted event is hidden at once, but a reply to that reply only once the muted tree has caught up, within 5 seconds.
* Zap checks trust the recipient's own LNURL server: it can sign receipts for invoices that were never paid.
* The harvester's TLS connections (uWS client) do not verify certificates, so connecting to the checked address protects against rebinding to a private network, not against an attacker on the path.
* A relay shared by several owners with a remote signer gets one connection per owner, plus the shared one.
