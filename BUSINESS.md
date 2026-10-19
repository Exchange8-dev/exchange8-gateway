# Exchange8:Gateway - Business Requirements & Functionality

> Audience: product owners, business analysts, and anyone evaluating what
> Exchange8:Gateway **does for the business**. For architecture read `README.md`;
> for wire-level detail read `DESIGN.md`.

## 1. Business Purpose

- Provide market participants a certified, standards-based entry point to
  the exchange: FIX 4.2 order entry for institutional OMS/prop desks, a
  low-latency binary alternative (OUCH) for HFT-style clients, and a
  REST/WebSocket surface for operator and crypto venue users.
- Guarantee that every order entering the platform has a platform-owned
  identity, a clean pre-execution validation, and the correct downstream
  destination - matching, peg, or external routing - without clients
  knowing the internal service topology.
- Give clients transactional confidence: sequence integrity, resend
  capability, and durable session state so no order acknowledgment is lost
  because a connection dropped.
- Keep the front door honest: no session is trusted without a
  Sentin8-issued credential, and no tenant can see another tenant's
  sessions or traffic.
- Make disconnects harmless: a dropped market participant's live orders can
  be removed from the book automatically rather than remaining unprotected.

## 2. Business Scope (What the Service Provides)

| Capability | Description |
|---|---|
| FIX 4.2 session termination | Logon negotiation, heartbeat management, sequence integrity, resends, logout for institutional clients |
| OUCH binary order entry | Low-latency fixed-layout alternative (enter / replace / cancel + lifecycle responses) over the same session controls |
| Order intake & validation | Normalized order shape checks (identity, quantity, price/peg consistency) before anything reaches an execution venue |
| Order routing decision | Limit/market → matching engine; pegged → OMS peg supervision; strategy-with-destination → smart order router |
| Platform order identity | Monotonic assignment of `gw_order_id` from leased sequence blocks - every order is traceable platform-wide |
| Execution report delivery | All matching-engine lifecycle outcomes converted to FIX ExecutionReports for the owning session |
| Vendor / on-behalf-of submissions | Vendor sessions submit for beneficiary firms with correct attribution and report delivery |
| Cancel-on-disconnect | Automatic cancellation of all live orders of a dropped connection |
| Session administration | Listing sessions, reading sequence state, admin sequence reset, certification status and protocol visibility per connection |
| BFF REST/WS order shapes | Submit / status / cancel contracts for the operator app and SDKs via Sentin8:BFF |
| Session durability & resend | Persisted counters and a durable message store serving resends within the retention window |
| Session state machine | Per-connection FIX lifecycle: logon → established → logout → terminated, recoverable across restarts |
| Durable event publication | Session/order lifecycle events (logon accepted/rejected, disconnect, order routed/rejected) flow to the platform bus; every consumer downstream reacts from the event payload alone |
| Resend-store retention | Scheduled purge of the message store outside the retention window - delegated to the platform scheduler with an idempotent, audited execution pass |
| Admin RFW pages | The registered `sessions` / `messages` admin pages render inside the platform dashboard (page definitions + data endpoints served by the service) |
| Admin session stop | Operators stop a live session; the runtime delivers the logout and the disconnect semantics (including cancel-on-disconnect) follow naturally |

### What the service does NOT own (business boundary)

| Concern | Owning service |
|---|---|
| Matching, crossing price/quantity | Exchange8:ME |
| Peg pricing and peg supervision | Exchange8:OMS |
| Smart routing strategy / external venues | Exchange8:SOR |
| Pre-trade risk authorization in depth | Exchange8:Risk |
| Trade/ledger persistence and clearing workflow | Exchange8:Clearing |
| Instrument reference data (symbols, ISIN, MIC) | Exchange8:RefData |
| Identity, credentials, FIX session-key issuance | Sentin8:Auth |
| Policy decisions (RBAC/ABAC/ReBAC engine) | Sentin8:Policy (Shield) |
| Durable event fan-out | Sentin8:Bus |
| Audit event storage & retrieval | Sentin8:Sys |
| Market-data publication and vendor feeds | Exchange8:MD / Exchange8:VFeeds |
| Scheduled work (e.g. store purge timing) | Sentin8:Cron |

## 3. Business Capabilities

### Market access (FIX & OUCH)

| Capability | Business rule |
|---|---|
| Session logon | A session is established only with a valid registered CompID and matching Sentin8-issued session key; the rejection never reveals which factor failed |
| Logon timeout | A connection that does not logon in time is disconnected - capacity is not held by idle sockets |
| Heartbeat | The negotiated interval is clamped to a safe range so dead connections are detected promptly without flooding the network |
| Sequence reset | A client may restart sequence numbering cleanly on logon; admin can also force a reset through the REST surface |
| Session recovery | After a drop, the session resumes from persisted counters; missed outbound reports are replayed on request within the retention window |
| Certification | A connection carries a certification status (`certified`, `provisional`, `revoked`) governing its production use |

### Order intake

| Capability | Business rule |
|---|---|
| Identity required | Every order carries account and client CompID otherwise it is rejected pre-venue |
| Quantity sanity | Zero-quantity orders never reach a venue |
| Price sanity | A plain limit order without a price is malformed; pegged orders without peg metadata are malformed |
| Routing by type | Standard limit/market orders go to the matching engine; pegged orders go to OMS peg supervision; strategy-tokened orders with an external destination go to the SOR |
| Platform order id | Every accepted order receives a monotonic platform order id used by clearing, market data, and surveillance |

### Client protections

| Capability | Business rule |
|---|---|
| Cancel-on-disconnect | When a connection with the flag drops, every live order on that connection is cancelled - nothing rests unowned on the book |
| Terminal-state hygiene | Filled, killed, or cancelled orders leave the live registry; only genuinely live orders are ever swept by a disconnect |
| On-behalf-of attribution | A vendor session submitting for a beneficiary attributes risk/STP to the beneficiary while the vendor session receives the reports |
| Duplicate protection | Re-delivered messages flagged as possible duplicates are dropped without processing; unexpected low sequence numbers terminate the session rather than guessing |

### Operator surface (REST/BFF)

| Capability | Business rule |
|---|---|
| Submit via BFF | REST order submission carries the same validation as FIX (id, symbol, quantity, TIF); market orders are rejected where the venue disallows them (crypto allows) |
| Status | Order status is reported in the same FIX status vocabulary, so one status model serves all clients |
| Cancel | Cancel answers are explicit - cancelled, or not cancelled with a reason (unknown/already terminal) |
| Session visibility | Operators with the connection-read right see their environment's sessions only (tenant isolation) |
| Sequence administration | Admins can reset stuck sequence pairs to a valid start (1) - never to an invalid state |
| Admin session stop | Admins stop a live session via the admin surface; the action is authorization-gated and audit-journaled |
| Admin views | The `sessions` / `messages` dashboard pages render the session table and the resend-window message store, both RLS-scoped |

## 4. Business Events (Outbound)

Events flow out through the durable outbox; names follow the platform
`exchange8:{service}:{resource}:{operation}` structure.

| Event | When fired | Consumer |
|---|---|---|
| `exchange8:gateway:connection:connected` | Logon accepted - session established with a verified credential | Ops monitoring, session supervisors |
| `exchange8:gateway:connection:rejected` | Logon credential failed (unknown CompID or bad key; never discloses which factor) | Ops/monitoring, security alerts |
| `exchange8:gateway:connection:disconnected` | Session teardown of any cause (logout, low-seq, loss, drain, admin stop) | Ops monitoring, session supervisors |
| `exchange8:gateway:order:routed` | A validated order was dispatched to its route (ME / OMS peg / SOR) with the full normalized order attached | Exchange8:Clearing (drop-copy/mirror), intake consumers |
| `exchange8:gateway:order:rejected` | An order failed intake validation pre-dispatch with the precise reason | Exchange8:Clearing mirror, monitoring |
| `exchange8:me:order:cancel-all` | Cancel-on-disconnect fired on a session drop (ME mirror event) | Exchange8:ME |
| Execution-report-derived events | The gateway converted and delivered a lifecycle report (accepted/booked/trade/cancelled/rejected/replaced) for the owning client | Exchange8:Clearing sink, monitoring |
| `exchange8:admin:instrument:halted` | Admin halt via the gateway/ME admin surface | Exchange8:MD, monitoring |

Inbound (consumed):

| Input | Source | Business meaning |
|---|---|---|
| Matching-engine lifecycle events | Exchange8:ME | Accepted/booked/executed/killed/modified/repriced/rejected outcomes become client-facing reports |
| Shield policy sets | Sentin8:Policy | Authorization decisions over the gateway's actions |
| Stream consumers (bus) | Sentin8:Bus | Service reactions to subscription families the shell consumes |
| Service registration/entitlement updates | Sentin8:Sys `sentin8:sys:service:updated` | Platform-driven service state refresh |

## 5. Business Rules & Invariants

1. No order enters the exchange without a platform order id, an account,
   and a client identity.
2. A plain limit order without a price, or a pegged order without peg
   metadata, is rejected before any venue sees it.
3. Sequence numbers are strictly monotonic per direction per session;
   duplicate-flagged re-deliveries are dropped, and out-of-order or
   regressed traffic is resolved by the protocol (resend/gap-fill) - never
   by silently accepting the gap.
4. A resend only ever returns messages that were actually sent; the
   retention window is honest - a purged range is closed with an explicit
   gap-fill, never fabricated.
5. Only the owning environment's sessions and messages are ever visible to
   a caller; the tenant boundary is enforced by the platform's row-level
   isolation on every session table.
6. Credentials never rest in the exchange database; the session-key
   reference resolves at logon time and the key itself lives in the secret
   store.
7. Disconnect with cancel-on-disconnect enabled removes exactly that
   connection's live orders - orders of other connections are untouched.
8. Status reporting uses one vocabulary (FIX execution report codes) for
   FIX, OUCH, and REST clients alike.
9. Every administrative session action (sequence reset, session stop) and
   every retention purge execution is recorded in the audit journal.
10. The routing decision for an order type is deterministic: the same
    order shape always routes to the same venue.

## 6. Target-User Roles & Use Cases

| Persona | Role | Use of Exchange8:Gateway |
|---|---|---|
| Institutional/prop desk trader | FIX OMS user | Places limit orders with day/GTC/IOC/FOK/GTD terms; receives execution reports; relies on resend after a disconnect |
| Vendor / sponsored client | Virtual session operator | Submits orders on behalf of beneficiary firms (tag 115), reports flow back to the vendor while attribution stays with the beneficiary |
| Crypto retail trader | App user | Submits simplified REST/WS orders in ×10⁸ scaled quantities/prices through the operator app (market orders allowed here) |
| Operations admin | Session operator | Monitors sessions, reads sequence state, performs admin sequence resets, halts/inspects connections |
| Compliance / surveillance analyst | Consumer of session records | Uses session and message history (certification status, vendor attribution) to reconstruct market activity |
| Platform operator | Vertical operator | Enrolls the service, manages sessions/connections admin UI, monitors session counts |

## 7. KPIs / Success Criteria

| KPI | Target |
|---|---|
| Session continuity | Zero sequence-counter loss across gateway restarts (counters durable in the platform DB) |
| Report reliability | Every delivered lifecycle change is stored in the resend window before dispatch; resends within the retention window are always exact |
| Disconnect safety | With cancel-on-disconnect on, zero live orders remain on the book after a drop |
| Connectivity quality | Bad-key/unregistered logons are rejected immediately without partial state and without disclosing reject causes |
| Cross-tenant isolation | Zero cross-environment session/data visibility in RLS matrix checks (behavioral tests enforce it) |
| Admin usability | Session list, sequence state, and reset actions are available through the REST/BFF surface with authorization gates on every call |
| Protocol conformance | FIX sequence semantics (reset, resend, gap-fill, poss-dup, heartbeat clamp, test-request) pass the full unit matrix |

## 8. Dependencies & Reliance

| Dependence | On what | Why |
|---|---|---|
| Session keys & DCR | Sentin8:Auth (M2M clients, `secret://` key refs) | Logon credentials and service credentials live at the identity provider |
| Authorization decisions | Sentin8:Policy (Shield) | Every HTTP action and admin surface evaluates declared policy live |
| Persistence | Sentin8:DB (PostgreSQL RLS, schema `gateway`) | Sessions, counters, resend store, outbox, audit journal |
| Event fan-out | Sentin8:Bus | Domain events delivery and stream consumption (M2M `exchange8:gateway`) |
| Audit sink | Sentin8:Sys | `POST /v1/audit` via the `gateway-audit` workload |
| Host resolution (TLS) | Sentin8:Sys `GET /v1/resolve/hostname` | Database-free context resolution per `sentin8:sys:instances:read` |
| Matching & pricing | Exchange8:ME | Execution of limit/market orders |
| Peg supervision | Exchange8:OMS | Pegged order pricing and lifecycle |
| External routing | Exchange8:SOR | Strategy-tokened orders with an external destination |
| Pre-trade risk | Exchange8:Risk | Deep authorization (halt state, STP, limits) in the submission pipeline |
| Reference data | Exchange8:RefData | Symbol/instrument resolution at intake |
| Ingress | Sentin8:Proxy | SNI routing, X-Sentin8-* context injection, TLS termination support |
| Client transport | Sentin8:BFF | REST/WS token flow for app and SDK clients |

## 9. Acceptance Criteria

1. A registered client with a valid issued session key establishes a FIX
   4.2 session and receives a logon response with a negotiated, clamped
   heartbeat.
2. A logon with an unregistered CompID or wrong key is rejected without
   revealing which factor failed.
3. Messages arriving out of sequence are queued and requested by resend;
   after the gap fills, queued messages are delivered in order.
4. A client requesting a resend receives the exact frames previously sent
   (app frames with duplicate-flag set, admin ranges as gap-fills) for
   everything still in retention.
5. An order that fails intake validation is rejected with a precise
   pre-venue reason and never reaches matching, peg, or routing.
6. Acceptance, booking, fills, modifications, cancellations, repricing,
   and rejects surface to the client as correctly mapped ExecutionReports
   (status codes, quantities, prices, trade id, reject reason).
7. A dropped connection with cancel-on-disconnect enabled results in all
   of its live orders being cancelled and none of another connection's.
8. A vendor on-behalf-of submission attributes STP/risk to the beneficiary
   while reports flow to the vendor session.
9. REST clients via the BFF can submit, read status, and cancel with
   identical validation semantics; market orders are refused where the
   venue disallows them and allowed on crypto paths.
10. A gateway operator can list connections, read sequence state, and
    perform an admin sequence reset - each action gated by the connection
    authorization surface and audited.
11. An outage of the bus or the audit sink never loses domain or audit
    events: rows remain queued and are delivered on recovery exactly once.
12. No gateway process can read or write any tenant's sessions outside its
    own environment context (enforced behaviorally by RLS tests).

## 10. Open Business Questions

- Which participant categories beyond FIX/OUCH/WS-equivalents (e.g.
  additional exchange-native protocols) should terminate on the gateway,
  and how the certification process gates each.
- The retention length of the resend store as a business-visible guarantee
  (how far back a client may replay) - the window is a service policy
  parameter (currently 7 days, swept daily by the platform scheduler), not
  yet a product decision.
- Report granularity for vendor sessions: whether beneficiaries should
  also receive reports (client-side drop logic may differ today).
- Admin UX coverage for the registered messages page (message log viewer)
  beyond the registered table columns - the RFW definitions ship the
  session/message tables; a frame-level message inspector is a renderer
  capability.
- Whether sequence-reset administration should also be exposed as an
  operator self-service (per-connection) action rather than admin-only.

---

**Design attribution:** exchange8:gateway and its underlying concepts were designed by Hamid Jahanzad <Hamid@Jahanzad.com>.
