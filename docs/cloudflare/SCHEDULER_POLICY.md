# Scheduler policy foundation

`deploy/cloudflare/src/scheduler-policy.ts` is a pure TypeScript policy function for a later Worker or Durable Object scheduler. It does not read D1, call a Durable Object, inspect a clock, retain a sticky mapping, perform a request, or contain any credential-bearing account fields. It is **not connected to live scheduling** and does not constitute production acceptance.

## Contract and hard eligibility

The caller supplies `nowMs`, required group, platform, account type, model, optional stickiness key, and a bounded account snapshot. Each fact is represented as `confirmed`, `estimated`, or `unknown`.

The policy rejects an account, with the first applicable stable reason code, when any of these gates fail:

- active and schedulable must be confirmed true;
- group membership and platform/type/model capability must be confirmed and match;
- account concurrency, account RPM, and user RPM each require **confirmed** finite integer limit and usage, with `used < limit`;
- confirmed or estimated explicit quota exhaustion rejects;
- a confirmed or estimated temporary-unschedulable or cooldown deadline later than `nowMs` rejects.

Unknown quota exhaustion does not mean exhausted. Unknown remaining quota and health remain eligible once every hard capacity gate passes, but earn no points and are labelled `unknown` in the output. Estimated health and remaining quota may contribute only to ranking and retain their `estimated` flags. Estimated or unknown concurrency/RPM limit or usage can never establish admission capacity and is rejected; only confirmed observations can pass those gates. Estimated active, schedulable, group, and capability facts also reject because those admission facts must be confirmed.

The public function accepts runtime `unknown` and validates the decoded/persisted shape before admission. Nulls, non-objects, missing evidence fields, malformed evidence kinds or values, sparse arrays, and throwing property access fail closed without escaping an exception. `quotaExhausted` values for confirmed/estimated evidence must be actual booleans; strings, numbers, objects, and other truthy/falsy substitutes reject.

Input is bounded to 256 accounts, 64 entries per group or capability list, 19 characters for positive canonical decimal account IDs, 128 characters for stable IDs and selector/list text, and 256 characters for a stickiness key. Text must be non-empty, trimmed, and free of C0/C1 controls and line/paragraph separators. Lists reject holes, non-string entries, duplicates, control characters, and oversized values before membership checks. Timestamps must be safe integers through year 2100, priority is `0..1,000,000`, ratios are finite `0..1`, and capacity integers are `0..1,000,000`. Duplicate canonical account IDs reject the entire request. Invalid values including `NaN` and infinity fail closed.

## Ranking and determinism

Eligible candidates are ranked by a bounded integer score. Ratio inputs are rounded to integer basis points (`0..10,000`) before scoring, so the policy does not depend on floating-point comparison order.

```
score = (1,000,000 - priority) * 1,000,000
      + healthBps * 20
      + (10,000 - concurrencyLoadBps) * 10
      + quotaRemainingBps * 5
      + cooldownReadinessBps * 2
```

Lower numeric account priority wins, matching traditional Sub2API scheduling. The one-priority-step gap is larger than all secondary components combined, so health/load/quota cannot reverse it. `concurrencyLoadBps = floor(inFlight * 10,000 / limit)`. A confirmed inactive/past cooldown gets readiness `10,000`, an estimated inactive/past cooldown gets `5,000`, and unknown cooldown evidence gets `0`. Unknown health or quota gets `0` only as a ranking contribution; output flags preserve the evidence state. Every component and total remains within JavaScript safe-integer range.

Equal totals sort by exact bytewise canonical decimal `accountId`, then exact bytewise `stableId`. The comparison is implemented with UTF-16 code units for the constrained ASCII account IDs, rather than locale collation.

When a caller supplies `stickinessKey`, the policy considers only eligible candidates within 50,000 score points of the top candidate. It applies FNV-1a 32-bit rendezvous hashing to `stickinessKey`, account ID, and stable ID, choosing the highest unsigned hash. This is portable across Workers, browsers, and Node through `Math.imul`; it uses no randomness or ambient time. A candidate that becomes ineligible leaves the sticky pool immediately, so normal eligible failover applies.

## Output and required future state

The decision exposes only `selectedAccountId`, ordered eligible IDs with integer score components/evidence flags, rejected ID/stable-ID pairs with reason codes, and request errors. It never returns an account name, credential, access token, proxy URL, or secret.

A later D1/DO integration still needs to provide an authoritative, bounded snapshot for: account state and group/capability membership; in-flight leases and concurrency reservations; account and user RPM rolling-window counters; quota observations with source/time/confidence; cooldown and temporary-disable deadlines; health measurements; and any durable tenant-to-account stickiness record or versioning strategy. This pure decision cannot make its confirmed capacity snapshot atomic with acquisition. Atomic reservation, lease expiry, counter reconciliation, source freshness, and request-level authorization remain integration responsibilities.

The focused tests cover every eligibility filter, lower-number priority precedence, confirmed-only hard capacity, evidence states, runtime-malformed objects and evidence, text/list/count boundaries, duplicate IDs, numeric/deadline boundaries, input permutation/repetition, sticky selection/failover, bytewise ordering, and output leakage shape.
