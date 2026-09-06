# Cloudflare platform verification

Checked on 2026-09-06 against official Cloudflare documentation, Wrangler's
published JSON schema, generated binding types, and the installed package type
definitions. A page's “last updated” label is recorded only as documentation
freshness; it is not treated as a feature launch date.

## Locked implementation inputs

| Input | Version / value | Verification use |
| --- | --- | --- |
| Wrangler | `4.129.0` | Configuration schema, binding type generation, bundle/dry-run |
| `@cloudflare/containers` | `0.3.7` | `Container`, `getContainer`, `ContainerProxy`, egress interception |
| `@cloudflare/workers-types` | `5.20260905.1` | Current Worker/D1/DO/Queue compile-time APIs accepted by the lockfile minimum-age policy |
| `@cloudflare/vitest-pool-workers` | `0.22.0` | Local workerd-backed binding tests |
| Vitest | `4.1.11` | Version compatible with the Workers pool peer range |
| Production compatibility date | `2026-09-06` | Current-date production build; never silently lowered for deployment |

The Workers pool currently bundles a workerd build whose newest accepted date is
older than the production date. Tests may use a separate, explicitly named
configuration at the newest date supported by that workerd, but production
configuration and generated types remain current. Such a run is local runtime
evidence, not proof of the newer compatibility date or remote Containers.

## Verified contracts and resulting decisions

### Containers

- [Containers overview](https://developers.cloudflare.com/containers/):
  Containers are attached to Workers, use `Container`/`getContainer`, run on the
  Workers Paid plan, and can be developed locally with `wrangler dev`. The first
  resource target is the current `basic` instance (1/4 vCPU, 1 GiB memory, 4 GB
  disk), subject to measurement rather than assumed capacity.
- [Connect to Workers and bindings](https://developers.cloudflare.com/containers/configuration/workers-connections/):
  `outboundByHost` intercepts a Container HTTP request to a virtual hostname and
  executes a Worker handler with bindings. The implementation therefore uses
  `http://sub2api.internal`; it does not call Cloudflare's public REST API and
  does not place an account-management token in Go.
- [Container lifecycle](https://developers.cloudflare.com/containers/concepts/architecture/):
  the lifecycle class is a Durable Object, default idle sleep is ten minutes,
  disk/process placement is not durable application state, and shutdown sends
  SIGTERM before an eventual SIGKILL (up to fifteen minutes). The branch chooses
  an explicit shorter idle policy and a bounded Go shutdown, while correctness
  remains in D1/business DO/outbox state.
- Published Container package types additionally confirm `envVars`,
  `interceptHttps`, `enableInternet`, `allowedHosts`, `outboundByHost`, and the
  required `ContainerProxy` export. HTTPS fixture interception and Go runtime
  environment are configured explicitly rather than inferred from Worker vars.
- [Outbound traffic guidance](https://developers.cloudflare.com/containers/guides/outbound-traffic/)
  confirms that HTTPS interception creates an ephemeral CA at
  `/etc/cloudflare/certs/cloudflare-containers-ca.crt`. The distroless Go image
  points `SSL_CERT_FILE` at that runtime file; the CA is never baked into the
  image. Plain HTTP to the internal binding handler remains inside the
  Cloudflare platform networking boundary.
- The installed SDK stores static egress handlers through inherited setters.
  Native `static field = ...` semantics bypass those setters, which produced a
  real local `Network connection lost` fallback. The implementation now assigns
  handlers after the class declaration, and a structural regression test proves
  the subclass has no shadowing own property. Local HTTP control-plane and HTTPS
  fixture interception both pass after that correction.

### D1

- [D1 database API](https://developers.cloudflare.com/d1/worker-api/d1-database/):
  prepared statements are parameterized; `batch()` executes statements in order
  as a SQL transaction and rolls the sequence back when a statement errors.
  Business conditions such as an `UPDATE` affecting zero rows are not SQL
  errors, so code must inspect mutation metadata or encode the condition in the
  write—it cannot rely on batch rollback alone.
- [D1 read replication](https://developers.cloudflare.com/d1/best-practices/read-replication/):
  replicas are asynchronous. Security/read-after-write paths use primary reads
  or a Session beginning at `first-primary`; bookmarks are the mechanism for
  sequential consistency when replica reads are later introduced.
- [D1 limits](https://developers.cloudflare.com/d1/platform/limits/): at the
  verification date, a string/BLOB/row is limited to 2 MB, a SQL statement to
  100 KB, and a query to 100 bound parameters. IDs and exact values therefore
  use compact decimal text, while prompts, full responses, images, and files are
  outside the unconditional D1 data model.

### Durable Objects

- [SQLite storage API](https://developers.cloudflare.com/durable-objects/api/sqlite-storage-api/):
  `transactionSync()` is available only for SQLite-backed objects, rolls back on
  an exception, and permits only synchronous storage work in the callback. The
  account lease critical sections use it; alarms are cleanup accelerators and
  may run late, so lazy expiry checks remain authoritative.
- [Durable Object rules](https://developers.cloudflare.com/durable-objects/best-practices/rules-of-durable-objects/):
  non-storage I/O such as `fetch()` permits request interleaving. No external
  fetch or D1 call occurs inside the account lease transaction, and no long
  upstream request is held under a DO critical section.

### KV and Queues

- [How KV works](https://developers.cloudflare.com/kv/concepts/how-kv-works/):
  KV is eventually consistent and a write can remain invisible elsewhere for
  sixty seconds or more. Only a rebuildable model/config alias with a bounded
  TTL is cached; auth, disable/revocation, balances, leases, and credentials are
  never KV-authoritative.
- [Queue delivery guarantees](https://developers.cloudflare.com/queues/reference/delivery-guarantees/):
  delivery is at least once and rare duplicates are expected. Stable event IDs,
  durable payload hashes, D1 dedupe plus effect, per-message ack/retry, a DLQ,
  and explicit conflict audit are required. “Exactly once” is not claimed.

### Worker limits and testing

- [Workers testing](https://developers.cloudflare.com/workers/testing/): local
  Vitest/workerd tests exercise Worker APIs and bindings. They do not prove a
  remote account, paid Container scheduling, image rollout, or production
  network behavior.
- [Workers limits](https://developers.cloudflare.com/workers/platform/limits/):
  request header limits and account-plan body limits are separate from the
  gateway's own tighter body cap. The external Worker streams the body and
  response; the Go gateway enforces its configured text/body limits instead of
  treating the platform maximum as an application-safe default.

## Locally verified platform behavior

- Linux image build/startup through current Wrangler/Docker integration.
- Virtual-host control-plane interception and HTTPS fixture interception with
  the ephemeral mounted CA trusted by the Go process.
- `wrangler dev` non-streaming and SSE pass-through, Queue consumption,
  five-second lease renewal across 10/15-second silent upstream waits, idle
  sleep/wake, forced process death, restart, and two-instance shared leases.

## Still requiring empirical verification

- Remote paid-plan Container image rollout, D1/DO/Queue behavior, regional
  placement, and remote two-instance concurrency.
- Real authorized upstream TLS, redirects, throttling, cancellation, and error
  behavior; local fixture interception is not a real-provider acceptance test.
- Slow-client backpressure, rolling update, 1/3/10 concurrency, body-size and
  stream-duration profiles, CPU/memory, rows read/written, internal round trips,
  and first-byte overhead.
- Paid-plan cost under measured workload. No zero-cost or QPS claim is made.
