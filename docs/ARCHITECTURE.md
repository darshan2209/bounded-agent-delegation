# Laboratory architecture

Five containerised components, orchestrated from a single compose file so the environment stands up
reproducibly. The design is vendor-neutral so that the result is a property of the mechanism rather
than of any one cloud provider.

```
  human principal
        |
        v
   [ idp ]  OpenID Connect authorisation server, hosts the token-exchange endpoint
        |
        v
  [ agent ]  over-scoped AI-agent workload, reaches tools over MCP
        |
        v
  [ broker ]  RFC 8693 token exchange   <-- the component under test
        |          passthrough | enforcing
        v
 [ resource ]  mock SaaS data API (bulk-query and record-read endpoints)
        |
        v
 [ logsink ]  captures every issuance, exchange, refusal and presentation
```

## The bounded token shape

| Property | Value enforced | Primitive property closed |
|----------|----------------|---------------------------|
| `aud` | exactly one resource server | revocation boundary |
| `scope` | least privilege for the task, never the inherited scope | delegated scope |
| `exp` | minutes, no refresh | trust-compounding step |
| `act` / `may_act` | delegation recorded and pre-authorised | principal |

## Why the chain breaks where it does

The disruption sits between `T1550.001` (present the stolen token) and `T1078.004` (operate as a
broadly privileged cloud account). A token pinned to one audience cannot be re-pointed at the wider
API surface, so the pivot has nothing to consume. This is a property of the token shape, not of the
implementation, which is why the result follows from the specification rather than from a fortunate
configuration.
