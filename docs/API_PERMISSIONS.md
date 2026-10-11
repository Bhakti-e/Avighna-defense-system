# Offline API permissions (development, unreleased)

The API binds to loopback only. The offline middleware checks authentication and
database-backed permissions before dispatch. JWT expiry is required; role claims
inside a token cannot grant privileges. Missing/invalid tokens return 401.
Inactive accounts, unknown roles and insufficient permissions return 403.

| Surface | Permission | Current behavior |
|---|---|---|
| GET /, /health; POST /auth/login, /auth/signup | Public on loopback | Signup always creates a user, never an administrator |
| OPTIONS | CORS preflight | No collection or enforcement |
| Inventory, alerts, statistics, report list/download, incident details, /auth/me, API documentation | Active user/viewer/analyst/admin | Authenticated read only |
| POST /auth/logout | Active reader | Client must remove its token; no server-side token revocation list |
| Discovery, ingestion, diagnostics, simulation, report generation, device registration, containment and every other route | Admin gate, then offline prohibition | 503 even for admin; no action dispatched |

Readers receive 403 on disabled action paths; missing credentials receive 401.
Legacy effectful routers remain unmounted. The investigation router additionally
contains no command executor and requires admin if mounted in future.
There is no dashboard administrator-provisioning flow in this increment.

Dashboard API calls attach the saved token only to the configured API origin.
A 401 removes the local session and returns to login. A 403 raises a permission
error without clearing the session. The command console has been removed.

## Verification and limitations

Backend: 70 tests passed, 7 deprecation warnings. Frontend helper tests cover
token forwarding, refusing another origin, expired sessions, and permission errors.
The offline tests forbid process/network actions and use isolated databases.
These results do not establish security of the disabled legacy online modules.

Manual validation remains pending: follow docs/MANUAL_VALIDATION.md.
Persistent audit logging, rate limiting, server-side logout revocation, safe agent
enrollment/ingestion and positive authorized-discovery tests remain future work.
Authentication does not make the existing reports evidence-correct; Stage 4
must address their content and time range before generation is enabled.
