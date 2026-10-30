# Money — Production Security Notes

## Implemented in the application

- Passwords are hashed with Node.js `scrypt`; plaintext passwords are never stored.
- Sessions use random opaque tokens; only SHA-256 token hashes are stored in MySQL.
- Session cookies are `HttpOnly`; public HTTPS uses `SameSite=None; Secure`.
- Mutating API requests require a double-submit CSRF token.
- Helmet security headers are enabled without blocking the cross-site Preview iframe.
- JSON body size is limited to 256 KB; saved user state is limited to 2 MB and sanitized.
- Login/register, general API, and AI requests have separate rate limits.
- AI keys are server-side only; the assistant receives only the authenticated user's context.
- Expired sessions are periodically deleted; database state is durable and user-scoped.

## Required before a 50,000-user launch

1. Put the container behind HTTPS, a WAF/DDoS layer, and a managed load balancer.
2. Configure a managed MySQL cluster with automated backups, point-in-time recovery, replicas, and connection pooling/proxying.
3. Set production secrets through the deployment secret manager; never commit `.env` files.
4. Run dependency, SAST, DAST, authentication, authorization, and prompt-injection reviews.
5. Run load tests against login, state writes, and AI quotas; define SLOs and alerting.
6. Add centralized redacted logs, metrics, tracing, incident response, and account abuse workflows.
7. Complete a privacy policy, retention/deletion/export process, and an independent security review.

The current repository contains the hardened application layer, but these infrastructure and verification items are still required before public launch at scale.
