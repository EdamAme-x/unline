# Threat Model

## Assets

- LINE account session material stored by the browser client.
- Self-host deployment cookies or reverse-proxy credentials.
- Local TLS keys and environment files.
- Basic auth access key.
- Generated upstream LINE extension package.

## Default Deny Decisions

- The server never proxies arbitrary URLs.
- The server does not forward local `Cookie` headers.
- The server does not forward `Authorization` headers unless explicitly configured.
- The server strips upstream `Set-Cookie` headers to avoid binding LINE cookies to the self-host origin.
- The server can require Basic auth and stores only a salted PBKDF2-SHA256 hash.
- Browser `connect-src` is same-origin by default, so unpatched direct telemetry and API calls are blocked.
- Generated upstream assets are ignored by git and verified after generation.

## Accepted Risk

The generated LINE client remains proprietary upstream JavaScript. The wrapper can constrain network paths and repo hygiene, but it cannot prove the upstream app is safe. Regenerate in a clean tree, inspect `go run ./cmd/unline verify`, and expose the service only to users who understand that boundary.
