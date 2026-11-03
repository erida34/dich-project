# ADR 0021 — Explicit HTTP CONNECT proxy

Status: Accepted for the experimental `update` and `fetch` commands.

Some WSL installations reach HTTPS repositories only through a preconfigured HTTP proxy. Dich therefore accepts an explicit `--https-proxy http://host:port` for these network commands. It never discovers or trusts proxy environment variables automatically. Proxy URLs with credentials, non-HTTP schemes, paths, query strings, fragments, or no explicit port are rejected. Proxy configuration is not persisted.

The proxy is an untrusted transport hop. Repository origins must remain HTTPS, certificate validation and redirect restrictions stay enabled, and the configured repository signing fingerprints still authorize Release metadata before index or package digests are used. TLS inspection that presents an untrusted certificate fails closed. Proxy authentication, HTTPS/SOCKS proxies, retries, and environment-variable support are out of scope for this increment.

Acceptance: parser negative tests, workspace checks, and a real CLI fetch through an explicitly configured proxy with valid origin TLS and signed repository metadata. This does not establish availability or trustworthiness of arbitrary proxies.
