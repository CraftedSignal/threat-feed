---
title: Directus Authorization Bypass via Cache Key Collision (CVE-2026-61836)
slug: 2026-07-directus-cache-key-auth-bypass
description: A vulnerability in Directus allows for an authorization bypass when response caching is enabled, leading to cross-share confidentiality breaches where sensitive data scoped for one share can be accessed by another share token holder or anonymous users due to an unsegmented cache key.
date: "2026-07-20T21:49:23Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - authorization-bypass
  - cache-poisoning
  - cve
  - web-application
vendors:
  - Directus
products:
  - Directus (less than 12.0.0)
cves:
  - id: CVE-2026-61836
    cvss: 8.6
    epss: 0.00277
references:
  - https://github.com/advisories/GHSA-c6w9-5g5j-jh2p
---

A critical vulnerability, CVE-2026-61836, has been identified in Directus versions prior to 12.0.0. This flaw, classified under CWE-524 and CWE-639, allows for an authorization bypass affecting instances where response caching (`CACHE_ENABLED=true`) is active. The issue stems from an incomplete cache-key derivation process in `api/src/utils/get-cache-key.ts`, which fails to incorporate all necessary authorization contexts beyond the basic `user` identifier. Specifically, for share tokens and anonymous requests, the `user` attribute defaults to `null`, causing different share tokens or anonymous clients requesting the same URL and query to generate identical cache keys. This cache collision leads to unauthorized access; once a share populates the cache with its permission-filtered response, subsequent requests from other shares or anonymous users for the same resource retrieve the cached, potentially sensitive, payload without re-evaluating their specific permissions. The vulnerability is present in Directus deployments utilizing its caching feature, which is commonly enabled in production for performance benefits, and poses a significant risk of data exposure.

## Attack Chain

1. **Precondition**: A Directus instance is configured with `CACHE_ENABLED=true` and has at least one active `directus_shares` configured, providing scoped read access to sensitive items (e.g., `/items/articles`).
2. **Share Configuration**: A legitimate administrator creates a share token (e.g., `Share A`) to grant specific, limited read access to particular data items within Directus.
3. **Initial Request**: A user possessing `Share Token A` makes an authenticated request to access shared, sensitive data (e.g., `GET /items/articles/123`).
4. **Cache Population**: Directus processes the request, applies the specific authorization rules associated with `Share Token A`, retrieves the appropriate permission-filtered data, and stores this response in the configured cache.
5. **Cache Key Derivation Flaw**: The cache key is generated using an incomplete set of authorization contexts (e.g., `version`, `path`, `query`, and `accountability.user`), with `accountability.user` being `null` for share tokens and anonymous requests.
6. **Subsequent Request**: A different user, either holding `Share Token B` (distinct from `Share A`) or making an anonymous request, attempts to access the *exact same URL* (`GET /items/articles/123`).
7. **Cache Hit & Bypass**: Due to the identical cache key derived from the previous request, Directus retrieves and serves the already cached response without performing a fresh authorization check against `Share Token B`'s or the anonymous user's specific permissions.
8. **Unauthorized Data Access**: The second user (with `Share Token B` or anonymous) gains unauthorized access to the sensitive data originally filtered and intended only for `Share Token A`.

## Impact

This vulnerability can lead to severe cross-share confidentiality breaches. Any permission-filtered response populated in the cache by one share token can be served to any other share token holder or an anonymous request that subsequently hits the same URL and query, bypassing intended authorization. For instance, an anonymous client could retrieve sensitive, share-scoped data without any authentication. While password protection on shares exists at the JWT issuance stage, a cached response bypasses this once populated. The data leak persists for the duration of the `CACHE_TTL` window (typically 5-30 minutes) and can survive server restarts if `CACHE_STORE=redis` is used. The scope of the leaked data depends on the original share's permissions, ranging from primary keys to full content for shares backed by roles with broader field access. The bypass is read-only, meaning no write operations are affected.

## Recommendation

* **Patch CVE-2026-61836**: Upgrade all Directus instances to version 12.0.0 or newer immediately to mitigate the vulnerability.
* **Review `CACHE_ENABLED` Configuration**: For instances that cannot be immediately patched, consider disabling `CACHE_ENABLED` by setting it to `false` in your Directus configuration, especially if `directus_shares` are in use and sensitive data is involved.
* **Audit Share Configurations**: Review all `directus_shares` to ensure they adhere to the principle of least privilege, minimizing the amount of sensitive data exposed even in the event of a bypass.
