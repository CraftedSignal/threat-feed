---
title: Unauthenticated Denial of Service in Nuxt SSR
slug: 2026-08-nuxt-dos
description: An unauthenticated remote denial-of-service vulnerability (CVE-2026-71314) in Nuxt allows attackers to trigger memory exhaustion via unbounded 'v-for' iteration within server-side rendered components.
date: "2026-08-05T21:25:30Z"
type: advisory
types:
  - advisory
severities:
  - low
vendors:
  - Nuxt
products:
  - Nuxt 3
  - Nuxt 4
cves:
  - id: CVE-2026-71314
    cvss: 7.5
references:
  - https://github.com/advisories/GHSA-hxcr-hm88-mpq6
  - https://nvd.nist.gov/vuln/detail/CVE-2026-71314
---

Nuxt versions prior to 4.5.1 and 3.21.10 are vulnerable to a remote denial-of-service attack (CVE-2026-71314). The vulnerability originates in the island/server-component rendering pipeline, where 'v-for' directives can be applied to user-controlled props. Because the island URL hash is a predictable digest, an attacker can craft a request that forces the server-side rendering (SSR) engine to iterate a 'v-for' loop an arbitrary number of times.

By supplying an extremely large integer as the iterated prop, an attacker causes the Nuxt server to allocate memory proportional to the iteration count, leading to an out-of-memory (OOM) crash of the worker process. The vulnerability impacts both direct 'v-for' directives on props and slot-based 'v-for' expansion via the 'vforToArray' utility. Successful exploitation requires only a small (approx. 130-byte) HTTP request. Organizations using Nuxt for SSR should update to the patched versions immediately or implement input clamping for props passed to 'v-for' within server components.

## Attack Chain

1. Attacker identifies a Nuxt application using server-side rendered islands or components that perform 'v-for' iterations on user-provided props.
2. Attacker inspects public-facing island URL hash generation to understand the request digest format.
3. Attacker constructs a malicious request containing a crafted prop value, specifically a high-integer value intended for a 'v-for' loop.
4. Attacker submits the request to the target endpoint, typically targeting the /__nuxt_island/ path.
5. The Nuxt SSR engine processes the request and maps the attacker-supplied integer to the 'v-for' iteration logic.
6. The rendering engine expands the loop during SSR, leading to rapid, unbounded memory allocation within the worker process.
7. The server process exhausts system memory and crashes, resulting in a denial-of-service for the application.

## Impact

Successful exploitation results in an immediate denial-of-service condition for the targeted application instance. A single small request (approx. 130 bytes) is sufficient to crash a worker process when provided with an iteration count in the tens of millions. This allows for trivial, unauthenticated resource exhaustion and service unavailability across affected infrastructure.

## Recommendation

* Update to Nuxt 4.5.1 or 3.21.10 to incorporate the 'MAX_VFOR_LENGTH' clamping logic, which prevents unbounded iteration expansion.
* Audit application code for components utilizing 'v-for' on props passed from server-side inputs.
* Deploy manual input validation or clamping in server components using 'Math.min(count, 1000)' to provide defense-in-depth until patching is complete.
* Monitor webserver logs for unusual spikes in 500-series status codes targeting the /__nuxt_island/ endpoint, which may indicate crash attempts.
