---
title: Memcached Denial of Service Vulnerabilities
slug: 2026-09-memcached-dos
description: Memcached versions prior to 1.4.33 are susceptible to remote, unauthenticated denial-of-service attacks due to improper request handling of specific commands.
date: "2026-09-14T13:03:21Z"
type: advisory
types:
  - advisory
severities:
  - medium
cpes:
  - cpe:2.3:a:memcached:memcached:*:*:*:*:*:*:*:*
cves:
  - id: CVE-2016-8704
    cvss: 9.8
    epss: 0.23173
  - id: CVE-2016-8705
    cvss: 9.8
    epss: 0.19854
---

Memcached versions earlier than 1.4.33 contain vulnerabilities (CVE-2016-8704, CVE-2016-8705) that allow an unauthenticated, remote attacker to trigger a denial-of-service condition. These flaws stem from improper input handling during specific memory operations and request processing. By sending specially crafted packets to the memcached service, an attacker can induce resource exhaustion or memory corruption, resulting in an immediate crash of the service. This vulnerability is significant for organizations relying on memcached for high-performance caching in web architectures, as a successful exploit causes immediate service disruption and potential loss of cached data.

## Impact

Successful exploitation results in the unavailability of the memcached service. Because memcached is frequently used to offload database
