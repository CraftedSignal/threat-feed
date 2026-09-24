---
title: Denial of Service Vulnerability in redis-parser via RESP Protocol
slug: 2026-09-redis-parser-dos
description: The redis-parser library up to version 3.0.0 fails to validate multi-bulk length values in the RESP protocol, allowing an attacker-controlled Redis endpoint to trigger an unhandled RangeError and crash the Node.js application process.
date: "2026-09-24T14:47:33Z"
type: advisory
types:
  - advisory
severities:
  - low
cpes:
  - cpe:2.3:a:redis-parser_project:redis-parser:*:*:*:*:*:node.js:*:*
tags:
  - denial-of-service
  - nodejs
  - library-vulnerability
products:
  - redis-parser (<= 3.0.0)
cves:
  - id: CVE-2026-97057
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-97057
action_plan:
  priority: elevated
  owners:
    - Application Security
    - Development Teams
  immediate_actions:
    - action: Inventory all applications using redis-parser and assess exposure to untrusted Redis endpoints
      owner: Application Security
      due: 48h
      evidence: CVE-2026-97057 identifies a critical DoS in redis-parser
  mitigation_plan:
    - priority: immediate
      action: Identify and upgrade to patched version of redis-parser when released
      owner: Development Teams
      addresses: CVE-2026-97057
      evidence: NVD vulnerability notice
---

The redis-parser library, a component frequently used in Node.js applications for parsing the Redis Serialization Protocol (RESP), contains a critical validation flaw identified as CVE-2026-97057. The vulnerability exists because the library does not properly validate the multi-bulk length value during protocol parsing. An attacker who has compromised a Redis endpoint or is positioned as a malicious upstream Redis server can transmit a crafted RESP header with a length parameter exceeding 2^32-1. This payload causes the parser to trigger an uncaught RangeError within the JavaScript runtime, leading to an immediate process crash and denial of service. Because redis-parser is often a core dependency for Redis clients, this vulnerability directly impacts the availability of any Node.js service connecting to an untrusted or compromised Redis instance.

## Impact

The vulnerability results in an application-level denial of service for any Node.js process relying on redis-parser versions 3.0.0 or earlier. By forcing a process crash, attackers can disrupt backend services, queue consumers, or data caches that rely on Redis connectivity. Given the commonality of the redis-parser library in the Node.js ecosystem, widespread availability impact is possible for services integrated with external Redis clusters or Redis instances exposed to potentially malicious input.

## Recommendation

1. Audit dependencies to identify all projects utilizing redis-parser versions 3.0.0 or lower.
2. Upgrade to a patched version of redis-parser that implements strict bounds checking on RESP length fields as soon as the vendor provides a resolution.
3. If immediate patching is not possible, implement ingress filtering or application-level sanity checks on the maximum expected size of RESP messages before passing them to the parser.
4. Ensure Redis clients are configured to connect only to authenticated and trusted Redis instances to mitigate the threat of a malicious or compromised upstream server.
