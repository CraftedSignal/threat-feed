---
brief_id: brief-2026-09-17-redis-parser-dos
event_id: brief-2026-09-17-redis-parser-dos
revision: 2
activity_at: "2026-09-18T00:04:19Z"
revision_history:
  - revision: 2
    at: "2026-10-20T13:19:21Z"
    checksum: sha256:5d0301d795bf635530b3bc8037fa08ec083514dc10a9d2a1f3afc11fa0ba58b2
    summary: Repaired a legacy canonical identity collision
    changed_fields:
      - slug
    maintenance: true
title: Denial of Service Vulnerability in redis-parser via RESP Recursion
slug: 2026-09-17-redis-parser-dos
description: The redis-parser library up to version 3.0.0 is vulnerable to a denial of service attack where crafted RESP byte streams trigger unbounded recursion, exhausting the V8 call stack and crashing the host Node.js process.
date: "2026-09-18T00:04:19Z"
type: advisory
types:
  - advisory
severities:
  - low
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Source validated; requires dependency mapping in user environment
cpes:
  - cpe:2.3:a:redis:redis-parser:*:*:*:*:*:node.js:*:*
tags:
  - denial-of-service
  - vulnerability
  - supply-chain
vendors:
  - Redis
products:
  - redis-parser (<= 3.0.0)
cves:
  - id: CVE-2026-93435
    cvss: 7.5
    kev_status: unknown
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-93435
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Development
  immediate_actions:
    - action: Upgrade redis-parser to a patched version once released
      owner: Development
      due: 48h
      evidence: CVE-2026-93435
  mitigation_plan:
    - priority: immediate
      action: Scan build artifacts and dependencies for vulnerable redis-parser versions
      owner: IT Operations
      addresses: CVE-2026-93435
      evidence: Source advisory
  gaps:
    - Missing specific patch version in source
---

The redis-parser library, widely used in the Node.js ecosystem, contains a critical denial of service (DoS) vulnerability in its RESP (REdis Serialization Protocol) parser, identified as CVE-2026-93435. The vulnerability exists in versions 3.0.0 and earlier and stems from improper handling of nested arrays within the protocol implementation.

An attacker controlling a malicious Redis server, or capable of intercepting and modifying communication between a client and a legitimate Redis server, can transmit a crafted RESP byte stream. This stream contains deeply nested array headers that trigger unbounded recursion during parsing. This process exhausts the V8 call stack, leading to an unhandled RangeError. Because the error is not caught within the parser's logic, it propagates to the main execution context, forcing an immediate, ungraceful termination of the host Node.js process. This vulnerability is particularly impactful for high-availability applications that depend on stable Redis connections.

## Impact

Successful exploitation results in the immediate, unhandled crash of the application process using the vulnerable redis-parser library. This leads to a persistent denial of service condition for the affected service. The impact is significant for production environments where unexpected process termination can cause data loss, service outages, and secondary failures in dependent services that expect a continuous Redis connection.

## Recommendation

Prioritized actions for development and security teams:

- Update all applications dependent on redis-parser to the latest version that includes the fix for CVE-2026-93435.
- Audit dependencies using package management tools to identify and remove all instances of redis-parser versions 3.0.0 or lower.
- Monitor application logs for Node.js process termination patterns (e.g., unexpected exit codes, stack trace overflows) that may indicate attempts to trigger this DoS vulnerability.
