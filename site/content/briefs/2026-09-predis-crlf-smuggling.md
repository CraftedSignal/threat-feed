---
title: Remote Command Injection and DoS in Predis via CRLF Smuggling
slug: 2026-09-predis-crlf-smuggling
description: Predis versions 3.0.0-RC1 through 3.2.0 are vulnerable to CRLF smuggling in pipeline operations on aggregate connections, enabling remote command injection on cluster configurations or denial-of-service on replication setups.
date: "2026-09-08T21:48:57Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:predis:predis:3.0.0:rc1:*:*:*:*:*:*
  - cpe:2.3:a:predis:predis:3.2.0:*:*:*:*:*:*:*
tags:
  - redis
  - injection
  - php
  - predis
vendors:
  - Predis
products:
  - Predis (3.0.0-RC1 to 3.2.0)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.003
    technique_name: 'Command and Scripting Interpreter: Windows Command Shell'
    evidence: A malicious user can inject arbitrary Redis commands by smuggling CRLF sequences into the input.
    confidence_band: high
cves:
  - id: CVE-2026-84372
    cvss: 9.8
    epss: 0.00415
references:
  - https://github.com/advisories/GHSA-w6f5-v2h6-g786
  - https://github.com/predis/predis/commit/053cb4b6
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Application Security
  immediate_actions:
    - action: Upgrade Predis dependency to 3.3.0 or later across all applications.
      owner: Application Security
      due: 24h
      evidence: Upgrade to predis/predis 3.3.0 or later is the official remediation.
  mitigation_plan:
    - priority: immediate
      action: Implement strict validation for CRLF characters in inputs used for cache keys.
      owner: Development
      addresses: CVE-2026-84372
      evidence: Source states that CRLF sequences facilitate command smuggling.
---

Predis versions 3.0.0-RC1 through 3.2.0 contain an improper CRLF neutralization vulnerability in the `AbstractAggregateConnection::write()` method. When executing pipeline operations on aggregate connections (cluster or replication), the library re-parses the serialized pipeline buffer using `explode("\r\n")` instead of respecting RESP length prefixes. An attacker who can influence values or keys passed into pipelined commands can inject arbitrary Redis commands. 

On cluster configurations, this results in remote command injection, allowing attackers to execute commands like `FLUSHDB`, `DEL`, or `SET` on specific shards, potentially leading to cache poisoning, data theft, or service outages. On replication configurations, the same CRLF injection causes the `deserializeCommand()` method to throw an uncaught `UnexpectedValueException`, resulting in a repeatable, unauthenticated denial-of-service condition. This vulnerability was introduced in v3.0.0-RC1 and fixed in version 3.3.0.

## Attack Chain

1. The application accepts user-influenced input, such as a URL slug, used as a key for Redis cache operations.
2. The application initiates a `pipeline()` request containing the attacker-influenced key to a Redis cluster.
3. The attacker crafts a request containing a smuggled command payload, such as `PAD\r\n*1\r\n$7\r\nFLUSHDB`.
4. The Predis library's vulnerable `AbstractAggregateConnection` logic splits the buffer based on `\r\n` characters, improperly identifying the smuggled payload as a new command.
5. The library rebuilds the smuggled command and routes it to a specific Redis node based on the hardcoded `'key'` slot strategy.
6. The Redis cluster node parses the smuggled command (e.g., `FLUSHDB`) as a legitimate request from the application.
7. The target Redis shard executes the smuggled command, resulting in cache clearing, data modification, or unauthorized access.

## Impact

Successful exploitation allows for unauthenticated remote command injection in cluster environments, leading to shard-wide data destruction via `FLUSHDB`, targeted `DEL` operations, or cache poisoning. In replication environments, the vulnerability acts as a reliable vector for denial-of-service, crashing request-handling threads and impacting application availability. This affects any application utilizing Predis v3.0.0-RC1 through 3.2.0 with aggregate connection types.

## Recommendation

1. Immediately upgrade to **predis/predis 3.3.0 or later** to resolve the CRLF neutralization flaw in the pipeline handler.
2. If upgrading is not immediately possible, audit application code to ensure that no attacker-influenced data (values or keys) is used within `pipeline()` calls on aggregate connections.
3. Deploy WAF or application-level input validation to sanitize input keys and values for `\r\n` sequences before they are processed by the Predis client library.
4. Monitor application logs for `UnexpectedValueException` errors in production environments, which may indicate attempted exploitation or active DoS attacks against replication-based setups.
