---
title: DNS Rebinding Vulnerability in DBHub HTTP Transport
slug: 2026-09-dbhub-dns-rebind
description: DBHub 0.21.2 fails to securely validate hostnames in its HTTP transport mode, allowing attackers to use DNS rebinding to execute arbitrary SQL queries via a victim's browser.
date: "2026-09-24T20:03:55Z"
lastmod: "2026-09-24T20:05:22Z"
type: threat
types:
  - threat
severities:
  - high
exploited: true
tags:
  - web-vulnerability
  - dns-rebinding
  - database-security
  - vulnerability
  - rce
vendors:
  - Bytebase
products:
  - DBHub (0.21.2)
  - dbhub (< 0.22.6)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1557.002
    technique_name: 'Adversary-in-the-Middle: DNS Spoofing'
    evidence: An attacker can leverage DNS rebinding to trick a victim's browser into sending unauthorized requests to a locally accessible DBHub instance.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: a malicious website can deterministically invoke DBHub MCP tools from the victim's browser
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The HTTP transport is unauthenticated and binds to 0.0.0.0 by default, so this is reachable by any network caller of /mcp.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.003
    technique_name: 'Command and Scripting Interpreter: Windows Command Shell'
    evidence: SELECT dblink_exec('dbname=app', $$COPY (SELECT 1) TO PROGRAM 'id > /tmp/pwned'$$); -- runs a shell command
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-mwwr-p57h-56pf
  - https://github.com/bytebase/dbhub/pull/342
  - https://nvd.nist.gov/vuln/detail/CVE-2026-61788
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Audit environments for DBHub instances running with --transport http
      owner: IT Operations
      due: 24h
      evidence: Source documentation identifies HTTP transport mode as the vulnerable configuration
  mitigation_plan:
    - priority: immediate
      action: Bind DBHub HTTP transport to loopback interface (127.0.0.1) or disable if not required
      owner: IT Operations
      addresses: DNS rebinding via local network access
      evidence: Remediation guidance provided in source
updates:
  - at: "2026-09-24T20:05:22Z"
    level: L2
    summary: added coverage for dbhub (< 0.22.6)
    sources:
      - ghsa
    source_urls:
      - https://github.com/advisories/GHSA-mwwr-p57h-56pf
---

DBHub version 0.21.2, when deployed using the `--transport http` configuration, contains a critical flaw in its DNS rebinding protection mechanism. The server attempts to prevent unauthorized cross-origin requests by validating that the `Origin` header matches the `Host` header. However, this check is insufficient as it does not enforce a whitelist of trusted hostnames. An attacker can perform a DNS rebinding attack to cause a victim's browser to resolve an attacker-controlled domain to the IP address where DBHub is running. Because both the `Host` and `Origin` headers in the rebind request will match the attacker-controlled hostname, the server erroneously trusts the request. This allows an attacker to interact with the `/mcp` endpoint and dispatch JSON-RPC tool calls, such as `execute_sql`, directly from the victim's browser. This vulnerability bypasses traditional local network boundaries and does not require authentication, potentially exposing sensitive database contents to exfiltration.

## Attack Chain

1. Attacker registers a domain (e.g., dbhub-rebind.example) and configures an authoritative DNS server to provide a short Time-To-Live (TTL).
2. Victim is lured to an attacker-controlled website hosted at the attacker's domain, which resolves initially to an attacker-controlled web server.
3. Attacker's web server delivers malicious JavaScript to the victim's browser.
4. Attacker updates the DNS record for their domain to point to the victim's internal loopback or local network IP where DBHub is running.
5. The malicious JavaScript triggers a cross-origin HTTP request to the DBHub server at the attacker's domain (e.g., dbhub-rebind.example:8080).
6. DBHub's middleware extracts the `Host` and `Origin` headers, finds they match the attacker's domain, and validates the request as authorized.
7. DBHub dispatches the JSON-RPC command, executing arbitrary SQL queries on the connected database.
8. Attacker receives query results from the JSON-RPC response via the browser's ability to read the reflected origin, completing the exfiltration.

## Impact

Successful exploitation allows unauthenticated execution of SQL queries on databases connected to a DBHub instance. Depending on the server's configured permissions, an attacker can enumerate schemas, read sensitive database contents, and perform write operations. As the interaction occurs through the victim's browser, the attacker can exfiltrate data without needing direct network access to the target machine or bypassing local firewall rules, significantly impacting organizations using DBHub for local database management.

## Recommendation

Prioritized actions for security teams:
- Immediately audit all DBHub deployments to identify instances using the `--transport http` configuration.
- Bind DBHub instances to `127.0.0.1` rather than `0.0.0.0` to restrict network accessibility.
- Implement an explicit allowed-hosts and allowed-origins policy in local infrastructure proxies if DBHub must be exposed.
- Require a static authentication token for all `/mcp` requests, independent of the HTTP transport's origin validation.
- Restrict the `execute_sql` tool permissions to read-only for production database connections where possible.
