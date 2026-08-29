---
title: Hardcoded Connection Key Vulnerability in Shinobi Child Node
slug: 2026-08-shinobi-hardcoded-key
description: Shinobi versions prior to commit 5a76c74f contain a hardcoded connection key in the child node service, allowing unauthenticated attackers to execute arbitrary SQL queries.
date: "2026-08-29T13:38:50Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:shinobi:shinobi:*:*:*:*:*:*:*:*
tags:
  - cve-2026-82448
  - sql-injection
  - vulnerability
vendors:
  - Shinobi
products:
  - Shinobi (< commit 5a76c74f)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Shinobi before commit 5a76c74f contains a hardcoded connection key in the child node service that allows unauthenticated attackers to execute arbitrary database queries.
    confidence_band: high
cves:
  - id: CVE-2026-82448
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-82448
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - SOC
  mitigation_plan:
    - priority: immediate
      action: Upgrade Shinobi child node service to commit 5a76c74f or later
      owner: IT Operations
      addresses: CVE-2026-82448
      evidence: Source documentation identifies commit 5a76c74f as the remediation point.
---

Shinobi versions released prior to commit 5a76c74f contain a significant security vulnerability involving a hardcoded connection key within the child node service. This vulnerability enables unauthenticated remote attackers to establish a WebSocket connection to the child node by providing the known hardcoded key during the handshake process. Once the handshake is successful, the attacker can leverage the 'onWebSocketDataFromChildNode' handler to dispatch arbitrary SQL queries against the underlying database. This allows for unauthorized data exfiltration, modification of user records, and manipulation of camera configurations. Because the vulnerability facilitates direct interaction with the database layer, it effectively grants full database access to any attacker with network connectivity to the child node port.

## Impact

Successful exploitation leads to full database compromise, which may include the theft of user credentials, unauthorized viewing of camera feeds, and the ability to alter system configurations. This poses a critical risk to deployments where Shinobi nodes are exposed to untrusted networks.

## Recommendation

1. Upgrade the Shinobi child node service to commit 5a76c74f or later immediately.
2. Restrict network access to the child node service port (default WebSocket ports) to trusted internal IP addresses only.
3. Audit database logs for unusual query patterns or unexpected modifications to the 'users' and 'camera' tables that occur from the child node service interface.
