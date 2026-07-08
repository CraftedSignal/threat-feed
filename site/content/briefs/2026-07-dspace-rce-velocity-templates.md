---
title: DSpace RCE via Velocity Templates (CVE-2026-49832)
slug: 2026-07-dspace-rce-velocity-templates
description: DSpace versions 8.0 through 8.3, 9.0 through 9.2, and 10.0-rc1 are vulnerable to Remote Code Execution (RCE) via Velocity Templates used for COAR Notify/LDN messages, allowing an attacker with DSpace administrator credentials to execute direct Java code using reflection, a high-impact vulnerability that can be chained with a related path traversal attack (GHSA-9qm4-rh6w-pq5x).
date: "2026-07-08T20:32:37Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - rce
  - web-application
  - vulnerability
  - dspace
vendors:
  - DSpace
products:
  - DSpace (8.0)
  - DSpace (8.1)
  - DSpace (8.2)
  - DSpace (8.3)
  - DSpace (9.0)
  - DSpace (9.1)
  - DSpace (9.2)
  - DSpace (10.0-rc1)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: it may be possible to execute Java directly from Velocity templates using reflection
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-9x82-rm84-c6x7
  - https://github.com/DSpace/DSpace/security/advisories/GHSA-9qm4-rh6w-pq5x
  - https://www.cve.org/CVERecord?id=CVE-2026-49832
---

Remote Code Execution (RCE) is possible via Velocity Templates used by DSpace for COAR Notify/LDN messages. This vulnerability, tracked as CVE-2026-49832, impacts DSpace versions 8.0 through 8.3, 9.0 through 9.2, and the 10.0-rc1 development release. An attacker must first obtain DSpace administrator credentials to exploit this flaw. When chained with a prior path traversal vulnerability (GHSA-9qm4-rh6w-pq5x), this allows for direct Java execution using reflection within Velocity templates. The vulnerability was discovered and reported by Pablo Picurelli Ortiz and affects critical components of the DSpace repository system, enabling adversaries with administrative access to compromise the integrity and confidentiality of the entire platform by executing arbitrary code on the server. The fix is included in DSpace 8.4, 9.3, and 10.0.

## Attack Chain

1. Attacker obtains valid DSpace administrator credentials through various means (e.g., phishing, credential stuffing, brute-force).
2. Attacker logs into the DSpace administrative interface using the compromised credentials.
3. Leveraging the LDN (COAR Notify) feature, the attacker exploits the identified path traversal vulnerability (GHSA-9qm4-rh6w-pq5x) to upload or modify a Velocity template file on the server.
4. The attacker injects malicious Java code (using reflection) into the compromised Velocity template, specifically crafted to achieve server-side execution.
5. The DSpace application, when processing an LDN message or rendering a page that utilizes the manipulated template, invokes the Velocity template engine.
6. The Velocity engine processes the compromised template, leading to the execution of the embedded malicious Java code on the DSpace server.
7. The attacker achieves Remote Code Execution (RCE) on the underlying DSpace server, enabling arbitrary command execution, data exfiltration, or further system compromise.

## Impact

This vulnerability poses a very high impact when exploited, allowing for Remote Code Execution on the DSpace server. Successful exploitation requires DSpace administrator credentials and can be chained with a prior LDN Path Traversal Attack (GHSA-9qm4-rh6w-pq5x). If exploited, attackers can execute arbitrary Java code using reflection from Velocity templates, leading to full compromise of the DSpace instance, including data manipulation, exfiltration, or complete system takeover. The vulnerability affects DSpace versions 8.0 through 8.3, 9.0 through 9.2, and 10.0-rc1. Disabling the LDN feature serves as an effective workaround if immediate patching is not possible.

## Recommendation

* Upgrade DSpace instances to version 8.4, 9.3, or 10.0 immediately to remediate CVE-2026-49832.
* Disable the LDN feature by setting `ldn.enabled=false` in `dspace.cfg` or `local.cfg` if it is not critical for your DSpace repository's operation.
* If immediate upgrade is not feasible, apply the manual patch files available for DSpace 8.x (Pull request #12549) or DSpace 9.x (Pull request #12548) as described in the advisory.
