---
title: Remote Code Execution in SPIP via editer_objet Action
slug: 2026-09-spip-rce
description: SPIP versions before 4.4.18 are vulnerable to remote code execution due to improper validation of the arg parameter in the editer_objet action, allowing attackers to inject malicious serialized data into the job queue.
date: "2026-09-11T19:14:44Z"
lastmod: "2026-09-11T19:15:21Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:spip:spip:*:*:*:*:*:*:*:*
tags:
  - rce
  - vulnerability
  - web-application
  - sql-injection
  - cve
vendors:
  - SPIP
products:
  - SPIP (< 4.4.18)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: The vulnerability leads to arbitrary PHP function execution on the underlying system.
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Attackers can supply a crafted value such as a time-based payload through the annee parameter in squelettes-dist/sitemap.xml.html to embed arbitrary SQL
    confidence_band: high
cves:
  - id: CVE-2026-72710
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-72710
  - https://nvd.nist.gov/vuln/detail/CVE-2026-72708
rules:
  - title: Detects CVE-2026-72708 Exploitation - Blind SQL Injection via Sitemap Endpoint
    description: Detects attempts to exploit CVE-2026-72708 by monitoring for time-based SQL injection payloads within the 'annee' parameter of requests to the sitemap.xml.html endpoint.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Upgrade SPIP to 4.4.18 or later
      owner: IT Operations
      due: 24h
      evidence: Source advisory specifies version 4.4.18 as the fix.
  mitigation_plan:
    - priority: immediate
      action: Upgrade SPIP to 4.4.18 or later
      owner: IT Operations
      addresses: CVE-2026-72710
      evidence: Source advisory specifies version 4.4.18 as the fix.
updates:
  - at: "2026-09-11T19:15:21Z"
    level: L2
    summary: 'added detection rule: Detects CVE-2026-72708 Exploitation - Blind SQL Injection via Sitemap Endpoint'
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-72708
---

SPIP versions prior to 4.4.18 are affected by a critical remote code execution (RCE) vulnerability within the editer_objet action. The vulnerability arises because the arg parameter resolves SQL table names without validating them against an editable columns allowlist. An attacker possessing a valid nonce can exploit this to inject arbitrary, attacker-controlled rows into the spip_jobs database table. 

The injected entries are later processed by the system's cron job queue. Because the application unserializes these malicious payloads during the queue execution process, it leads to arbitrary PHP function execution on the underlying server. Given the severity of this flaw, which carries a CVSS v3.1 base score of 9.8, immediate patching to version 4.4.18 or later is required to prevent unauthorized system compromise. Defenders should focus on monitoring for unauthorized access to administrative actions or suspicious manipulation of the spip_jobs table.

## Impact

Successful exploitation allows unauthenticated or low-privileged attackers with a valid nonce to achieve full remote code execution on the hosting server. This enables complete system compromise, potential data exfiltration, and lateral movement within the environment. All sectors deploying SPIP versions below 4.4.18 are at risk of total infrastructure takeover.

## Recommendation

* Patch all instances of SPIP to version 4.4.18 or later immediately.
* Audit database activity specifically targeting the spip_jobs table for suspicious or unexpected entries.
* Monitor webserver access logs for anomalous requests targeting the editer_objet action, particularly those containing encoded or serialized PHP objects.
