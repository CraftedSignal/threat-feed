---
brief_id: brief-2026-11-09-ws-ftp-insecure-comm
event_id: brief-2026-11-09-ws-ftp-insecure-comm
revision: 1
activity_at: "2026-11-09T17:50:18Z"
title: 'Progress WS_FTP Server: Insufficient protection of communications (CVE-2026-115338)'
slug: 2026-11-ws-ftp-insecure-comm
description: Progress WS_FTP Server versions prior to 2025.0.5 are vulnerable to man-in-the-middle attacks, allowing network attackers to intercept or modify traffic when unencrypted connections are permitted.
date: "2026-11-09T17:50:18Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
qa_status:
  verdict: pass
cpes:
  - cpe:2.3:a:progress:ws_ftp_server:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - network-security
  - man-in-the-middle
vendors:
  - Progress
products:
  - WS_FTP Server (< 2025.0.5)
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1557
    technique_name: Adversary-in-the-Middle
    evidence: A network attacker can exploit this flaw to intercept sensitive information or perform man-in-the-middle attacks.
    confidence_band: high
cves:
  - id: CVE-2026-115338
    cvss: 8.1
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-115338
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Patch WS_FTP Server to 2025.0.5 or later
      owner: IT Operations
      due: 24h
      evidence: Vulnerability in WS_FTP Server versions prior to 2025.0.5
  hunt_leads:
    - lead: Identify WS_FTP Server instances configured to accept non-TLS traffic
      technique_id: T1557
      data_needed:
        - Server listener configuration logs
        - Application audit logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Vulnerability occurs when unencrypted connections are used
  mitigation_plan:
    - priority: immediate
      action: Disable unencrypted listeners
      owner: IT Operations
      addresses: CVE-2026-115338
      evidence: Vulnerability tied to unencrypted connections
---

Progress WS_FTP Server versions prior to 2025.0.5 contain a vulnerability where communications are insufficiently protected. This flaw allows a network attacker positioned to observe or intercept traffic to conduct man-in-the-middle attacks. An attacker can intercept sensitive information or modify requests if the server is configured to allow or fall back to unencrypted connections.

## Impact

Successful exploitation allows for the interception of sensitive data transmitted over the network and the modification of client-to-server requests, potentially compromising credentials or file transfer integrity.

## Recommendation

* Patch Progress WS_FTP Server to version 2025.0.5 or later immediately.
* Audit WS_FTP Server configurations to disable support for unencrypted connections (e.g., ensure mandatory TLS/SSL usage for all listeners).
* Inventory all internet-facing instances of Progress WS_FTP Server.
