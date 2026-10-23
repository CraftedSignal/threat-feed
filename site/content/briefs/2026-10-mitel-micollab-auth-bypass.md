---
brief_id: brief-2026-10-23-mitel-micollab-auth-bypass
event_id: brief-2026-10-23-mitel-micollab-auth-bypass
revision: 1
activity_at: "2026-10-23T16:37:52Z"
title: 'Mitel MiCollab: Authentication bypass and arbitrary file read (CVE-2024-41713)'
slug: 2026-10-mitel-micollab-auth-bypass
description: An authentication bypass vulnerability in Mitel MiCollab versions 9.8.1.201 and earlier enables unauthenticated attackers to perform arbitrary file reads via a path traversal flaw.
date: "2026-10-23T16:37:52Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: B
  credibility: "2"
  rating: B2
  likelihood: very likely
qa_status:
  verdict: pass
  validation_status: Needs environment validation
cpes:
  - cpe:2.3:a:mitel:micollab:*:*:*:*:*:-:*:*
tags:
  - vulnerability
  - authentication-bypass
  - file-read
  - path-traversal
vendors:
  - Mitel
products:
  - MiCollab (<= 9.8.1.201)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Authentication bypass in Mitel MiCollab allows arbitrary file read.
    confidence_band: high
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1005
    technique_name: Data from Local System
    evidence: Exploiting CVE-2024-41713 to read /etc/passwd
    confidence_band: high
cves:
  - id: CVE-2024-41713
    cvss: 9.1
    epss: 0.97209
    kev_status: "false"
references:
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-GUNYAKIT-CVE-2024-41713-POC-EXPLOIT&utm_source=rss&utm_medium=rss
rules:
  - title: Detects CVE-2024-41713 Exploitation - Path Traversal in Mitel MiCollab
    description: Detects exploitation attempts against CVE-2024-41713 by searching for path traversal patterns in web server logs
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
    - SOC
    - IT Operations
  immediate_actions:
    - action: Inventory all Mitel MiCollab instances
      owner: IT Operations
      due: 24h
      evidence: Source identifies Mitel MiCollab <= 9.8.1.201 as vulnerable
    - action: Patch or restrict access to MiCollab
      owner: IT Operations
      due: 48h
      evidence: Public exploit availability elevates risk
  hunt_leads:
    - lead: Search web logs for URI patterns matching '/etc/passwd' or similar system file paths
      technique_id: T1190
      data_needed:
        - Web server access logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: PoC code explicitly demonstrates reading /etc/passwd
  mitigation_plan:
    - priority: immediate
      action: Upgrade Mitel MiCollab beyond version 9.8.1.201
      owner: IT Operations
      addresses: CVE-2024-41713
      evidence: Source identifies 9.8.1.201 as the affected upper bound
---

CVE-2024-41713 is an authentication bypass and arbitrary file read vulnerability affecting Mitel MiCollab versions 9.8.1.201 and earlier. The vulnerability allows unauthenticated attackers to access sensitive files on the host system. Public proof-of-concept (PoC) exploit scripts are available, demonstrating the ability to read system files like '/etc/passwd'. The vulnerability carries a CVSS score of 9.1.

## Impact

Successful exploitation allows unauthenticated attackers to read arbitrary files from the filesystem of the affected Mitel MiCollab instance. This can lead to the exposure of credentials, configuration files, and other sensitive system information, facilitating further unauthorized access or escalation.

## Recommendation

- Identify all instances of Mitel MiCollab within the environment.
- Patch affected instances of Mitel MiCollab to a version beyond 9.8.1.201 immediately.
- If patching is not immediately feasible, restrict network access to the MiCollab interface to trusted IP addresses only.
- Review web server logs for suspicious requests containing path traversal sequences (e.g., '..', '/etc/passwd') targeting the MiCollab application.
