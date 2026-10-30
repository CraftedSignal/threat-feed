---
brief_id: brief-2026-10-30-chamilo-rce
event_id: brief-2026-10-30-chamilo-rce
revision: 1
activity_at: "2026-10-30T21:03:06Z"
title: 'Chamilo LMS: Unauthenticated remote code execution via arbitrary file upload (CVE-2023-4220)'
slug: 2026-10-chamilo-rce
description: An unauthenticated arbitrary file upload vulnerability in Chamilo LMS versions 1.11.24 and earlier allows remote attackers to execute arbitrary code by uploading malicious web shells to the bigUpload.php endpoint.
date: "2026-10-30T21:03:06Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: B
  credibility: "3"
  rating: B3
  likelihood: very likely
qa_status:
  verdict: pass
  validation_status: Source confirmed vulnerable path and exploitation vector
cpes:
  - cpe:2.3:a:chamilo:chamilo_lms:*:*:*:*:*:*:*:*
tags:
  - web-application-vulnerability
  - remote-code-execution
  - file-upload
  - chamilo
vendors:
  - Chamilo
products:
  - Chamilo LMS (<= 1.11.24)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Unrestricted file upload in Chamilo LMS <= 1.11.24 allows unauthenticated RCE via web shell.
    confidence_band: high
cves:
  - id: CVE-2023-4220
    cvss: 8.1
    epss: 0.76084
    kev_status: "false"
references:
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-THEFIZZYFISH-CVE-2023-4220_CHAMILO_RCE
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-THEFIZZYFISH-CVE-2023-4220_CHAMILO_RCE&utm_source=rss&utm_medium=rss
rules:
  - title: Detect CVE-2023-4220 Exploitation - Unauthenticated File Upload to bigUpload.php
    description: Detects exploitation attempts against CVE-2023-4220 by identifying POST requests to the vulnerable bigUpload.php file.
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
    - action: Patch Chamilo LMS to a version beyond 1.11.24
      owner: IT Operations
      due: 24h
      evidence: Source states Chamilo LMS <= 1.11.24 is affected.
  hunt_leads:
    - lead: Search web logs for POST requests to /main/inc/lib/javascript/bigupload/inc/bigUpload.php resulting in HTTP 200/201.
      technique_id: T1190
      data_needed:
        - Web access logs containing URI stems and status codes
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Source identifies this file as the entry point for unauthenticated RCE.
  mitigation_plan:
    - priority: immediate
      action: Restrict public access to bigUpload.php via WAF or web server configuration
      owner: IT Operations
      addresses: CVE-2023-4220
      evidence: Path is identified as the entry point for arbitrary file upload.
---

CVE-2023-4220 is an unauthenticated arbitrary file upload vulnerability found in Chamilo LMS versions 1.11.24 and earlier. The flaw resides in the bigUpload.php handler, which fails to adequately validate file types during the upload process. Successful exploitation allows an unauthenticated attacker to upload web shells, enabling remote code execution (RCE) or the deployment of stored cross-site scripting (XSS) payloads. Public proof-of-concept exploits are currently available.

## Impact

Successful exploitation provides attackers with arbitrary remote code execution on the underlying web server, potentially leading to full system compromise, data theft, or further lateral movement within the network.

## Recommendation

- Patch Chamilo LMS to a version later than 1.11.24 immediately.
- Implement access controls or restrict network-level access to /main/inc/lib/javascript/bigupload/inc/bigUpload.php to authorized users or internal subnets only.
- Monitor web server access logs for anomalous POST requests targeting the bigUpload.php script.
- Audit the web server document root and associated directories for unexpected file extensions or suspicious files created post-exploitation.
