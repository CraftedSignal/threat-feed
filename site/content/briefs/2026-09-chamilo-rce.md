---
title: Chamilo LMS CStudio Unauthenticated Remote Code Execution
slug: 2026-09-chamilo-rce
description: An unauthenticated remote code execution vulnerability in the Chamilo LMS CStudio upload flow allows attackers to gain server-level access by exploiting improper file handling (CVE-2026-45140).
date: "2026-09-18T01:10:40Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:chamilo:chamilo_lms:*:*:*:*:*:*:*:*
tags:
  - remote-code-execution
  - web-application
  - critical-vulnerability
vendors:
  - Chamilo
products:
  - Chamilo LMS (<= 2.0.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The product uses external input to construct a pathname that is intended to identify a file or directory that is located underneath a restricted parent directory.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: The product constructs all or part of a code segment using externally-influenced input from an upstream component.
    confidence_band: high
cves:
  - id: CVE-2026-45140
    cvss: 9.8
references:
  - https://github.com/advisories/GHSA-g4c3-4g96-6g4m
  - https://github.com/chamilo/chamilo-lms/releases/tag/v2.0.1
rules:
  - title: Detects CVE-2026-45140 Exploitation - Suspicious File Upload to CStudio
    description: Detects potential exploitation of CVE-2026-45140 by monitoring for POST requests to the CStudio upload flow that include path traversal or attempt to upload executable extensions.
    platform: sigma
    severity: critical
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
    - action: Upgrade Chamilo LMS to version 2.0.1 or later
      owner: IT Operations
      due: 24h
      evidence: Source states 2.0.1 is the patched version
  enrichment_needed:
    - item: CVE-2026-45140
      owner: CTI
      reason: Monitor for emerging PoC or exploitation scripts
      evidence: N/A
  hunt_leads:
    - lead: Search logs for unusual file names with PHP extensions in upload directories
      technique_id: T1190
      data_needed:
        - Web server access logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Vulnerability allows storage of file with dangerous type
  mitigation_plan:
    - priority: immediate
      action: Upgrade to 2.0.1
      owner: IT Operations
      addresses: CVE-2026-45140
      evidence: Official fix version provided in GHSA
---

Chamilo LMS versions 2.0.0 and earlier are vulnerable to an unauthenticated remote code execution (RCE) flaw in the CStudio file upload component. The vulnerability, tracked as CVE-2026-45140, stems from a combination of path traversal (CWE-22) and unrestricted file upload (CWE-434) issues. Attackers can leverage the upload flow to store malicious files within the web document root, which can subsequently be executed by the server. This allows for total compromise of the application and potentially the underlying server infrastructure. Given the lack of required privileges and user interaction, this vulnerability represents a critical risk for deployments of Chamilo LMS. Users are strongly advised to upgrade to version 2.0.1 or later to remediate the flaw.

## Impact

Successful exploitation leads to full server compromise, allowing unauthenticated attackers to execute arbitrary code, modify application data, and access sensitive files. The vulnerability affects all Chamilo LMS instances running version 2.0.0 or older. Given the high CVSS score of 9.8, the potential for data exfiltration and complete system takeover is high for affected organizations in the education and corporate learning sectors.

## Recommendation

- Upgrade all Chamilo LMS installations to version 2.0.1 or later immediately to patch CVE-2026-45140.
- Audit webserver access logs for POST requests to the CStudio upload endpoint followed by direct requests to unusual files in the application's upload directory.
- Implement strict ingress filtering for web traffic to the application to minimize exposure to unauthenticated exploitation attempts.
- Review file system permissions on the web root to ensure that user-uploaded content directories do not have execution privileges.
