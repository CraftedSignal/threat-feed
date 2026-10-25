---
brief_id: brief-2026-10-25-siyuan-path-bypass
event_id: brief-2026-10-25-siyuan-path-bypass
revision: 1
activity_at: "2026-10-25T14:32:11Z"
title: 'SiYuan: Sensitive-path denylist bypass (CVE-2026-116171)'
slug: 2026-10-siyuan-path-bypass
description: SiYuan versions 3.5.4 through 3.8.6 on Windows contain a path denylist bypass vulnerability (CVE-2026-116171) that allows authenticated attackers to exfiltrate sensitive workspace files by prepending a Windows extended-length prefix to path parameters.
date: "2026-10-25T14:32:11Z"
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
cpes:
  - cpe:2.3:a:siyuan:siyuan:*:*:*:*:*:windows:*:*
tags:
  - path-traversal
  - security-bypass
  - credential-theft
  - vulnerability
vendors:
  - SiYuan
products:
  - SiYuan (< 3.8.7)
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1083
    technique_name: File and Directory Discovery
    evidence: Authenticated API callers can prepend the prefix to localPath in /api/import/importStdMd to copy workspace conf files, including the API token and TLS private keys, into assets served to unauthenticated clients.
    confidence_band: high
cves:
  - id: CVE-2026-116171
    cvss: 7.5
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-116171
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade SiYuan to version 3.8.7 or later
      owner: IT Operations
      due: 48h
      evidence: Vulnerability is resolved in version 3.8.7
  hunt_leads:
    - lead: Hunt for API requests to /api/import/importStdMd containing the string \\?\
      technique_id: T1083
      data_needed:
        - Web server access logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Authenticated API callers can prepend the prefix to localPath in /api/import/importStdMd
  mitigation_plan:
    - priority: immediate
      action: Upgrade SiYuan to version 3.8.7
      owner: IT Operations
      addresses: CVE-2026-116171
      evidence: SiYuan 3.5.4 before 3.8.7 on Windows contains a sensitive-path denylist bypass
---

SiYuan 3.5.4 through 3.8.6 on Windows contain a sensitive-path denylist bypass vulnerability within the IsSensitivePath function. The application fails to properly handle Windows extended-length path prefixes ('\\?\'), allowing them to survive 'filepath.Clean' calls and evade security filters. An authenticated attacker can exploit this via the '/api/import/importStdMd' endpoint by prepending this prefix to the 'localPath' parameter, enabling the copying of workspace configuration files - including API tokens and TLS private keys - into asset directories accessible to unauthenticated users.

## Impact
Successful exploitation allows for the unauthorized retrieval of sensitive configuration files, including credentials and cryptographic keys, from the SiYuan workspace. This can lead to full compromise of the application instance or unauthorized access to integrated services.

## Recommendation
- Upgrade SiYuan to version 3.8.7 or later to resolve the improper path validation.
- Review access logs for the '/api/import/importStdMd' endpoint to identify suspicious path traversal patterns or repeated requests containing '?\'.
- Rotate API tokens and TLS private keys that may have been exposed through this vulnerability if an attacker is suspected of having accessed the workspace assets.
