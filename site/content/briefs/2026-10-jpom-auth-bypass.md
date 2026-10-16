---
title: Authorization Bypass Vulnerability in Jpom SshFileController
slug: 2026-10-jpom-auth-bypass
description: Jpom versions through 2.11.12 contain an authorization bypass vulnerability allowing authenticated users to perform unauthorized file operations on SSH hosts across different workspaces.
date: "2026-10-16T18:46:19Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:jpom:jpom:*:*:*:*:*:*:*:*
tags:
  - auth-bypass
  - cve-2026-111605
  - jpom
  - privilege-escalation
vendors:
  - Jpom
products:
  - Jpom (<= 2.11.12)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: Jpom through 2.11.12 contains an authorization bypass vulnerability in SshFileController that allows authenticated workspace users to access SSH hosts belonging to other workspaces
    confidence_band: high
cves:
  - id: CVE-2026-111605
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-111605
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade Jpom to the latest secure version addressing CVE-2026-111605
      owner: IT Operations
      due: 48h
      evidence: NVD vulnerability report
  hunt_leads:
    - lead: Identify high-volume or unusual API calls to SshFileController endpoints from single user sessions
      technique_id: T1068
      data_needed:
        - webserver_logs
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: Exploit targets multiple endpoints including download, upload, and file manipulation
---

Jpom versions up to and including 2.11.12 contain a critical authorization bypass vulnerability located in the SshFileController component, identified as CVE-2026-111605. This vulnerability allows an authenticated user with existing file management permissions in their own workspace to gain unauthorized access to SSH hosts associated with other workspaces. By manipulating the SSH asset identifier within API requests, a malicious user can bypass workspace-level access controls. 

This flaw grants the attacker unauthorized access to various file management endpoints, including downloading, uploading, reading, modifying, renaming, and deleting files on the compromised SSH host. The vulnerability represents a significant risk to environment isolation within the Jpom management platform, potentially leading to unauthorized data exfiltration or system modification. Defenders should prioritize patching to the version addressing this authorization flaw.

## Impact

The vulnerability allows for horizontal privilege escalation within Jpom, enabling attackers to execute sensitive file operations on SSH hosts outside their assigned workspace scope. If exploited, an attacker can read, modify, or delete files on any SSH host managed by the Jpom instance, facilitating data theft or persistence via configuration changes. The impact is significant for multi-tenant or multi-workspace environments.

## Recommendation

1. Upgrade Jpom to a version released after 2.11.12 that incorporates a patch for CVE-2026-111605.
2. Implement monitoring on Jpom web API endpoints to alert on unusual usage patterns where a single authenticated session interacts with multiple distinct SSH asset IDs.
3. Review access logs for the Jpom SshFileController endpoints mentioned (download, upload, read_file_data.json, etc.) to identify anomalies originating from accounts that should only have workspace-restricted access.
