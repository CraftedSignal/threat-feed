---
title: Authorization Bypass in File Browser via Recursive Operations
slug: 2026-08-file-browser-access-bypass
description: File Browser versions prior to 2.63.22 contain an authorization bypass vulnerability allowing authenticated users to manipulate restricted files via recursive copy, rename, and delete operations.
date: "2026-08-13T12:55:18Z"
lastmod: "2026-08-13T12:55:42Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - vulnerability
  - access-control-bypass
  - cve
  - file-deletion
  - path-traversal
vendors:
  - File Browser
  - FileBrowser
products:
  - File Browser (< 2.63.22)
  - filebrowser (< 2.63.19)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: Authenticated users can perform unauthorized copy, rename, or delete actions on files restricted by access control rules by manipulating a parent directory that they are permitted to access.
    confidence_band: high
cves:
  - id: CVE-2026-73612
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-73612
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade File Browser to v2.63.22 or higher
      owner: IT Operations
      due: 48h
      evidence: Remediation for CVE-2026-73612
  mitigation_plan:
    - priority: immediate
      action: Review and restrict user permissions to sensitive parent directories
      owner: IT Operations
      addresses: CVE-2026-73612
      evidence: NVD vulnerability details
updates:
  - at: "2026-08-13T12:55:42Z"
    level: L1
    summary: added coverage for filebrowser (< 2.63.19)
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-73613
---

File Browser versions prior to 2.63.22 are affected by an authorization bypass vulnerability stemming from a flaw in how the application validates access rules during recursive file operations. Authenticated users with limited permissions to a parent directory can circumvent access control rules to perform unauthorized actions on descendant files or directories. The vulnerability manifests during copy, rename, and delete operations, where the system fails to verify that the target files or destination paths adhere to the organization's defined access constraints. This allows a low-privileged user to impact the confidentiality and integrity of restricted files by initiating recursive commands from a parent folder for which they have valid access. This issue is tracked as CVE-2026-73612 and carries a CVSS base score of 8.1.

## Impact

Successful exploitation allows authenticated users to bypass path-based access controls, potentially leading to unauthorized data exfiltration (via copy), unauthorized data destruction (via delete), or directory structure manipulation (via rename). This can result in significant loss of confidentiality and integrity for files that were intended to be protected by administrative or user-based access rules.

## Recommendation

1. Upgrade File Browser installations to version 2.63.22 or later to remediate the authorization logic flaw identified in CVE-2026-73612.
2. Audit current access control rules within the File Browser environment to identify any over-privileged user roles that could facilitate this attack.
3. Monitor file management logs for anomalous patterns of recursive copy, move, or delete operations originating from low-privileged accounts or unexpected directory paths.
