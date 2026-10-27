---
brief_id: brief-2026-10-27-filebrowser-quantum-path-traversal
event_id: brief-2026-10-27-filebrowser-quantum-path-traversal
revision: 1
activity_at: "2026-10-27T20:04:34Z"
title: 'FileBrowser Quantum: Arbitrary file read via symbolic link traversal (CVE-2026-116682)'
slug: 2026-10-filebrowser-quantum-path-traversal
description: FileBrowser Quantum versions prior to 1.5.2-stable and 2.0.1-beta contain a path-traversal vulnerability that allows authenticated or unauthorized users to read arbitrary server files by exploiting improperly validated symbolic links.
date: "2026-10-27T20:04:34Z"
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
  - cpe:2.3:a:filebrowser_quantum:filebrowser_quantum:*:*:*:*:*:*:*:*
tags:
  - file-read
  - path-traversal
  - webserver
  - cve-2026-116682
vendors:
  - FileBrowser Quantum
products:
  - FileBrowser Quantum (< 1.5.2-stable, < 2.0.1-beta)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An authenticated user with download access can read server-accessible files outside the assigned scope, and a holder of a public share link can do the same without an account.
    confidence_band: high
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1005
    technique_name: Data from Local System
    evidence: Download, preview, media, OnlyOffice, and public-share read flows that enable FollowSymlinks can therefore serve an out-of-scope target.
    confidence_band: high
cves:
  - id: CVE-2026-116682
    cvss: 8.6
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-116682
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade all FileBrowser Quantum deployments to version 1.5.2-stable, 2.0.1-beta, or later.
      owner: IT Operations
      due: 48h
      evidence: This issue is fixed in 1.5.2-stable and 2.0.1-beta.
  hunt_leads:
    - lead: Identify the presence of symbolic links within web-accessible file storage directories.
      technique_id: T1005
      data_needed:
        - Host filesystem scan results
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: The vulnerability relies on serving an out-of-scope target through a reachable in-scope symlink.
    - lead: Analyze web server logs for suspicious access patterns to file download or preview endpoints targeting known sensitive system paths.
      technique_id: T1005
      data_needed:
        - Web server access logs
      priority: medium
      confidence: medium
      disposition: convert_to_detection
      evidence: Download, preview, media, OnlyOffice, and public-share read flows... can therefore serve an out-of-scope target.
  mitigation_plan:
    - priority: immediate
      action: Upgrade to version 1.5.2-stable or 2.0.1-beta.
      owner: IT Operations
      addresses: CVE-2026-116682
      evidence: This issue is fixed in 1.5.2-stable and 2.0.1-beta.
---

FileBrowser Quantum versions prior to 1.5.2-stable and 2.0.1-beta are vulnerable to an arbitrary file read flaw (CVE-2026-116682) located in the backend file indexing logic. The application fails to validate symbolic links during resolution, allowing the service to traverse outside of the authorized root directory. This vulnerability affects multiple file access flows, including file downloads, previews, media rendering, OnlyOffice integration, and public shares. An attacker can access sensitive system files by placing a symlink within an accessible directory that points to an out-of-scope target on the host filesystem.

## Impact

Successful exploitation allows authenticated users, or unauthenticated users via public share links, to read arbitrary files from the underlying server filesystem. This can lead to the exposure of configuration files, credentials, or other sensitive system data.

## Recommendation

- Upgrade FileBrowser Quantum to version 1.5.2-stable, 2.0.1-beta, or later immediately to apply the patch for CVE-2026-116682.
- Audit existing shared directories for the presence of symbolic links that may point to sensitive host filesystem locations (e.g., /etc/shadow, configuration files).
- Review access logs for web requests to the file manager that include unexpected traversal patterns or attempt to resolve symlink structures.
