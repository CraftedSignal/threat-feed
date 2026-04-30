---
title: Weblate Project Backup Vulnerability Leads to Potential Remote Code Execution (CVE-2026-33435)
slug: 2026-04-weblate-rce
description: Weblate versions before 5.17 are susceptible to remote code execution due to unfiltered Git and Mercurial configuration files in project backups, potentially allowing attackers to execute arbitrary code under specific conditions.
date: "2026-04-15T19:16:35Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - cve-2026-33435
  - rce
  - weblate
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-33435
    cvss: 8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-33435
  - https://github.com/WeblateOrg/weblate/pull/18549
  - https://github.com/WeblateOrg/weblate/security/advisories/GHSA-558g-h753-6m33
rules:
  - title: Detect Web Server Download of Backup Files
    description: Detects downloads of backup files from the web server, potentially indicating an attempt to exploit CVE-2026-33435.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Suspicious Upload of Git Configuration Files
    description: Detects the upload of .git/config files to a web server, potentially indicating an attempt to exploit CVE-2026-33435.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Weblate, a web-based localization tool, contains a vulnerability (CVE-2026-33435) in versions prior to 5.17. The flaw stems from the project backup functionality, which fails to adequately filter Git and Mercurial configuration files. This oversight can be exploited to achieve remote code execution (RCE) under certain circumstances. The vulnerability was reported and patched in version 5.17. Mitigation steps for unpatched systems involve restricting access to the project backup feature, as it is limited to users with project creation privileges. This vulnerability poses a significant risk, as successful exploitation can lead to complete system compromise, data breaches, and further malicious activities.

## Attack Chain

1. An attacker gains access to a Weblate account with project creation privileges.
2. The attacker creates a malicious project containing crafted Git or Mercurial configuration files.
3. The attacker triggers a project backup.
4. The backup process fails to properly sanitize the malicious configuration files.
5. The backup is stored on the server, potentially overwriting existing files.
6. The Weblate server attempts to process or utilize the tainted configuration files.
7. Due to improper sanitization, the malicious configuration files trigger command execution within the Weblate server's environment.
8. The attacker achieves remote code execution, gaining control over the Weblate server.

## Impact

Successful exploitation of CVE-2026-33435 can lead to remote code execution on the Weblate server. The impact includes potential data breaches, unauthorized access to localization projects, and complete compromise of the affected system. While the exact number of affected installations is unknown, organizations using vulnerable versions of Weblate risk significant operational disruption and data loss. Sectors utilizing Weblate for localization, such as software development, content creation, and e-commerce, are at increased risk.

## Recommendation

*   Upgrade Weblate to version 5.17 or later to patch CVE-2026-33435.
*   If upgrading is not immediately feasible, restrict access to the project backup feature to only trusted users as recommended in the CVE description.
*   Monitor web server logs for unusual activity related to project backup downloads, focusing on requests to /admin/backup/ paths. Use the provided Sigma rule to detect unusual file downloads from the webserver.
*   Implement the provided Sigma rule to detect suspicious file uploads of git configuration files.
