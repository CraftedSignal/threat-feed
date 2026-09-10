---
title: Multiple Vulnerabilities in AVEVA Pipeline Integrity Monitor
slug: 2026-09-aveva-pim-vulnerabilities
description: AVEVA Pipeline Integrity Monitor versions through 2025_SP1_P1_build_7.1.9580.8513 contain multiple vulnerabilities including hard-coded keys and improper authorization, facilitating information disclosure, credential brute-forcing, and XSS-based code execution.
date: "2026-09-10T16:07:40Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:aveva:pipeline_integrity_monitor:*:*:*:*:*:*:*:*
tags:
  - industrial-control-systems
  - vulnerability
  - critical-infrastructure
vendors:
  - AVEVA
products:
  - Pipeline Integrity Monitor (<= 2025_SP1_P1_build_7.1.9580.8513)
cves:
  - id: CVE-2026-81821
    cvss: 8.4
    epss: 0.00143
  - id: CVE-2026-81822
    cvss: 8.4
    epss: 0.00108
  - id: CVE-2026-81823
    cvss: 5.3
    epss: 0.00313
  - id: CVE-2026-81824
    cvss: 4.7
    epss: 0.00297
references:
  - https://www.cisa.gov/news-events/ics-advisories/icsa-26-253-01
  - https://www.aveva.com/content/dam/aveva/documents/support/cyber-security-updates/SecurityBulletin_AVEVA-2026-006.pdf
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade to AVEVA Pipeline Integrity Monitor 2025 SP1 P2 and migrate project files
      owner: IT Operations
      due: 48h
      evidence: Vendor remediation guidance for CVE-2026-81821 through CVE-2026-81824
    - action: Force password resets for all PIMBoards users
      owner: IT Operations
      due: 48h
      evidence: Vendor recommendation for CVE-2026-81822
  mitigation_plan:
    - priority: immediate
      action: Restrict read access to PIMBoards project files (.pimboards or equivalent)
      owner: IT Operations
      addresses: CVE-2026-81821, CVE-2026-81822
      evidence: Vendor mitigation for unmigrated project files
---

AVEVA Pipeline Integrity Monitor (PIM) is affected by four vulnerabilities (CVE-2026-81821, CVE-2026-81822, CVE-2026-81823, CVE-2026-81824) impacting PIMBoards project files and user sessions. The vulnerabilities, discovered in versions up to 2025_SP1_P1_build_7.1.9580.8513, allow attackers with read access to project files to decrypt sensitive information or perform brute-force attacks against weak password hashes, potentially leading to administrative privilege escalation. Furthermore, missing authorization allows unauthorized unauthenticated read access to PIMBoards data. Finally, an XSS vulnerability enables arbitrary JavaScript execution within an authenticated user's browser session via social engineering. Given the use in critical infrastructure sectors, these vulnerabilities present a significant risk for data exfiltration and credential compromise.

## Impact

Successful exploitation allows for unauthorized disclosure of sensitive industrial information, compromise of user credentials leading to administrative access within PIMBoards, and potential session hijacking or further malicious activity through arbitrary code execution in browser environments. These risks affect global deployments in the Critical Manufacturing sector.

## Recommendation

* Apply the AVEVA Pipeline Integrity Monitor 2025 SP1 P2 Security Update immediately and perform the required one-way migration of PIMBoards project files.
* For project files that cannot be migrated (e.g., backups or transient copies), implement strict file-system read access controls to mitigate the risk of unauthorized decryption.
* Enforce a mandatory password change for all PIMBoards users following the upgrade to 2025 SP1 P2, as the migration changes underlying password hashing algorithms.
* Review security bulletin AVEVA-2026-006 for full remediation details and architectural guidance.
