---
title: Path Traversal Vulnerability in AKINSOFT Wolvox9 ERP
slug: 2026-08-akinsoft-path-traversal
description: A path traversal vulnerability (CVE-2026-15585) in AKINSOFT Wolvox9 ERP KontrolPanel.exe versions s26.02.17 through s26.02.21 allows unauthenticated remote attackers to read arbitrary files from the host filesystem.
date: "2026-08-18T12:52:20Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - vulnerability
  - path-traversal
  - erp
vendors:
  - AKIN Software Computer Import Export Industry and Trade Ltd.
products:
  - AKINSOFT Wolvox9 ERP
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') vulnerability in AKIN Software Computer Import Export Industry and Trade Ltd. AKINSOFT Wolvox9 ERP / KontrolPanel.exe allows Path Traversal.
    confidence_band: high
cves:
  - id: CVE-2026-15585
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-15585
  - https://siberguvenlik.gov.tr/guvenlik-bildirimleri/detay/tr-26-0851
action_plan:
  priority: elevated
  owners:
    - IT Operations
  immediate_actions:
    - action: Patch AKINSOFT Wolvox9 ERP to version 26.02.22
      owner: IT Operations
      due: 48h
      evidence: Vendor advisory fix version
---

AKINSOFT Wolvox9 ERP contains a path traversal vulnerability (CVE-2026-15585) within the KontrolPanel.exe component. The vulnerability arises from an improper limitation of a pathname to a restricted directory, enabling unauthenticated remote attackers to manipulate file paths to access files outside the intended web root. This flaw affects product versions starting from s26.02.17 up to, but not including, s26.02.22. Successful exploitation results in unauthorized disclosure of sensitive files residing on the host operating system. As this is an unauthenticated vector, it presents a significant risk to organizations hosting this software on internet-facing infrastructure.

## Impact

The vulnerability allows an unauthenticated, remote attacker to bypass directory restrictions and access arbitrary files on the underlying Windows system. This can lead to the exposure of sensitive configuration files, credentials, or application data. Given the CVSS 3.1 base score of 7.5, the impact is considered high, particularly for organizations that have not updated to version 26.02.22 or later.

## Recommendation

- Update AKINSOFT Wolvox9 ERP / KontrolPanel.exe to version 26.02.22 or higher immediately to remediate the path traversal vulnerability.
- Restrict access to the KontrolPanel.exe interface via network-level controls if an immediate update is not possible.
- Review web server access logs for requests containing directory traversal sequences (e.g., ../ or ..%2f) directed at the application to identify potential exploitation attempts.
