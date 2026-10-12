---
title: IBM Db2 Privilege Escalation Vulnerability
slug: 2026-10-ibm-db2-privilege-escalation
description: IBM Db2 versions 11.5.0-11.5.9 and 12.1.0-12.1.5 contain an improper privilege management vulnerability allowing local users to escalate privileges.
date: "2026-10-12T20:30:28Z"
lastmod: "2026-10-12T20:30:36Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:ibm:db2:*:*:*:*:*:*:*:*
tags:
  - privilege-escalation
  - database-security
  - vulnerability
vendors:
  - IBM
products:
  - Db2 (11.5.0-11.5.9, 12.1.0-12.1.5)
  - Db2 Connect Server (11.5.0-11.5.9, 12.1.0-12.1.5)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: IBM Db2 versions 11.5.0 through 11.5.9, and 12.1.0 through 12.1.5 for Linux, UNIX and Windows (includes DB2 Connect Server) could allow a local attacker to gain elevated privileges due to improper privilege management.
    confidence_band: high
cves:
  - id: CVE-2026-105464
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-105464
  - https://nvd.nist.gov/vuln/detail/CVE-2026-105465
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Engineering
  immediate_actions:
    - action: Patch IBM Db2 instances to the version identified as remediating CVE-2026-105464
      owner: IT Operations
      due: 72h
      evidence: CVE-2026-105464 report
  mitigation_plan:
    - priority: immediate
      action: Review and restrict access to system files and database utilities for non-administrative local users
      owner: Security Engineering
      addresses: CVE-2026-105464
      evidence: NVD vulnerability details
updates:
  - at: "2026-10-12T20:30:36Z"
    level: L2
    summary: added coverage for Db2 (11.5.0-11.5.9, 12.1.0-12.1.5)
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-105465
---

IBM Db2, including the Db2 Connect Server component, is affected by a local privilege escalation vulnerability (CVE-2026-105464). The flaw exists in versions 11.5.0 through 11.5.9, as well as 12.1.0 through 12.1.5, across Linux, UNIX, and Windows platforms. The vulnerability stems from improper privilege management within the database environment, which could allow a local attacker who already has access to the system to elevate their permissions. This could potentially allow an attacker to perform unauthorized database operations, access sensitive data, or gain further control over the database instance. Organizations using the affected versions of Db2 should assess the vulnerability and apply the appropriate security updates provided by IBM to remediate the privilege management defect.

## Impact

The successful exploitation of this vulnerability allows a local user to gain unauthorized elevated privileges. This could lead to a full compromise of the database environment, including data exfiltration, manipulation, or unauthorized administrative control, depending on the scope of the escalated privileges and the configuration of the affected Db2 instance.

## Recommendation

- Identify all instances of IBM Db2 and Db2 Connect Server within the environment to determine if they fall within the affected version ranges (11.5.0-11.5.9 or 12.1.0-12.1.5).
- Apply the security patches or upgrade to the version provided by IBM that resolves CVE-2026-105464.
- Review local system access logs for unauthorized attempts to escalate privileges or unexpected use of administrative Db2 command-line utilities.
- Restrict access to database management utilities and configuration files to only authorized administrative accounts to minimize the risk of local exploitation.
