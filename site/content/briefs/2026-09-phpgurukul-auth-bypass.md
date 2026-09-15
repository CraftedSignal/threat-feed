---
title: Authentication Bypass in PHPGurukul Blood Donor Management System
slug: 2026-09-phpgurukul-auth-bypass
description: PHPGurukul Blood Donor Management System 1.0 is vulnerable to an authentication bypass in the admin dashboard, allowing remote attackers to gain unauthorized administrative access.
date: "2026-09-15T01:37:25Z"
lastmod: "2026-09-15T01:37:34Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:phpgurukul:blood_donor_management_system:1.0:*:*:*:*:*:*:*
tags:
  - web-application
  - authentication-bypass
  - vulnerability
vendors:
  - PHPGurukul
products:
  - Blood Donor Management System (1.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1595
    technique_name: Active Scanning
    evidence: The attack can be initiated remotely.
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The attack can be launched remotely.
    confidence_band: high
cves:
  - id: CVE-2026-90840
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-90840
  - https://nvd.nist.gov/vuln/detail/CVE-2026-90841
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Restrict network access to admin interface
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-90840 allows remote unauthenticated access
  mitigation_plan:
    - priority: immediate
      action: Filter external access to the admin dashboard
      owner: IT Operations
      addresses: CVE-2026-90840
      evidence: NVD vulnerability details
updates:
  - at: "2026-09-15T01:37:34Z"
    level: L2
    summary: added coverage for Blood Donor Management System (1.0)
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-90841
---

A critical authentication vulnerability has been identified in the PHPGurukul Blood Donor Management System version 1.0. The flaw resides within the __construct function of the admin controller located at /application/controllers/admin/Dashboard.php. By manipulating this function, a remote, unauthenticated attacker can circumvent the application's authentication logic to access administrative functions. The vulnerability is publicly disclosed, and proof-of-concept exploit code is currently available, increasing the risk of opportunistic exploitation by malicious actors. Organizations utilizing this system should restrict external access to the administrative dashboard or transition to a secure alternative, as no vendor-provided patch has been documented.

## Impact

Successful exploitation of this vulnerability allows unauthorized actors to bypass authentication to the administrative panel. This can result in full administrative control over the Blood Donor Management System, potentially leading to unauthorized data exfiltration, database manipulation, or the compromise of sensitive donor and patient information managed by the platform.

## Recommendation

- Restrict network access to the admin dashboard interface to trusted management IP ranges via firewall rules.
- Implement web application firewall (WAF) rules to filter suspicious requests targeting /application/controllers/admin/Dashboard.php.
- Evaluate the necessity of the Blood Donor Management System 1.0 installation; given the lack of patching, consider decommissioning or replacing the system.
- Monitor web server access logs for anomalous, unauthenticated requests targeting administrative URI paths.
