---
title: Critical Vulnerabilities in SAP NetWeaver and S/4HANA
slug: 2026-10-sap-critical-patches
description: SAP has released security updates addressing four critical-severity vulnerabilities, including SSRF, code injection, and authorization bypasses, across multiple enterprise platforms.
date: "2026-10-14T06:22:11Z"
type: threat
types:
  - threat
severities:
  - high
exploited: true
tags:
  - vulnerability
  - enterprise-software
  - patch-management
vendors:
  - SAP
products:
  - NetWeaver
  - S/4HANA
  - Cloud SDK for Python
  - Manufacturing Integration and Intelligence
  - Commerce Cloud
  - ABAP Platform
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The bugs could allow attackers to invoke internal operations and execute code, completely compromising the system.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: Missing authorization check in Manufacturing Integration and Intelligence that could allow an attacker... to create an administrator account.
    confidence_band: high
cves:
  - id: CVE-2026-89111
    cvss: 10
    epss: 0.00274
  - id: CVE-2026-89110
    cvss: 9.9
    epss: 0.00312
  - id: CVE-2026-89107
    cvss: 9.9
    epss: 0.00374
  - id: CVE-2026-89108
    cvss: 9.1
    epss: 0.00301
references:
  - https://www.securityweek.com/sap-patches-critical-netweaver-s-4hana-vulnerabilities/
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Patch SAP systems against CVE-2026-89111, CVE-2026-89110, CVE-2026-89107, and CVE-2026-89108.
      owner: IT Operations
      due: 48h
      evidence: SAP October 2026 Security Patch Day advisory
  mitigation_plan:
    - priority: immediate
      action: Review and restrict administrative roles within Manufacturing Integration and Intelligence.
      owner: Security Operations
      addresses: CVE-2026-89108
      evidence: Source documentation on missing authorization checks
---

SAP released security updates on October 14, 2026, resolving 22 security notes, including four critical-severity vulnerabilities. These flaws impact key infrastructure components, including SAP NetWeaver, S/4HANA, and the Cloud SDK for Python. The identified vulnerabilities range from Server-Side Request Forgery (SSRF) and broken access control to arbitrary code injection and missing authorization checks. 

Specifically, CVE-2026-89111 allows for OAuth2 token exfiltration via SSRF in Cloud SDK for Python, while CVE-2026-89110 and CVE-2026-89107 enable arbitrary code execution and internal operation invocation in NetWeaver and S/4HANA, respectively. Additionally, CVE-2026-89108 allows unauthorized creation of administrative accounts in Manufacturing Integration and Intelligence. While there is no current evidence of exploitation in the wild, the potential for complete system compromise necessitates immediate patching and configuration auditing.

## Impact

Successful exploitation of these vulnerabilities could result in the total compromise of SAP environments, including the exfiltration of sensitive credentials, execution of arbitrary ABAP or system-level code, and the creation of unauthorized administrative accounts. Organizations utilizing SAP NetWeaver, S/4HANA, or SAP BTP applications are at risk of data breaches and persistent unauthorized access if these flaws remain unpatched.

## Recommendation

* Prioritize patching for the four critical vulnerabilities: CVE-2026-89111, CVE-2026-89110, CVE-2026-89107, and CVE-2026-89108.
* Audit access controls for Fiori Applications to ensure input validation is enforced for all business roles as a mitigation for CVE-2026-89110.
* Review administrative account creation logs in SAP Manufacturing Integration and Intelligence to identify unauthorized account provisioning (CVE-2026-89108).
* Implement egress filtering for SAP Cloud SDK implementations to prevent potential token redirection and credential exfiltration related to CVE-2026-89111.
