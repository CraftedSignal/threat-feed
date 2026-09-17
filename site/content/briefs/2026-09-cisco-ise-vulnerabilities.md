---
title: Critical Vulnerabilities in Cisco Identity Services Engine and ISE-PIC
slug: 2026-09-cisco-ise-vulnerabilities
description: Multiple vulnerabilities, including one actively exploited in the wild (CVE-2026-76460), allow unauthenticated attackers to bypass authentication and gain administrative control over Cisco ISE and ISE-PIC deployments.
date: "2026-09-17T19:05:59Z"
type: threat
types:
  - threat
severities:
  - critical
exploited: true
tags:
  - vulnerability
  - cisco
  - identity-management
  - authentication-bypass
vendors:
  - Cisco
products:
  - Identity Services Engine (ISE)
  - ISE Passive Identity Connector (ISE-PIC)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Successful exploitation could allow unauthenticated attackers to bypass authentication controls, gain administrative access, and potentially compromise affected systems.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: CVE-2026-76460... may allow an attacker to gain unauthorized access to the affected device by bypassing the web-based management interface.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1078
    technique_name: Valid Accounts
    evidence: This vulnerability is an Authentication Bypass by Spoofing vulnerability (CWE-290) that may enable the attacker to read and modify ISE configuration and identity data with administrative privileges.
    confidence_band: high
cves:
  - id: CVE-2026-20192
    cvss: 10
  - id: CVE-2026-76423
    cvss: 10
references:
  - https://cyber.gc.ca/en/alerts-advisories/al26-021-vulnerabilities-impacting-cisco-identity-services-engine-ise-cisco-ise-passive-identity-connector-ise-pic-cve-2026-20192-cve-2026-76423-cve-2026-76460
  - https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2026-76460
  - https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-hardening-ise-XU5EwX5T
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Upgrade affected Cisco ISE and ISE-PIC nodes to the latest patched releases
      owner: IT Operations
      due: 24h
      evidence: Vendor provided patch table
    - action: Review logs for anomalous administrative or API access
      owner: SOC
      due: 24h
      evidence: Recommendation to review access logs for indicators of compromise
  mitigation_plan:
    - priority: immediate
      action: Restrict management interface access via ACLs
      owner: IT Operations
      addresses: All CVEs
      evidence: Restrict access to management interfaces through access control lists (ACL)
---

Cisco has disclosed three vulnerabilities impacting the Cisco Identity Services Engine (ISE) and Cisco ISE Passive Identity Connector (ISE-PIC). The affected versions include releases prior to 3.0, as well as versions 3.1, 3.2, 3.3, 3.4, and 3.5. These flaws, identified as CVE-2026-20192 (Improper Access Control), CVE-2026-76423 (Authentication Bypass by Spoofing), and CVE-2026-76460 (Incorrect Use of Privileged APIs), enable unauthenticated attackers to bypass security controls, modify configurations, and obtain administrative privileges. 

Cisco has confirmed active exploitation of CVE-2026-76460, and it has been added to the CISA Known Exploited Vulnerabilities (KEV) catalog. Given the high-privilege nature of ISE within network environments, these vulnerabilities pose a significant threat to organizational security, potentially allowing attackers to gain full administrative access to identity and access management systems. Organizations are advised to update to the latest patched releases immediately and restrict management interface access.

## Impact

Successful exploitation of these vulnerabilities allows unauthenticated attackers to gain unauthorized administrative access to the Cisco ISE platform. This results in the ability to modify identity data, change system configurations, and intercept or manipulate sensitive identity information. In scenarios where ISE is used to control network access or authenticate internal users, successful compromise can lead to broad unauthorized access across the enterprise network.

## Recommendation

* Upgrade all Cisco ISE and ISE-PIC instances to the following patched versions immediately: 3.1 Patch 12, 3.2 Patch 11, 3.3 Patch 12, 3.4 Patch 7, or 3.5 Patch 4.
* Prioritize remediation of CVE-2026-76460 due to confirmed in-the-wild exploitation.
* Restrict network access to management interfaces for all Cisco ISE and ISE-PIC nodes using access control lists (ACLs) and network segmentation to trusted administration networks.
* Review administrative and API access logs for unauthorized or unexpected configuration changes or anomalous login activity.
* If compromise is suspected, re-image affected nodes and perform a full restore from known-good backups as attackers may have achieved persistent administrative access.
