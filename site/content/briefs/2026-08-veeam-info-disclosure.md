---
title: Information Disclosure Vulnerability in Veeam Backup & Replication
slug: 2026-08-veeam-info-disclosure
description: A local information disclosure vulnerability in Veeam Backup & Replication, identified as CVE-2024-40713, allows authenticated local attackers to gain unauthorized access to sensitive data.
date: "2026-08-26T14:04:57Z"
type: advisory
types:
  - advisory
severities:
  - medium
cpes:
  - cpe:2.3:a:veeam:veeam_backup_\&_replication:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - information-disclosure
vendors:
  - Veeam
products:
  - Backup & Replication
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1005
    technique_name: Data from Local System
    evidence: A local attacker can exploit a vulnerability in Veeam Backup & Replication to disclose information.
    confidence_band: high
cves:
  - id: CVE-2024-40713
    cvss: 7.8
    epss: 0.00315
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-3011
  - https://nvd.nist.gov/vuln/detail/CVE-2024-40713
action_plan:
  priority: elevated
  owners:
    - IT Operations
  mitigation_plan:
    - priority: immediate
      action: Patch Veeam Backup & Replication software to address CVE-2024-40713
      owner: IT Operations
      addresses: CVE-2024-40713
      evidence: Advisory indicates vulnerability exists in product; patching is the standard remediation
---

The German Federal Office for Information Security (BSI) has released a security advisory regarding a local information disclosure vulnerability within Veeam Backup & Replication. This flaw enables an authenticated local attacker to bypass existing security controls and access sensitive information stored or processed by the application. Because the vulnerability requires local access, the scope is primarily limited to environments where an attacker has already established a foothold on the underlying host operating system. The vulnerability is tracked as CVE-2024-40713. Defenders should prioritize auditing access controls on systems hosting Veeam Backup & Replication services and ensure that local user privileges are strictly enforced to minimize the risk of lateral movement or privilege escalation resulting from this disclosure.

## Impact

The vulnerability poses a significant risk to the integrity and confidentiality of backup environments. If successfully exploited, an attacker could extract sensitive data such as backup metadata, configurations, or credentials, which could facilitate further unauthorized access across the enterprise network. This impact is particularly severe in backup systems, which often hold centralized keys or administrative access to the entire infrastructure.

## Recommendation

Prioritize the application of vendor-provided security patches that address CVE-2024-40713 on all affected Veeam Backup & Replication server instances. Audit local user accounts and groups on Windows hosts running Veeam services to ensure the principle of least privilege is applied, particularly restricting access for non-administrative accounts that might interact with Veeam directories or local API endpoints. Review service account permissions to ensure they are not over-privileged, limiting the potential information an attacker could harvest if the service context is compromised.
