---
title: Multiple Vulnerabilities in Veeam Backup and Replication
slug: 2026-10-veeam-vulnerabilities
description: Multiple vulnerabilities, including remote code execution, have been identified in Veeam Backup & Replication versions prior to 12.3.2 P4.
date: "2026-10-07T16:45:20Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:veeam:backup_replication:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - remote-code-execution
  - backup-infrastructure
vendors:
  - Veeam
products:
  - Backup & Replication (< 12.3.2.4934)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: They allow an attacker to provoke remote code execution and unauthorized data access.
    confidence_band: high
cves:
  - id: CVE-2025-64392
  - id: CVE-2025-64393
  - id: CVE-2026-93026
references:
  - https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1278/
  - https://www.veeam.com/kb4934
  - https://www.cve.org/CVERecord?id=CVE-2025-64392
  - https://www.cve.org/CVERecord?id=CVE-2025-64393
  - https://www.cve.org/CVERecord?id=CVE-2026-93026
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
  mitigation_plan:
    - priority: immediate
      action: Upgrade Veeam Backup & Replication to version 12.3.2.4934 or later
      owner: IT Operations
      addresses: CVE-2025-64392, CVE-2025-64393, CVE-2026-93026
      evidence: Source bulletin kb4934
---

Veeam has released security bulletin kb4934 addressing multiple vulnerabilities affecting Veeam Backup & Replication. The identified flaws, tracked as CVE-2025-64392, CVE-2025-64393, and CVE-2026-93026, pose significant risks to backup infrastructure. Successful exploitation may result in remote code execution (RCE), unauthorized access to sensitive backup data, and cross-site scripting (XSS). These vulnerabilities affect all versions of Veeam Backup & Replication prior to 12.3.2 P4 (build 12.3.2.4934). Given the critical nature of backup infrastructure, unauthorized control or data tampering could facilitate ransomware deployment or long-term persistence within an organization. Organizations should prioritize patching to version 12.3.2.4934 or later.

## Impact

Successful exploitation of these vulnerabilities allows an attacker to compromise the integrity and confidentiality of backup data, as well as achieve remote code execution on the server hosting the Veeam Backup & Replication service. This potentially grants an attacker full control over the backup environment, which is frequently targeted to delete backups or exfiltrate sensitive enterprise data.

## Recommendation

- Upgrade all instances of Veeam Backup & Replication to version 12.3.2 P4 (build 12.3.2.4934) or later immediately.
- Review the official Veeam security bulletin kb4934 for detailed remediation steps and configuration changes.
- Audit logs for the Veeam Backup & Replication service for any unauthorized access or unusual web-based requests that could indicate exploitation attempts (CVE-2025-64392, CVE-2025-64393, CVE-2026-93026).
