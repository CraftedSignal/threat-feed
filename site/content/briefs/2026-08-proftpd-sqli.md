---
title: 'CVE-2026-42167: Remote Code Execution via ProFTPD mod_sql'
slug: 2026-08-proftpd-sqli
description: An authenticated SQL injection vulnerability (CVE-2026-42167) in the ProFTPD mod_sql module allows attackers to achieve remote code execution, with a functional exploit now publicly available.
date: "2026-08-25T16:37:15Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:proftpd:proftpd:*:*:*:*:*:*:*:*
vendors:
  - ProFTPD
products:
  - ProFTPD
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: CVE-2026-42167 describes a post-authentication SQL injection vulnerability in the ProFTPD mod_sql module, which can be leveraged to achieve remote code execution.
    confidence_band: high
cves:
  - id: CVE-2026-42167
    cvss: 8.1
    epss: 0.04275
references:
  - https://www.exploit-db.com/exploits/52658
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Patch ProFTPD instances to address CVE-2026-42167
      owner: IT Operations
      due: 48h
      evidence: Public exploit (EDB-52658) availability significantly elevates the risk for unpatched systems.
  mitigation_plan:
    - priority: immediate
      action: Disable mod_sql module if not in use
      owner: IT Operations
      addresses: CVE-2026-42167
      evidence: The vulnerability exists specifically within the mod_sql module.
---

CVE-2026-42167 is a critical vulnerability affecting the ProFTPD server, specifically within the mod_sql module. This vulnerability allows an authenticated user to perform SQL injection attacks, which can be further weaponized to achieve remote code execution on the underlying host. The vulnerability was disclosed alongside a functional exploit (EDB-52658), significantly increasing the risk to environments where ProFTPD is deployed with SQL-based authentication or logging enabled. Defenders should prioritize patching or disabling the mod_sql module if it is not strictly required, as the public availability of the exploit simplifies the path to system compromise for attackers who have obtained valid FTP credentials.

## Impact

Successful exploitation allows for arbitrary code execution with the privileges of the ProFTPD service. This can lead to full system compromise, data exfiltration, and lateral movement within the network. The scope of impact is limited to servers running ProFTPD with the mod_sql module enabled.

## Recommendation

- Apply vendor patches for CVE-2026-42167 across all affected ProFTPD instances immediately.
- Disable the mod_sql module in the ProFTPD configuration file if it is not necessary for business operations.
- Monitor authentication logs for suspicious patterns originating from authenticated FTP users, specifically those interacting with database-backed authentication components.
