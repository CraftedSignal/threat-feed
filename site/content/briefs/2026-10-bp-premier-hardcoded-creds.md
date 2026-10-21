---
brief_id: brief-2026-10-21-bp-premier-hardcoded-creds
event_id: brief-2026-10-21-bp-premier-hardcoded-creds
revision: 1
activity_at: "2026-10-21T02:15:22Z"
title: Best Practice Software Bp Premier hardcoded SQL Server administrative password (CVE-2026-114119)
slug: 2026-10-bp-premier-hardcoded-creds
description: Best Practice Software Bp Premier versions prior to 1.14.1.1128 contain a hardcoded Microsoft SQL Server administrative password that allows remote unauthenticated attackers to execute operating system commands as SYSTEM.
date: "2026-10-21T02:15:22Z"
type: advisory
types:
  - advisory
severities:
  - critical
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Source documentation sufficient for summary and recommendations
tags:
  - credential-exposure
  - rce
  - privilege-escalation
vendors:
  - Best Practice Software
  - Microsoft
products:
  - Bp Premier (< 1.14.1.1128)
  - SQL Server (< 1.14.1.1128)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1552
    technique_name: Unsecured Credentials
    subtechnique_id: T1552.001
    subtechnique_name: Credentials In Files
    evidence: Best Practice Software Bp Premier before 1.14.1.1128 uses a hardcoded Microsoft SQL Server administrative password that is shared across all installations.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: Attackers with network access to the database instance can authenticate as sysadmin, bypass application authentication, and execute operating system commands as SYSTEM.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    subtechnique_id: T1059.003
    subtechnique_name: Windows Command Shell
    evidence: Attackers... execute operating system commands as SYSTEM.
    confidence_band: high
cves:
  - id: CVE-2026-114119
    cvss: 9.8
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-114119
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Security Engineering
  immediate_actions:
    - action: Upgrade Bp Premier to 1.14.1.1128 or later
      owner: IT Operations
      due: 24h
      evidence: NVD vulnerability disclosure
  mitigation_plan:
    - priority: immediate
      action: Restrict SQL Server network access to trusted hosts only
      owner: IT Operations
      addresses: CVE-2026-114119
      evidence: CVE-2026-114119
---

Best Practice Software Bp Premier versions before 1.14.1.1128 utilize a hardcoded Microsoft SQL Server administrative password. This credential is shared across all installations and is functionally required by the application, meaning it cannot be altered by administrators without causing operational failure. An attacker with network reach to the database instance can leverage this hardcoded credential to authenticate as a sysadmin. Once authenticated, the attacker can interact directly with the database engine to perform unauthorized queries, bypass application-level access controls, and use SQL Server stored procedures (such as xp_cmdshell) to execute operating system commands with SYSTEM privileges on the underlying host. This vulnerability represents a critical risk to health-sector environments where the software is deployed, as it grants full control over the database and host system.

## Attack Chain

1. Attacker performs network reconnaissance to identify accessible Microsoft SQL Server instances on the network.
2. Attacker establishes a connection to the identified SQL Server instance using the hardcoded administrative credential.
3. Attacker authenticates to the database as an account with sysadmin-level privileges.
4. Attacker enables advanced configuration features within the SQL Server instance if not already active (e.g., sp_configure 'show advanced options', 1).
5. Attacker enables the xp_cmdshell stored procedure to facilitate command execution.
6. Attacker executes arbitrary system commands via xp_cmdshell to establish persistence or exfiltrate data.
7. Attacker gains full control over the host operating system with SYSTEM-level permissions.

## Impact

Successful exploitation results in full compromise of the Bp Premier database and the host operating system. Given the nature of this software in medical environments, impact includes potential unauthorized access to sensitive patient health information, database destruction, and long-term persistence in the infrastructure of medical practices.

## Recommendation

* Patch Bp Premier to version 1.14.1.1128 or later immediately to address the hardcoded credential issue.
* Restrict network access to Microsoft SQL Server instances used by Bp Premier to only authorized application servers using host-based firewalls or network segmentation.
* Audit SQL Server logs for unauthorized connection attempts or usage of system-level stored procedures.
* Disable the xp_cmdshell procedure at the database level if it is not explicitly required for application operation.
