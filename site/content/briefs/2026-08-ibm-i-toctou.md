---
title: IBM i TOCTOU Race Condition Vulnerability
slug: 2026-08-ibm-i-toctou
description: IBM i versions 7.3 through 7.6 contain a time-of-check time-of-use (TOCTOU) race condition that allows a local authenticated attacker to gain unauthorized access to sensitive files.
date: "2026-08-13T22:05:55Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - ibm-i
  - cve
  - race-condition
  - privilege-escalation
vendors:
  - IBM
products:
  - i 7.3
  - i 7.4
  - i 7.5
  - i 7.6
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: IBM i 7.6, 7.5, 7.4, and 7.3 could allow a local authenticated attacker to obtain unauthorized access to files due to a time-of-check time-of-use (TOCTOU) race condition.
    confidence_band: high
cves:
  - id: CVE-2026-16896
    cvss: 7.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-16896
  - https://www.ibm.com/support/pages/node/7283293
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Apply available PTFs for CVE-2026-16896 as documented by IBM
      owner: IT Operations
      due: 48h
      evidence: 'Vendor advisory: https://www.ibm.com/support/pages/node/7283293'
  mitigation_plan:
    - priority: immediate
      action: Restrict local authenticated access to essential users only
      owner: IT Operations
      addresses: CVE-2026-16896
      evidence: Vulnerability requires local authenticated access
---

IBM i (formerly OS/400) versions 7.3, 7.4, 7.5, and 7.6 are affected by a race condition vulnerability tracked as CVE-2026-16896. The flaw stems from a time-of-check time-of-use (TOCTOU) error, which is categorized under CWE-367. This vulnerability requires the attacker to have local authenticated access to the system. By leveraging this race condition, an attacker can manipulate file operations between the initial security validation and the actual file access, potentially leading to unauthorized data disclosure or unauthorized modification of protected files. This vulnerability poses a significant risk to the integrity and confidentiality of the IBM i system, as it can be leveraged for privilege escalation or unauthorized data access.

## Impact

Successful exploitation allows a local authenticated attacker to bypass file permission controls, resulting in unauthorized access to sensitive system or user data. This could be used by malicious actors to escalate their privileges or exfiltrate restricted information. The scope of targeting covers any environment where IBM i is deployed and internal users or compromised accounts have local access to the system.

## Recommendation

- Apply the vendor-provided patch immediately; refer to the IBM support page at https://www.ibm.com/support/pages/node/7283293 for the latest PTF (Program Temporary Fix) information.
- Audit system logs for unusual file access patterns or repeated failed attempts by local users that might indicate exploitation attempts.
- Review user account permissions to ensure that only necessary users have local interactive access to IBM i environments.
