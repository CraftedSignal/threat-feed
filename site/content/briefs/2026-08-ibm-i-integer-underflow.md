---
title: Integer Underflow Vulnerability in IBM i
slug: 2026-08-ibm-i-integer-underflow
description: IBM i versions 7.3 through 7.6 are vulnerable to an integer underflow flaw (CVE-2026-17485) that could allow a remote, unauthenticated attacker to cause a denial of service or perform an out-of-bounds read to access sensitive information.
date: "2026-08-12T22:53:16Z"
lastmod: "2026-08-13T22:06:09Z"
type: advisory
types:
  - advisory
severities:
  - high
vendors:
  - IBM
products:
  - i
  - i (7.3, 7.4, 7.5, 7.6)
  - i (7.4, 7.5, 7.6)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1498
    technique_name: Network Denial of Service
    evidence: IBM i 7.6, 7.5, 7.4, and 7.3 could allow a remote attacker to cause a denial of service and obtain sensitive information due to an integer underflow.
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1558
    technique_name: Steal or Forge Kerberos Tickets
    evidence: IBM i 7.6, 7.5, 7.4, and 7.3 could allow a remote attacker to access server resources with the privileges of an authenticated user due to improper authentication during NTLM session negotiation.
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: A remote attacker could send specially crafted SQL statements, which could allow the attacker to view, add, modify, or delete information in the back-end database.
    confidence_band: high
cves:
  - id: CVE-2026-17485
    cvss: 8.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-17485
  - https://www.ibm.com/support/pages/node/7282695
  - https://nvd.nist.gov/vuln/detail/CVE-2026-16867
  - https://www.ibm.com/support/pages/node/7283573
  - https://nvd.nist.gov/vuln/detail/CVE-2026-16961
  - https://www.ibm.com/support/pages/node/7283298
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Patch IBM i versions 7.3-7.6 using the updates specified in IBM support node 7282695.
      owner: IT Operations
      due: 48h
      evidence: IBM security bulletin node 7282695 provides the necessary remediation for CVE-2026-17485.
updates:
  - at: "2026-08-13T22:05:43Z"
    level: L2
    summary: added coverage for i (7.3, 7.4, 7.5, 7.6)
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-16867
  - at: "2026-08-13T22:06:09Z"
    level: L2
    summary: added coverage for i (7.4, 7.5, 7.6)
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-16961
---

IBM has disclosed a critical integer underflow vulnerability (CVE-2026-17485) affecting IBM i operating system versions 7.3, 7.4, 7.5, and 7.6. This vulnerability arises from an integer underflow condition, categorized as CWE-125 (Out-of-bounds Read). The flaw allows a remote, unauthenticated attacker with network access to the target system to trigger a denial of service (DoS) condition or gain unauthorized access to sensitive information. Given the CVSS v3.1 base score of 8.2 and the potential for unauthenticated remote exploitation, this poses a significant risk to organizations running these versions of IBM i. Defenders should prioritize applying the security updates provided by IBM to mitigate the risk of service disruption and data exposure.

## Impact

Successful exploitation of this vulnerability could lead to significant operational disruption through service crashes (denial of service) and potential unauthorized disclosure of sensitive system memory contents. The vulnerability affects a wide range of enterprise environments currently utilizing IBM i versions 7.3 through 7.6.

## Recommendation

- Apply the security patches referenced in IBM Security Bulletin APAR node 7282695 immediately to all affected IBM i systems.
- Review network configurations to restrict unauthorized remote access to IBM i services, as the vulnerability is exploitable by remote, unauthenticated attackers.
- Audit system logs for unexpected service restarts or abnormal memory access errors that may indicate exploitation attempts.
