---
title: Arbitrary Code Execution in IBM i via Untrusted Search Path
slug: 2026-08-ibm-i-untrusted-search-path
description: An untrusted search path vulnerability (CVE-2026-16674) in IBM i versions 7.3 through 7.6 allows a remote authenticated attacker to achieve arbitrary code execution.
date: "2026-08-13T22:05:29Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - ibm-i
  - cve-2026-16674
  - arbitrary-code-execution
  - untrusted-search-path
vendors:
  - IBM
products:
  - i
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1574
    technique_name: Hijack Execution Flow
    evidence: IBM i 7.6, 7.5, 7.4, and 7.3 could allow a remote authenticated attacker to execute arbitrary code due to an untrusted search path.
    confidence_band: high
cves:
  - id: CVE-2026-16674
    cvss: 8.8
references:
  - https://www.ibm.com/support/pages/node/7283286
  - https://nvd.nist.gov/vuln/detail/CVE-2026-16674
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Review IBM support page node 7283286 to identify the required PTFs for IBM i 7.3-7.6.
      owner: IT Operations
      due: 48h
      evidence: 'Source provided support URL: https://www.ibm.com/support/pages/node/7283286'
  mitigation_plan:
    - priority: immediate
      action: Patch affected IBM i instances to the recommended version provided by IBM.
      owner: IT Operations
      addresses: CVE-2026-16674
      evidence: IBM security advisory remediation path.
---

IBM has disclosed a security vulnerability identified as CVE-2026-16674, affecting IBM i operating system versions 7.3, 7.4, 7.5, and 7.6. The flaw is rooted in an untrusted search path mechanism (CWE-426), which may permit an attacker with authenticated remote access to execute arbitrary code with elevated privileges. 

By manipulating the search path, an attacker can influence the system to load malicious binaries or libraries instead of expected legitimate resources. Because this vulnerability is triggered during the execution of system functions, it poses a significant risk to the integrity and confidentiality of the affected IBM i environments. Defenders should prioritize patching, as this vulnerability carries a CVSS 3.1 base score of 8.8, indicating high severity and potential for significant impact if exploited.

## Impact

Successful exploitation of this vulnerability allows a remote authenticated attacker to execute arbitrary code on the target IBM i system. This could lead to full system compromise, data exfiltration, or unauthorized administrative control over the affected infrastructure. The vulnerability affects critical versions of the IBM i platform, impacting enterprises that rely on these systems for core business operations.

## Recommendation

- Apply the relevant security patches provided by IBM for the IBM i operating system immediately.
- Review the official IBM support advisory for CVE-2026-16674 to verify the specific PTF (Program Temporary Fix) levels required for your version of IBM i.
- Audit system configurations to ensure search path environments are strictly controlled and restricted to authorized, read-only directories where possible to mitigate similar CWE-426 vectors.
