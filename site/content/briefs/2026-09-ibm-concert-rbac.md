---
title: Improper RBAC Configuration in IBM Concert
slug: 2026-09-ibm-concert-rbac
description: IBM Concert versions 1.0.0 through 3.0.0 contain an access control vulnerability due to wildcard usage in RBAC permissions that allows authenticated attackers to access or modify unauthorized resources.
date: "2026-09-22T22:39:49Z"
lastmod: "2026-09-23T22:45:35Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:ibm:concert:1.0.0:*:*:*:*:*:*:*
  - cpe:2.3:a:ibm:concert:3.0.0:*:*:*:*:*:*:*
tags:
  - privilege-escalation
  - authorization-bypass
  - cloud-security
  - vulnerability
  - rce
  - webserver
  - buffer-overflow
  - memory-corruption
vendors:
  - IBM
products:
  - Concert (1.0.0 through 3.0.0)
  - Concert (1.0.0-3.0.0)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1078
    technique_name: Valid Accounts
    evidence: IBM Concert 1.0.0 through 3.0.0 could allow a remote authenticated attacker to access or modify unauthorized resources due to the use of wildcards in RBAC permission definitions.
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: IBM Concert 1.0.0 through 3.0.0 allows an unauthenticated remote attacker can supply specially craft input that is incorporated into OS commands
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: resulting in arbitrary command execution on the underlying system.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1210
    technique_name: Exploitation of Remote Services
    evidence: A local user could overflow the buffer and execute arbitrary code on the system.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1574
    technique_name: Hijack Execution Flow
    evidence: IBM Concert 1.0.0 through 3.0.0 invokes operating system commands without fully qualifying executable paths or adequately restricting search path resolution.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1574
    technique_name: Hijack Execution Flow
    evidence: As a result, an attacker with local system access can manipulate the search path environment to execute untrusted or malicious code.
    confidence_band: high
cves:
  - id: CVE-2026-17472
    cvss: 9.6
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-17472
  - https://nvd.nist.gov/vuln/detail/CVE-2026-6721
  - https://nvd.nist.gov/vuln/detail/CVE-2026-6730
  - https://nvd.nist.gov/vuln/detail/CVE-2026-6928
  - https://nvd.nist.gov/vuln/detail/CVE-2026-6794
  - https://nvd.nist.gov/vuln/detail/CVE-2026-6935
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Inventory all IBM Concert deployments and check current version
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-17472 impacts versions 1.0.0 through 3.0.0
  mitigation_plan:
    - priority: immediate
      action: Upgrade IBM Concert to a non-vulnerable version when available
      owner: IT Operations
      addresses: CVE-2026-17472
      evidence: NVD vulnerability disclosure
updates:
  - at: "2026-09-23T22:44:56Z"
    level: L2
    summary: added coverage for Concert (1.0.0 through 3.0.0)
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-6721
  - at: "2026-09-23T22:45:03Z"
    level: L2
    summary: added coverage for Concert (1.0.0 through 3.0.0)
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-6730
  - at: "2026-09-23T22:45:17Z"
    level: L2
    summary: added coverage for Concert (1.0.0-3.0.0)
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-6928
  - at: "2026-09-23T22:45:28Z"
    level: L2
    summary: added coverage for Concert (1.0.0 through 3.0.0)
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-6794
  - at: "2026-09-23T22:45:35Z"
    level: L2
    summary: added coverage for Concert (1.0.0 through 3.0.0)
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-6935
---

IBM Concert versions 1.0.0 through 3.0.0 are affected by an authorization bypass vulnerability identified as CVE-2026-17472. The issue stems from the implementation of wildcard characters within Role-Based Access Control (RBAC) permission definitions. This flaw permits a remote authenticated attacker to bypass intended authorization constraints, granting them the capability to access or modify resources outside the scope of their assigned privileges. Given the high CVSS score of 9.6, this vulnerability poses a significant risk of unauthorized data exposure or system manipulation for organizations utilizing affected versions of IBM Concert. Defenders should prioritize updating to a patched version to remediate the insecure permission logic.

## Impact

Successful exploitation of this vulnerability allows an authenticated attacker to perform unauthorized operations, leading to potential data exfiltration, integrity loss, or administrative control over sensitive Concert resources. Impact is localized to the Concert application environment and its managed data.

## Recommendation

Prioritize patching all instances of IBM Concert to the latest version provided by IBM that resolves the RBAC wildcard misconfiguration. Given the complexity of RBAC testing, review application logs for anomalous user access patterns or repeated unauthorized API calls originating from low-privileged accounts post-patching to ensure remediation is effective.
