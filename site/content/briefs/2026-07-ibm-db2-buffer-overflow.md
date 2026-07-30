---
title: Stack-based Buffer Overflow in IBM Db2 setgid Helper
slug: 2026-07-ibm-db2-buffer-overflow
description: IBM Db2 versions 11.5.0 through 11.5.9 and 12.1.0 through 12.1.4 contain a buffer overflow vulnerability in the db2flacc setgid helper that allows local attackers to escalate privileges.
date: "2026-07-30T19:30:40Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - privilege-escalation
  - buffer-overflow
  - ibm-db2
vendors:
  - IBM
products:
  - Db2 11.5
  - Db2 12.1
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation of Privilege Escalation Vulnerability
    evidence: IBM Db2 11.5.0 through 11.5.9, and 12.1.0 through 12.1.4 is vulnerable to buffer overflow in setgid helper db2flacc.
    confidence_band: high
cves:
  - id: CVE-2026-10535
    cvss: 8.4
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-10535
  - https://www.ibm.com/support/pages/node/7279466
rules:
  - title: Detect Potential Exploitation of CVE-2026-10535 - db2flacc Buffer Overflow
    description: Detects potential exploitation attempts against the 'db2flacc' setgid binary by monitoring for execution with suspicious or abnormally long command-line arguments.
    platform: sigma
    severity: high
    tactics:
      - privilege-escalation
    techniques:
      - T1068
    data_sources:
      - process_creation
      - linux
rules_count: 1
---

IBM has disclosed a stack-based buffer overflow vulnerability, identified as CVE-2026-10535, residing in the 'db2flacc' setgid helper binary within IBM Db2. This vulnerability affects multiple versions in the 11.5.x and 12.1.x release families. The db2flacc utility, which carries setgid permissions, fails to properly validate input, allowing a local attacker to trigger a buffer overflow. By successfully exploiting this flaw, a local user could potentially gain elevated privileges or perform unauthorized actions with the permissions associated with the setgid binary, impacting the overall confidentiality, integrity, and availability of the database instance. Given the nature of setgid binaries in administrative software, this vulnerability represents a significant risk for local privilege escalation within database server environments.

## Attack Chain

1. An attacker gains low-privileged access to a system running a vulnerable version of IBM Db2 (11.5.0-11.5.9 or 12.1.0-12.1.4).
2. The attacker identifies the location of the setgid helper binary 'db2flacc', typically found in the Db2 installation bin directory.
3. The attacker crafts a malicious input string designed to exceed the allocated buffer space within the 'db2flacc' executable.
4. The attacker executes the 'db2flacc' binary, passing the malicious input string as an argument.
5. The application experiences a buffer overflow, allowing the attacker to overwrite the stack memory.
6. The attacker injects or redirects execution to malicious code within the process context.
7. The process executes with group-level privileges, effectively escalating the attacker's permissions to those of the Db2 group.
8. The attacker proceeds to modify database files or configuration parameters to achieve full system control or data exfiltration.

## Impact

Successful exploitation of CVE-2026-10535 allows a local user to escalate privileges, potentially leading to full compromise of the database environment. This poses a high risk to organizations relying on IBM Db2 for sensitive data storage, as the impact includes potential data exfiltration, modification, or denial-of-service against the database engine.

## Recommendation

Prioritized actions for security teams:
- Immediately identify all servers running affected IBM Db2 versions (11.5.0-11.5.9 and 12.1.0-12.1.4) using asset management tools.
- Apply the vendor-provided patch from IBM as described in the official advisory (https://www.ibm.com/support/pages/node/7279466).
- Review system access controls to limit the number of users capable of executing the 'db2flacc' binary.
- Monitor for unusual execution patterns or crashes of the 'db2flacc' binary using audit logs or endpoint detection and response (EDR) solutions.
