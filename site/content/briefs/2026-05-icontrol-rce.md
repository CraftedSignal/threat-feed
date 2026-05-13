---
title: F5 iControl REST RCE Vulnerability (CVE-2026-41225)
slug: 2026-05-icontrol-rce
description: CVE-2026-41225 allows a highly privileged, authenticated attacker with at least the Manager role to create configuration objects in F5 iControl REST, leading to arbitrary command execution.
date: "2026-05-13T16:17:56Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - cve
  - rce
  - f5
  - icontrol
vendors:
  - F5 Networks
products:
  - iControl REST
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.004
    technique_name: Command and Scripting Interpreter
cves:
  - id: CVE-2026-41225
    cvss: 9.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-41225
  - https://my.f5.com/manage/s/article/K000160916
rules:
  - title: Detect iControl REST Configuration Object Manipulation
    description: Detects CVE-2026-41225 exploitation — creation or modification of configuration objects via the iControl REST API, indicating potential command injection attempts.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - webserver
  - title: Detect iControl REST API Authentication Attempts
    description: Detects authentication attempts to the iControl REST API, which may precede or follow exploitation of CVE-2026-41225. Monitor for unusual login patterns.
    platform: sigma
    severity: low
    tactics:
      - initial_access
    techniques:
      - T1078
    data_sources:
      - webserver
rules_count: 2
---

CVE-2026-41225 is a critical vulnerability affecting F5 iControl REST. It enables a highly privileged attacker, authenticated with at least the Manager role, to create malicious configuration objects. This flaw stems from an incorrect use of privileged APIs, potentially allowing the injection of arbitrary commands. Successful exploitation leads to Remote Code Execution (RCE) on the affected system, compromising its integrity and availability. Note that End of Technical Support (EoTS) software versions are not evaluated for this vulnerability.

## Attack Chain

1. The attacker authenticates to the iControl REST interface with Manager-level or higher privileges.
2. The attacker crafts a malicious configuration object containing commands for execution.
3. The attacker leverages the iControl REST API to create or modify the malicious configuration object.
4. The vulnerable API endpoint processes the configuration object without proper sanitization.
5. The system executes the attacker-supplied commands within the context of the iControl REST process.
6. The attacker gains arbitrary code execution on the underlying system.
7. The attacker can then perform lateral movement, privilege escalation, or data exfiltration.
8. The ultimate impact is full system compromise, including the ability to disrupt services, steal sensitive information, or install persistent backdoors.

## Impact

Successful exploitation of CVE-2026-41225 allows a privileged attacker to achieve arbitrary command execution. This can lead to a full system compromise, potentially affecting critical network infrastructure and services. The high CVSS score (9.1) reflects the significant risk posed by this vulnerability. Organizations using affected versions of F5 iControl REST are at risk of data breaches, service disruption, and other severe security incidents.

## Recommendation

*   Apply the security updates provided by F5 Networks to remediate CVE-2026-41225.
*   Review and enforce the principle of least privilege for iControl REST access to limit the impact of potential compromises.
*   Implement network segmentation to restrict lateral movement following a successful exploit.
*   Deploy the Sigma rule "Detect iControl REST Configuration Object Manipulation" to identify suspicious activity related to configuration object creation or modification via the iControl REST API.
*   Enable detailed logging for iControl REST API calls to aid in incident investigation and detection efforts.
