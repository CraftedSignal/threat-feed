---
title: Microsoft HPC Pack Deserialization Vulnerability (CVE-2026-32184)
slug: 2026-04-hpc-deserialization
description: CVE-2026-32184 allows an authorized local attacker to elevate privileges on a Microsoft High Performance Compute Pack (HPC) system through deserialization of untrusted data.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - cve-2026-32184
  - privilege-escalation
  - deserialization
  - windows
vendors:
  - Microsoft
products:
  - HPC Pack
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-32184
    cvss: 7.8
    epss: 0.01928
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-32184
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-32184
rules:
  - title: Detect Suspicious HPC Process Creation
    description: Detects suspicious process creation events originating from the HPC Pack service, potentially indicating exploitation of CVE-2026-32184.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - process_creation
      - windows
  - title: Detect HPC Service launching cmd
    description: Detects cmd.exe process creation events originating from the HPC Pack service, potentially indicating exploitation of CVE-2026-32184.
    platform: sigma
    severity: medium
    tactics:
      - execution
      - privilege_escalation
    techniques:
      - T1059.001
      - T1068
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

CVE-2026-32184 is a critical vulnerability affecting Microsoft High Performance Compute Pack (HPC). An authorized attacker with local access can exploit this vulnerability to elevate their privileges on the system. The root cause lies in the insecure deserialization of untrusted data, allowing the attacker to inject malicious code during the deserialization process. The vulnerability was reported on April 14, 2026. Successful exploitation grants the attacker elevated privileges, potentially leading to full control over the HPC system. This is a significant concern for organizations utilizing Microsoft HPC Pack, as it can compromise the integrity and confidentiality of sensitive data processed on the cluster. Organizations should apply the necessary patches to mitigate this risk.

## Attack Chain

1. Attacker gains authorized local access to an HPC system running Microsoft HPC Pack.
2. The attacker crafts a malicious serialized object containing code designed for privilege escalation.
3. The attacker injects this malicious serialized object into a data stream processed by the HPC Pack.
4. The HPC Pack attempts to deserialize the untrusted data without proper validation.
5. During deserialization, the injected malicious code is executed.
6. The attacker gains elevated privileges on the local system.
7. With elevated privileges, the attacker can access sensitive data, modify system configurations, or install malicious software.

## Impact

Successful exploitation of CVE-2026-32184 allows a local attacker to escalate privileges on a Microsoft HPC Pack system. This can lead to complete compromise of the system, including unauthorized access to sensitive data, modification of critical system configurations, and potential deployment of malware. The impact is especially severe in environments where the HPC Pack processes sensitive research data or manages critical infrastructure. The number of affected organizations depends on the adoption rate of the HPC Pack, but any system left unpatched is vulnerable.

## Recommendation

*   Apply the security update provided by Microsoft for CVE-2026-32184 immediately to patch the deserialization vulnerability in Microsoft High Performance Compute Pack.
*   Monitor process creation events for unexpected processes launched by the HPC Pack service to detect potential exploitation attempts (see Sigma rule "Detect Suspicious HPC Process Creation").
*   Implement strict access control policies to limit the number of users with authorized local access to HPC Pack systems.
*   Audit the configuration of the HPC pack to detect unauthorized users.
