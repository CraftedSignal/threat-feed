---
title: NVIDIA BioNeMo Deserialization Vulnerability (CVE-2026-24164)
slug: 2026-04-nvidia-bionemo-deserialization
description: NVIDIA BioNeMo is vulnerable to deserialization of untrusted data (CVE-2026-24164), potentially leading to code execution, denial of service, information disclosure, and data tampering.
date: "2026-03-31T17:17:41Z"
severities:
  - high
type: advisory
types:
  - advisory
tags:
  - cve
  - deserialization
  - nvidia
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-24164
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-24164
  - https://nvidia.custhelp.com/app/answers/detail/a_id/5808
  - https://www.cve.org/CVERecord?id=CVE-2026-24164
iocs:
  - type: email
    value: '[email&#160;protected]'
ioc_counts:
  email: 1
rules:
  - title: Detect Suspicious BioNeMo Deserialization Attempts
    description: Detects suspicious POST requests potentially exploiting deserialization vulnerabilities in NVIDIA BioNeMo.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect BioNeMo Child Process
    description: Detects suspicious child processes spawned by the BioNeMo application.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

A deserialization of untrusted data vulnerability has been identified in NVIDIA BioNeMo (CVE-2026-24164). This vulnerability allows a malicious actor to potentially inject arbitrary code, trigger a denial-of-service condition, expose sensitive information, or tamper with data within the BioNeMo environment. The vulnerability stems from BioNeMo's processing of serialized data, which, if crafted maliciously, can lead to unintended code execution or system compromise. The reported CVSS v3.1 score is 8.8, indicating a high severity. The vendor, NVIDIA, has acknowledged the vulnerability, but specific exploitation details and affected versions are not available in the provided source.

## Attack Chain

1. The attacker identifies an endpoint or functionality within NVIDIA BioNeMo that accepts serialized data as input.
2. The attacker crafts a malicious serialized object designed to exploit the deserialization vulnerability. This object could contain instructions to execute arbitrary code, read sensitive files, or modify application data.
3. The attacker sends the malicious serialized object to the vulnerable BioNeMo endpoint. This could be done via a web request, API call, or other data submission mechanism.
4. BioNeMo attempts to deserialize the received data.
5. During the deserialization process, the malicious object triggers the execution of attacker-controlled code due to the vulnerability.
6. The attacker gains control of the BioNeMo application process or underlying server.
7. The attacker performs malicious actions such as exfiltrating sensitive data, installing malware, or disrupting services.
8. The attacker achieves their objective, which could include data breach, system compromise, or denial of service.

## Impact

Successful exploitation of CVE-2026-24164 can have severe consequences. It could lead to the execution of arbitrary code on the BioNeMo server, allowing attackers to gain unauthorized access and control. Sensitive data processed by BioNeMo could be exposed, leading to a data breach. The vulnerability could also be exploited to cause a denial of service, disrupting BioNeMo's functionality. Data tampering is also a potential consequence, leading to data integrity issues and potentially impacting downstream processes that rely on BioNeMo. The number of potential victims and targeted sectors are unknown.

## Recommendation

*   Monitor web server logs for suspicious POST requests containing serialized data being sent to NVIDIA BioNeMo endpoints, and deploy the Sigma rule `Detect Suspicious BioNeMo Deserialization Attempts` to detect potential exploitation attempts.
*   Inspect network traffic for unusual data patterns related to serialization protocols and correlate with BioNeMo activity, to aid in identifying potential exploitation attempts targeting CVE-2026-24164.
*   Monitor process creation events on servers hosting NVIDIA BioNeMo for unexpected processes being spawned by the BioNeMo application, using the `Detect BioNeMo Child Process` Sigma rule to catch unexpected child processes.
*   Apply any available patches or updates released by NVIDIA to address CVE-2026-24164 as soon as they become available. Refer to NVIDIA's security advisory for remediation guidance.
