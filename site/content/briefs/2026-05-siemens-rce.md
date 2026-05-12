---
title: Siemens RUGGEDCOM ROX Devices Vulnerable to Remote Code Execution via Feature Key Injection (CVE-2025-40947)
slug: 2026-05-siemens-rce
description: CVE-2025-40947 describes a vulnerability in Siemens RUGGEDCOM ROX devices that allows authenticated remote attackers to inject arbitrary commands via a maliciously crafted feature key, resulting in remote code execution with root privileges.
date: "2026-05-12T10:19:32Z"
type: threat
types:
  - threat
severities:
  - high
tags:
  - cve
  - rce
  - siemens
  - ruggedcom
  - ics
vendors:
  - Siemens
products:
  - RUGGEDCOM ROX MX5000
  - RUGGEDCOM ROX MX5000RE
  - RUGGEDCOM ROX RX1400
  - RUGGEDCOM ROX RX1500
  - RUGGEDCOM ROX RX1501
  - RUGGEDCOM ROX RX1510
  - RUGGEDCOM ROX RX1511
  - RUGGEDCOM ROX RX1512
  - RUGGEDCOM ROX RX1524
  - RUGGEDCOM ROX RX1536
  - RUGGEDCOM ROX RX5000
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
cves:
  - id: CVE-2025-40947
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2025-40947
  - CVE-2025-40947
rules:
  - title: Detect Suspicious Feature Key Uploads
    description: Detects suspicious uploads of feature keys to RUGGEDCOM devices that may contain malicious code.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect Malicious Command Execution via Feature Key Injection
    description: Detects CVE-2025-40947 exploitation — execution of commands indicative of exploitation via feature key injection on RUGGEDCOM devices.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

A remote code execution vulnerability, tracked as CVE-2025-40947, affects multiple RUGGEDCOM ROX devices. The affected devices include RUGGEDCOM ROX MX5000, MX5000RE, RX1400, RX1500, RX1501, RX1510, RX1511, RX1512, RX1524, RX1536, and RX5000, specifically all versions prior to V2.17.1. The vulnerability stems from a failure to properly sanitize user-supplied input during the feature key installation process. An authenticated attacker can exploit this flaw to inject arbitrary commands, leading to remote code execution with root privileges on the underlying operating system. This vulnerability poses a significant risk to industrial control systems relying on these devices.

## Attack Chain

1. An attacker gains authenticated access to the RUGGEDCOM ROX device's management interface.
2. The attacker crafts a malicious feature key containing embedded operating system commands.
3. The attacker uploads the crafted feature key to the device through the management interface.
4. The RUGGEDCOM ROX device attempts to install the feature key without proper input sanitization.
5. The injected commands within the feature key are executed with root privileges.
6. The attacker gains arbitrary code execution on the device's underlying operating system.
7. The attacker can then establish persistence by modifying system files.
8. The attacker can pivot to other internal assets, disrupt operations, or exfiltrate sensitive data.

## Impact

Successful exploitation of CVE-2025-40947 allows an attacker to execute arbitrary code with root privileges on vulnerable RUGGEDCOM ROX devices. This could lead to complete system compromise, denial of service, disruption of critical infrastructure, and potential lateral movement to other systems within the network. The vulnerability targets industrial control systems, potentially impacting sectors such as energy, transportation, and manufacturing.

## Recommendation

*   Upgrade all affected RUGGEDCOM ROX devices (MX5000, MX5000RE, RX1400, RX1500, RX1501, RX1510, RX1511, RX1512, RX1524, RX1536, and RX5000) to version V2.17.1 or later to patch CVE-2025-40947.
*   Monitor network traffic for suspicious activity related to feature key uploads to detect potential exploitation attempts. Deploy the Sigma rule `Detect Suspicious Feature Key Uploads` to identify such activity.
*   Review the logs for any unusual processes or commands executed on the RUGGEDCOM ROX devices that may indicate successful exploitation. Utilize the Sigma rule `Detect Malicious Command Execution via Feature Key Injection` for this purpose.
