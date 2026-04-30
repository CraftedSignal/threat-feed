---
title: AWS Research and Engineering Studio (RES) RCE via FileBrowser API Vulnerability
slug: 2026-04-aws-res-rce
description: CVE-2026-5709 is a critical vulnerability in AWS Research and Engineering Studio (RES) versions 2024.10 through 2025.12.01, allowing remote authenticated attackers to execute arbitrary commands on the cluster-manager EC2 instance through the FileBrowser API.
date: "2026-04-06T22:16:25Z"
severities:
  - critical
type: advisory
types:
  - advisory
tags:
  - cve-2026-5709
  - rce
  - aws
  - res
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
cves:
  - id: CVE-2026-5709
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-5709
  - https://aws.amazon.com/security/security-bulletins/2026-014-aws/
  - https://github.com/aws/res/issues/150
  - https://github.com/aws/res/releases/tag/2026.03
rules:
  - title: Detect Suspicious FileBrowser API Requests
    description: Detects potentially malicious requests to the FileBrowser API in AWS Research and Engineering Studio (RES) by looking for common command injection attempts.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1203
    data_sources:
      - webserver
      - linux
  - title: Detect Potential File Uploads of Malicious Web Shells
    description: Detects potential attempts to upload web shells (PHP or HTML) through the FileBrowser API, which could be a sign of command execution exploitation.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1505.003
    data_sources:
      - webserver
      - linux
rules_count: 2
---

CVE-2026-5709 affects AWS Research and Engineering Studio (RES), a cloud-based platform for research and engineering workflows. The vulnerability resides in the FileBrowser API and is present in versions 2024.10 through 2025.12.01. An authenticated attacker can exploit this vulnerability by sending crafted input to the FileBrowser functionality, leading to arbitrary command execution on the underlying cluster-manager EC2 instance. This could allow attackers to gain complete control over the RES environment, potentially compromising sensitive data and disrupting critical research activities. AWS recommends that users upgrade to RES version 2026.03 or apply a mitigation patch.

## Attack Chain

1. An attacker gains valid credentials for an AWS Research and Engineering Studio (RES) account.
2. The attacker authenticates to the RES environment.
3. The attacker crafts malicious input designed to exploit the unsanitized input vulnerability in the FileBrowser API.
4. The attacker sends the crafted input to the FileBrowser API endpoint.
5. The FileBrowser API processes the input without proper sanitization.
6. The unsanitized input is executed as an operating system command on the cluster-manager EC2 instance.
7. The attacker achieves arbitrary command execution, potentially installing malware, exfiltrating data, or creating new administrative accounts.

## Impact

Successful exploitation of CVE-2026-5709 grants the attacker the ability to execute arbitrary commands on the cluster-manager EC2 instance within the AWS Research and Engineering Studio (RES) environment. This can lead to complete compromise of the RES environment, data theft, denial of service, and potential lateral movement to other AWS resources. Due to the nature of research environments, this vulnerability could expose highly sensitive data, intellectual property, and research findings. The impact is significant due to the potential for widespread damage and disruption of critical research activities.

## Recommendation

*   Immediately upgrade AWS Research and Engineering Studio (RES) to version 2026.03 or apply the recommended mitigation patch provided by AWS to remediate CVE-2026-5709.
*   Implement the Sigma rule "Detect Suspicious FileBrowser API Requests" to identify potential exploitation attempts targeting the FileBrowser API.
*   Monitor web server logs for suspicious activity related to the FileBrowser API endpoint, looking for unusual characters or command injection attempts.
