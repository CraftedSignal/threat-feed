---
title: CVE-2026-35428 Azure Cloud Shell Spoofing Vulnerability
slug: 2024-04-azure-cloud-shell-spoofing
description: CVE-2026-35428 is a command injection vulnerability in Azure Cloud Shell that allows an unauthorized attacker to perform spoofing over a network.
date: "2026-05-07T14:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - command-injection
  - spoofing
  - cloud
vendors:
  - Microsoft
products:
  - Azure Cloud Shell
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-35428
rules:
  - title: Detect CVE-2026-35428 Exploitation Attempt — Command Injection in Azure Cloud Shell
    description: Detects CVE-2026-35428 exploitation attempt — suspicious requests to Azure Cloud Shell with command injection payloads
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
---

CVE-2026-35428 is a command injection vulnerability affecting Azure Cloud Shell. This vulnerability stems from improper neutralization of special elements used in a command, which could enable an unauthorized attacker to perform spoofing attacks over a network. This allows an attacker to potentially masquerade as a legitimate service or user, leading to unauthorized access or information disclosure. The vulnerability was published by Microsoft on 2026-05-07 and affects the Azure Cloud Shell platform. Defenders need to implement detections and mitigations to prevent exploitation of this vulnerability and protect against potential spoofing attacks.

## Attack Chain

1. An attacker identifies a command injection point in Azure Cloud Shell.
2. The attacker crafts a malicious command string containing special elements (e.g., shell metacharacters) designed to be improperly neutralized.
3. The crafted command is injected into the vulnerable Azure Cloud Shell application through a network request.
4. Azure Cloud Shell processes the injected command without proper sanitization.
5. The injected command executes, leading to the attacker's desired outcome, such as network spoofing.
6. The attacker leverages the spoofing capability to impersonate a trusted entity on the network.
7. The attacker intercepts network traffic or gains unauthorized access to resources.
8. The attacker exfiltrates sensitive data or performs malicious actions under the guise of the spoofed identity.

## Impact

Successful exploitation of CVE-2026-35428 can allow attackers to perform network spoofing attacks within Azure Cloud Shell environments. This can lead to unauthorized access to sensitive data, disruption of services, and potential compromise of other systems on the network. The impact is significant as it allows attackers to impersonate legitimate users or services.

## Recommendation

*   Deploy the Sigma rule `Detect CVE-2026-35428 Exploitation Attempt — Command Injection in Azure Cloud Shell` to identify potential exploitation attempts in web server logs.
*   Implement input validation and sanitization measures within Azure Cloud Shell to prevent command injection attacks.
*   Monitor network traffic for suspicious activity originating from Azure Cloud Shell instances.
*   Review and update Azure Cloud Shell configurations to minimize the attack surface.
*   Enable logging for Azure Cloud Shell and related services to facilitate incident response and investigation.
