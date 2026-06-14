---
title: Multiple Vulnerabilities in Microsoft Edge Allow Security Policy Bypass
slug: 2026-06-microsoft-edge-vulnerabilities
description: Multiple vulnerabilities, including CVE-2026-10883, CVE-2026-10892, and others, have been discovered in Microsoft Edge versions prior to 149.0.4022.53, enabling an attacker to bypass security policies and potentially cause other unspecified security issues within the browser environment.
date: "2026-06-14T09:21:19Z"
type: advisory
types:
  - advisory
severities:
  - medium
cpes:
  - cpe:2.3:a:google:chrome:*:*:*:*:*:*:*:*
tags:
  - browser-vulnerability
  - security-policy-bypass
  - client-side-exploit
  - microsoft-edge
vendors:
  - Microsoft
products:
  - Microsoft Edge (versions prior to 149.0.4022.53)
affected_os:
  - Windows
  - macOS
  - Linux
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
cves:
  - id: CVE-2026-10953
    cvss: 8.3
    epss: 0.00118
  - id: CVE-2026-10959
    cvss: 8.8
    epss: 0.00086
  - id: CVE-2026-11007
    cvss: 6.5
    epss: 0.00064
  - id: CVE-2026-11034
    cvss: 6.1
    epss: 0.00052
  - id: CVE-2026-11127
    cvss: 6.5
    epss: 0.00021
references:
  - https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0726/
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-10883
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-10892
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-10923
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-10929
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-10934
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-10953
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-10959
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-10967
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-10984
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-11007
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-11010
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-11012
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-11019
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-11029
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-11034
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-11035
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-11045
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-11064
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-11065
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-11072
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-11077
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-11080
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-11082
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-11097
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-11108
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-11119
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-11127
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-11131
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-11145
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-11148
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-11163
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-11167
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-11172
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-11175
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-11178
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-11188
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-11215
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-11226
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-11247
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-11263
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-11270
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-11278
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-11287
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-11290
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-11291
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-11295
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-11297
  - https://www.cve.org/CVERecord?id=CVE-2026-10883
iocs:
  - type: url
    value: https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-10883
  - type: url
    value: https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-10892
  - type: url
    value: https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-10923
  - type: url
    value: https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-10929
  - type: url
    value: https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-10934
  - type: url
    value: https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-10953
  - type: url
    value: https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-10959
  - type: url
    value: https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-10967
  - type: url
    value: https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-10984
  - type: url
    value: https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-11007
  - type: url
    value: https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-11010
  - type: url
    value: https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-11012
  - type: url
    value: https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-11019
  - type: url
    value: https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-11029
  - type: url
    value: https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-11034
  - type: url
    value: https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-11035
  - type: url
    value: https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-11045
  - type: url
    value: https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-11064
  - type: url
    value: https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-11065
  - type: url
    value: https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-11072
  - type: url
    value: https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-11077
  - type: url
    value: https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-11080
  - type: url
    value: https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-11082
  - type: url
    value: https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-11097
  - type: url
    value: https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-11108
  - type: url
    value: https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-11119
  - type: url
    value: https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-11127
  - type: url
    value: https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-11131
  - type: url
    value: https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-11145
  - type: url
    value: https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-11148
  - type: url
    value: https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-11163
  - type: url
    value: https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-11167
  - type: url
    value: https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-11172
  - type: url
    value: https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-11175
  - type: url
    value: https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-11178
  - type: url
    value: https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-11188
  - type: url
    value: https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-11215
  - type: url
    value: https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-11226
  - type: url
    value: https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-11247
  - type: url
    value: https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-11263
  - type: url
    value: https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-11270
  - type: url
    value: https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-11278
  - type: url
    value: https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-11287
  - type: url
    value: https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-11290
  - type: url
    value: https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-11291
  - type: url
    value: https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-11295
  - type: url
    value: https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-11297
  - type: url
    value: https://www.cve.org/CVERecord?id=CVE-2026-10883
ioc_counts:
  url: 48
rules:
  - title: Detect Suspicious Child Process from Microsoft Edge
    description: Detects potentially malicious child processes (like cmd.exe, powershell.exe) spawned directly by Microsoft Edge (msedge.exe). This could indicate successful browser exploitation leading to code execution.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
      - execution
    techniques:
      - T1059
      - T1204.001
    data_sources:
      - process_creation
      - windows
  - title: Detect Outbound Network Connection to Uncommon Ports from Microsoft Edge
    description: Detects suspicious outbound network connections made by Microsoft Edge (msedge.exe) to non-standard, high-numbered ports. This could indicate Command and Control (C2) communication or data exfiltration following browser exploitation (CVE-2026-10883, etc.).
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
      - exfiltration
    techniques:
      - T1041
      - T1071.001
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

On June 10, 2026, the French National Agency for the Security of Information Systems (ANSSI) released an advisory (CERTFR-2026-AVI-0726) detailing numerous security vulnerabilities in Microsoft Edge. These flaws, collectively impacting versions prior to 149.0.4022.53, include various issues that could lead to a security policy bypass and other unspecified security problems as indicated by Microsoft's security bulletins. While the specific exploitation vectors and exact impacts of each vulnerability (e.g., CVE-2026-10883, CVE-2026-10892, CVE-2026-10923) are not fully detailed in the ANSSI advisory, the potential for an attacker to circumvent browser security mechanisms poses a risk to user data and system integrity. Defenders should prioritize patching to mitigate these client-side risks.

## Attack Chain

1.  **Initial Access (User Interaction)**: An attacker entices a user to visit a malicious website or click a crafted link, possibly via phishing or drive-by download.
2.  **Client-Side Exploitation (CVE-2026-XXXX)**: The vulnerable Microsoft Edge browser processes the malicious web content, triggering one or more of the identified vulnerabilities (e.g., memory corruption, logic error).
3.  **Security Policy Bypass**: Successful exploitation bypasses browser security policies (e.g., Same-Origin Policy, Content Security Policy), allowing the attacker to access restricted resources or execute unauthorized actions within the browser's context.
4.  **Unspecified Security Impact**: The bypass could lead to further compromise such as information disclosure (e.g., reading cookies, local storage), elevation of privileges within the browser, or cross-site scripting (XSS) in highly sensitive contexts.
5.  **Browser Sandbox Escape (Potential)**: Depending on the specific vulnerability and chaining, the attacker *may* attempt to escape the browser's sandbox to execute arbitrary code on the underlying operating system. (Note: This is a common objective for browser exploits, but not explicitly confirmed for these specific CVEs by the source).
6.  **Further Compromise**: If a sandbox escape is successful, the attacker could install malware, establish persistence, exfiltrate data, or pivot to other systems on the network.

## Impact

The primary impact of these vulnerabilities is the ability for an attacker to bypass security policies within the Microsoft Edge browser. While the full extent of the "unspecified security problem" is not detailed, a successful security policy bypass could allow an attacker to access sensitive user data, perform unauthorized actions on behalf of the user, or potentially set the stage for further system compromise by escaping the browser's sandbox. Organizations relying on Microsoft Edge for web browsing across their environments, especially those handling sensitive information, are at risk. No specific victim counts or targeted sectors were mentioned in the advisory, but all users of unpatched Microsoft Edge are vulnerable.

## Recommendation

*   Immediately update all Microsoft Edge installations to version 149.0.4022.53 or later, as recommended by the Microsoft security bulletins referenced.
*   Implement browser security policies (e.g., Microsoft Edge Group Policies) to restrict potentially dangerous browser functionalities and reduce attack surface against CVE-2026-10883, CVE-2026-10892, etc.
*   Deploy the Sigma rules in this brief to your SIEM to detect suspicious activities originating from `msedge.exe` processes.
*   Enable comprehensive logging for process creation and network connections on all endpoints to ensure telemetry coverage for the Sigma rules.
