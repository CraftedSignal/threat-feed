---
title: ClearFake, ACR Stealer, and GraphRunner Emerge as Significant Threats
slug: 2026-05-clearfake-acrstealer-graphrunner
description: The Red Canary Intelligence Insights report for May 2026 highlights the rise of ClearFake, ACR Stealer, and GraphRunner, with ClearFake using JavaScript injection to deliver malware like ACR Stealer, and GraphRunner being abused for reconnaissance and data exfiltration via the Microsoft Graph API.
date: "2026-05-26T14:20:18Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - credential-theft
  - malware
  - oauth
vendors:
  - Microsoft
  - ConnectWise
  - GitLab
  - npm
products:
  - Entra ID
  - Outlook
  - SharePoint
  - OneDrive
  - Teams
  - ConnectWise ScreenConnect
  - axios
affected_os:
  - macos
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1204
    technique_name: User Execution
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1218.011
    technique_name: Signed Binary Proxy Execution
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1105
    technique_name: Ingress Tool Transfer
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
references:
  - https://redcanary.com/blog/threat-intelligence/intelligence-insights-may-2026/
  - https://www.trendmicro.com/en_us/research/26/e/installfix-and-claude-code.html
iocs:
  - type: domain
    value: dialectosphere.in[.]net
  - type: domain
    value: compactedtightness[.]cfd
ioc_counts:
  domain: 2
rules:
  - title: Detect Rundll32.exe Without Command Line Arguments Making Network Connections
    description: Detects rundll32.exe executing without any command-line parameters and establishing a network connection, which is a common technique used by ACR Stealer.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1218.011
    data_sources:
      - network_connection
      - windows
  - title: Detect Outbound Connections from Rundll32.exe with Suspicious Arguments
    description: Detects outbound connections initiated by rundll32.exe when the command line argument specifies a remote network share, which can indicate malicious DLL loading.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
      - execution
    techniques:
      - T1218.011
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

The Red Canary Intelligence Insights report for May 2026 highlights the increasing prevalence of ClearFake, ACR Stealer, and GraphRunner. ClearFake, an activity cluster employing JavaScript injection on compromised websites, has risen to the top of the threat list, leveraging drive-by download techniques and fake CAPTCHA lures to trick users into executing malicious code via copy-paste. ACR Stealer, a malware-as-a-service (MaaS) information stealer written in C++, makes its debut due to its distribution via recent ClearFake campaigns. GraphRunner, a post-exploitation toolkit leveraging the Microsoft Graph API for reconnaissance, persistence, and data exfiltration from Entra ID accounts, is also gaining traction among malicious actors. The report emphasizes the increasing abuse of OAuth device code and offers mitigation strategies.

## Attack Chain

1.  A user browses to a legitimate website compromised by ClearFake.
2.  Injected JavaScript displays a fake CAPTCHA or other lure.
3.  The user is tricked into copying and pasting malicious code into their terminal (paste and run).
4.  The copied code downloads and executes a Go-based reflective loader.
5.  The loader sideloads a malicious DLL via `rundll32.exe`.
6.  The ACR Stealer DLL loads and executes in memory.
7.  ACR Stealer gathers sensitive information, including credentials and financial data.
8.  ACR Stealer establishes outbound command and control (C2) communications.

## Impact

The ClearFake campaign, combined with the capabilities of ACR Stealer and the misuse of GraphRunner, poses a significant threat to organizations. Successful attacks can lead to the compromise of user accounts, theft of sensitive data (including credentials and financial information), and unauthorized access to cloud resources. The rise in OAuth device code abuse further exacerbates the problem, potentially bypassing MFA and conditional access policies. Specifically, the compromise of the `axios` npm package on March 30, 2026, resulted in the distribution of two malicious versions to a large number of users via automated updates, highlighting the potential impact of supply chain compromises.

## Recommendation

*   Implement conditional access policies to block device code flows to prevent OAuth device code phishing, as described in the overview.
*   Monitor process execution for unusual uses of `rundll32.exe`, especially those lacking command-line parameters and initiating network connections; deploy the provided Sigma rule detecting this behavior.
*   Block the C2 domain `compactedtightness[.]cfd` and the malicious DLL download domain `dialectosphere.in[.]net` at the DNS resolver based on the IOCs in this brief.
*   Harden device joining by limiting permissions to groups that require Entra device joining, as recommended in the overview.
