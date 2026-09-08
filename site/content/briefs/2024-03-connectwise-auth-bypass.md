---
title: ConnectWise ScreenConnect Authentication Bypass Vulnerability Exploitation
slug: 2024-03-connectwise-auth-bypass
description: Exploitation of CVE-2024-1709 in ConnectWise ScreenConnect allows attackers to bypass authentication via the SetupWizard.aspx endpoint, potentially leading to unauthorized administrative access and remote code execution.
date: "2024-03-28T10:09:22Z"
lastmod: "2026-09-08T13:38:06Z"
type: threat
types:
  - threat
severities:
  - critical
cpes:
  - cpe:2.3:a:connectwise:screenconnect:*:*:*:*:*:*:*:*
tags:
  - connectwise
  - screenconnect
  - authentication bypass
  - cve-2024-1709
vendors:
  - Elastic
products:
  - Elastic Defend
  - ScreenConnect (< 23.9.8)
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2024-1709
    cvss: 10
    epss: 0.9998
  - id: CVE-2024-1708
    cvss: 8.4
    epss: 0.9549
references:
  - https://www.huntress.com/blog/a-catastrophe-for-control-understanding-the-screenconnect-authentication-bypass
  - https://www.huntress.com/blog/detection-guidance-for-connectwise-cwe-288-2
  - https://www.connectwise.com/company/trust/security-bulletins/connectwise-screenconnect-23.9.8
  - https://github.com/elastic/detection-rules/blob/main/rules/windows/initial_access_webshell_screenconnect_server.toml
  - https://www.huntress.com/blog/rogue-screenconnect-installations
rules:
  - title: ConnectWise ScreenConnect Authentication Bypass
    description: Detects attempts to exploit the ConnectWise ScreenConnect CVE-2024-1709 vulnerability by identifying POST requests to the SetupWizard.aspx page.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
      - T1190
    data_sources:
      - webserver
      - windows
  - title: ConnectWise ScreenConnect Authentication Bypass - Alternate Path
    description: Detects attempts to exploit the ConnectWise ScreenConnect CVE-2024-1709 vulnerability by identifying POST requests to the SetupWizard/ directory.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - windows
rules_count: 2
updates:
  - at: "2026-05-12T17:45:21Z"
    level: L2
    summary: added CVE-2024-1708 +1; OS windows
    sources:
      - elastic
  - at: "2026-09-08T13:38:06Z"
    level: L2
    summary: screenconnect version < 23.9.8
    sources:
      - huntress
    source_urls:
      - https://www.huntress.com/blog/rogue-screenconnect-installations
---

The ConnectWise ScreenConnect CVE-2024-1709 vulnerability allows attackers to bypass authentication and gain unauthorized administrative access. This vulnerability is actively being exploited in the wild. The primary attack vector involves sending malicious HTTP POST requests to the `SetupWizard.aspx` page, circumventing normal authentication procedures. Successful exploitation can lead to the creation of administrative users, granting the attacker full control over the affected ScreenConnect instance. ConnectWise has released version 23.9.8 to address this vulnerability. This vulnerability has been exploited in conjunction with CVE-2024-1708. Defenders should prioritize detection and patching of vulnerable ScreenConnect instances to prevent potential compromise.

## Attack Chain

1.  Attacker identifies a vulnerable ConnectWise ScreenConnect instance.
2.  The attacker sends a crafted HTTP POST request to `/SetupWizard.aspx/` or `*/SetupWizard.aspx/*`.
3.  The vulnerable ScreenConnect instance improperly handles the request, bypassing authentication checks.
4.  The attacker gains unauthorized access to administrative functions without valid credentials.
5.  The attacker creates a new administrative user account.
6.  The attacker logs in using the newly created administrative account.
7.  The attacker leverages administrative privileges to execute arbitrary code on the server.
8.  The attacker establishes persistence and expands their access to the network.

## Impact

Successful exploitation of CVE-2024-1709 allows attackers to gain complete control over the ConnectWise ScreenConnect server. This can lead to data breaches, ransomware deployment, and further compromise of connected systems. The number of affected organizations is currently unknown. This impacts MSPs (Managed Service Providers) and their clients since ScreenConnect is used for remote support.

## Recommendation

*   Deploy the Sigma rule `ConnectWise ScreenConnect Authentication Bypass` to detect unauthorized access attempts to `SetupWizard.aspx` in web server logs.
*   Upgrade ConnectWise ScreenConnect instances to version 23.9.8 or later to patch CVE-2024-1709 (reference: ConnectWise security bulletin).
*   Review web server access logs for suspicious POST requests to `SetupWizard.aspx` (reference: references section).
*   Enable logging for web servers (IIS, Apache) or proxy servers and ensure the logs are ingested into your SIEM.
