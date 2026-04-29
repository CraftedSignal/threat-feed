---
title: ConnectWise ScreenConnect Path Traversal Vulnerability (CVE-2024-1708)
slug: 2024-04-29-screenconnect-path-traversal
description: CVE-2024-1708 is a path traversal vulnerability in ConnectWise ScreenConnect that could allow an attacker to execute remote code or directly impact confidential data and critical systems.
date: "2024-04-29T12:00:00Z"
type: coverage
types:
  - coverage
severities:
  - critical
tags:
  - path-traversal
  - remote-code-execution
  - cve-2024-1708
  - connectwise
vendors:
  - ConnectWise
products:
  - ScreenConnect
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2024-1708
    cvss: 8.4
    epss: 0.8162
references:
  - https://www.cve.org/CVERecord?id=CVE-2024-1708
  - https://www.connectwise.com/company/trust/security-bulletins/connectwise-screenconnect-23.9.8
  - https://nvd.nist.gov/vuln/detail/CVE-2024-1708
rules:
  - title: Detect Suspicious ScreenConnect Path Traversal Attempts
    description: Detects potential path traversal attempts targeting ConnectWise ScreenConnect servers by identifying suspicious patterns in HTTP requests.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Suspicious ScreenConnect File Uploads via Path Traversal
    description: Detects potential file uploads via path traversal targeting ConnectWise ScreenConnect by identifying suspicious file extensions in HTTP requests combined with path traversal indicators.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

CVE-2024-1708 is a critical path traversal vulnerability affecting ConnectWise ScreenConnect. This flaw could allow an unauthenticated attacker to execute remote code or directly access confidential data and critical systems. ConnectWise released security bulletin 23.9.8 to address this vulnerability. Given the potential for remote code execution and data compromise, this vulnerability poses a significant risk to organizations using ConnectWise ScreenConnect, potentially allowing full system takeover. CISA added this to their KEV catalog and recommends applying mitigations per vendor instructions, following BOD 22-01 guidance for cloud services, or discontinuing use of the product if mitigations are unavailable.

## Attack Chain

1.  An unauthenticated attacker identifies a ConnectWise ScreenConnect server exposed to the internet.
2.  The attacker crafts a malicious HTTP request containing a path traversal payload targeting a vulnerable endpoint within ScreenConnect. This payload is designed to bypass authentication checks.
3.  The ScreenConnect server processes the malicious request, and the path traversal vulnerability allows the attacker to access files outside of the intended webroot directory.
4.  The attacker leverages the file access to read sensitive configuration files, potentially containing credentials or other sensitive information.
5.  Alternatively, the attacker uploads a malicious executable (e.g., a web shell) to a writeable directory accessible via path traversal.
6.  The attacker executes the uploaded web shell, gaining remote code execution on the ScreenConnect server.
7.  The attacker uses the compromised ScreenConnect server as a pivot point to move laterally within the internal network, escalating privileges and compromising additional systems.
8.  The attacker exfiltrates sensitive data or deploys ransomware, disrupting business operations and causing significant financial damage.

## Impact

Successful exploitation of CVE-2024-1708 can lead to complete compromise of ConnectWise ScreenConnect servers and potentially the entire network. Attackers could exfiltrate sensitive data, deploy ransomware, or use the compromised systems for lateral movement. Given the widespread use of ScreenConnect in MSP environments, a successful attack could impact numerous downstream clients, causing widespread disruption.

## Recommendation

*   Apply the mitigations provided by ConnectWise in security bulletin 23.9.8 to patch CVE-2024-1708.
*   Deploy the Sigma rule "Detect Suspicious ScreenConnect Path Traversal Attempts" to identify potential exploitation attempts in web server logs.
*   Monitor network traffic for suspicious outbound connections originating from ScreenConnect servers, as this could indicate post-exploitation activity.
*   Review and harden the configuration of ConnectWise ScreenConnect servers, following security best practices to minimize the attack surface.
