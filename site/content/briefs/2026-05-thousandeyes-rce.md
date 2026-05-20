---
title: Cisco ThousandEyes Virtual Appliance Authenticated Remote Code Execution Vulnerability
slug: 2026-05-thousandeyes-rce
description: CVE-2026-20199 - A vulnerability in the SSL certificate handling of Cisco ThousandEyes Virtual Appliance could allow an authenticated, remote attacker to execute commands on the underlying operating system as the root user.
date: "2026-05-20T16:02:43Z"
type: threat
types:
  - threat
severities:
  - medium
tags:
  - cve-2026-20199
  - rce
  - cisco
  - thousandeyes
  - ssl
vendors:
  - Cisco
products:
  - ThousandEyes Virtual Appliance
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1219
    technique_name: Remote Services
references:
  - https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-tevacert-rce-RMJVEym5
rules:
  - title: Detects CVE-2026-20199 Exploitation Attempt - Suspicious SSL Certificate Upload
    description: Detects CVE-2026-20199 exploitation — Attempts to upload a crafted SSL certificate to the ThousandEyes Virtual Appliance web interface.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1219
    data_sources:
      - webserver
  - title: Detects CVE-2026-20199 Post Exploitation - Root Shell Activity
    description: Detects CVE-2026-20199 exploitation — Attempts to execute commands as root on the ThousandEyes Virtual Appliance.
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

A vulnerability exists within the SSL certificate handling mechanism of the Cisco ThousandEyes Virtual Appliance. This flaw enables an authenticated, remote attacker to execute arbitrary commands on the underlying operating system with root privileges. The vulnerability, identified as CVE-2026-20199, stems from insufficient validation of user-supplied input during the SSL certificate upload process. Successful exploitation requires valid administrative credentials, emphasizing the importance of robust access control measures. Defenders should apply the available software updates released by Cisco to remediate this vulnerability and prevent potential compromise.

## Attack Chain

1. Attacker obtains valid administrative credentials for the Cisco ThousandEyes Virtual Appliance.
2. Attacker logs into the ThousandEyes Virtual Appliance web interface using the compromised credentials.
3. Attacker navigates to the SSL certificate management section within the web interface.
4. Attacker uploads a crafted SSL certificate containing malicious code designed for command execution.
5. The ThousandEyes Virtual Appliance processes the uploaded certificate without proper validation.
6. The malicious code embedded within the crafted certificate is executed with root privileges.
7. Attacker establishes a reverse shell or gains persistent access to the underlying operating system.

## Impact

Successful exploitation of CVE-2026-20199 grants the attacker complete control over the Cisco ThousandEyes Virtual Appliance, enabling them to execute arbitrary commands with root privileges. This can lead to complete system compromise, data exfiltration, service disruption, and potential lateral movement within the network. The vulnerability poses a significant risk to organizations relying on ThousandEyes for network monitoring and performance analysis.

## Recommendation

*   Apply the software updates released by Cisco to address CVE-2026-20199 on all affected ThousandEyes Virtual Appliances.
*   Implement strong password policies and multi-factor authentication to protect administrative credentials required to exploit this vulnerability.
*   Deploy the Sigma rules provided below to detect attempts to upload crafted SSL certificates to the ThousandEyes Virtual Appliance.
*   Monitor web server logs for suspicious activity related to SSL certificate management, specifically uploads from unusual IP addresses or user agents.
