---
title: Fortinet Appliance Authentication Bypass Vulnerability (CVE-2022-40684) Exploitation
slug: 2024-01-03-fortinet-auth-bypass
description: Exploitation of CVE-2022-40684, a Fortinet appliance authentication bypass vulnerability, allows unauthorized REST API access to modify system configurations, potentially leading to complete system compromise.
date: "2024-01-03T10:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - cve-2022-40684
  - fortinet
  - authentication-bypass
  - network-appliance
  - initial-access
vendors:
  - Fortinet
products:
  - FortiOS
  - FortiProxy
  - FortiSwitchManager
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1133
    technique_name: External Remote Services
references:
  - https://www.wordfence.com/blog/2022/10/threat-advisory-cve-2022-40684-fortinet-appliance-auth-bypass/
  - https://www.horizon3.ai/fortios-fortiproxy-and-fortiswitchmanager-authentication-bypass-technical-deep-dive-cve-2022-40684/
  - https://github.com/horizon3ai/CVE-2022-40684
  - https://www.horizon3.ai/fortinet-iocs-cve-2022-40684/
  - https://attackerkb.com/topics/QWOxGIKkGx/cve-2022-40684/rapid7-analysis
  - https://github.com/rapid7/metasploit-framework/pull/17143
rules:
  - title: Fortinet Appliance Auth Bypass Attempt
    description: Detects attempts to exploit CVE-2022-40684 by monitoring requests to the /api/v2/cmdb/system/admin endpoint.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1133
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Fortinet Appliance Admin Creation via API
    description: Detects attempts to create new administrator accounts via the Fortinet API, potentially indicating CVE-2022-40684 exploitation.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1133
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

CVE-2022-40684 is an authentication bypass vulnerability affecting Fortinet appliances, specifically FortiOS, FortiProxy, and FortiSwitchManager. Successful exploitation allows a remote attacker to bypass authentication and perform unauthorized administrative actions via crafted HTTP requests. Public exploits and Metasploit modules targeting this vulnerability were quickly developed and released after the vulnerability was disclosed in late 2022. The vulnerability stems from an improper access control issue, allowing attackers to interact with the REST API without proper authentication. The primary targets are organizations using unpatched Fortinet appliances, and the impact can range from data theft and denial of service to complete network compromise.

## Attack Chain

1. The attacker identifies a vulnerable Fortinet appliance exposed to the internet.
2. The attacker crafts a malicious HTTP request to the `/api/v2/cmdb/system/admin` endpoint, bypassing authentication checks.
3. The attacker uses the `PUT` or `POST` HTTP methods to modify existing administrator accounts or create new accounts.
4. The attacker adds an SSH key to an administrator account to gain persistent remote access.
5. The attacker uses the newly created or modified administrator account to log into the Fortinet appliance's web interface or SSH.
6. The attacker reconfigures firewall rules to allow unauthorized network traffic.
7. The attacker exfiltrates sensitive data from the network through the compromised Fortinet appliance.
8. The attacker uses the compromised appliance as a pivot point to access other internal systems.

## Impact

Successful exploitation of CVE-2022-40684 can lead to complete compromise of the Fortinet appliance and the network it protects. Attackers can gain unauthorized access to sensitive data, disrupt network services, and use the compromised appliance as a foothold for further attacks within the network. This vulnerability has been widely exploited, impacting numerous organizations across various sectors. Unpatched systems are at high risk of being compromised.

## Recommendation

*   Apply the latest Fortinet patches to address CVE-2022-40684 on all FortiOS, FortiProxy, and FortiSwitchManager appliances immediately.
*   Deploy the Sigma rule `Fortinet Appliance Auth Bypass Attempt` to your SIEM to detect exploitation attempts targeting the `/api/v2/cmdb/system/admin` endpoint.
*   Enable web server logging on Fortinet appliances to ensure the Sigma rule can effectively detect malicious activity.
*   Review existing user accounts and SSH keys for any unauthorized additions or modifications.
*   Monitor network traffic for suspicious outbound connections originating from Fortinet appliances.
*   Implement network segmentation to limit the impact of a successful breach.
