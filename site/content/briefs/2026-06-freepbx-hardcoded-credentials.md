---
title: FreePBX Hardcoded Credentials Vulnerability (CVE-2026-46376)
slug: 2026-06-freepbx-hardcoded-credentials
description: A critical vulnerability, CVE-2026-46376, exists in FreePBX due to the use of hard-coded credentials in the User Control Panel (UCP) generic template setup process, allowing an unauthenticated, remote attacker to gain unauthorized access to user accounts and manipulate user settings if default template credentials are not immediately changed by the administrator after enabling UCP.
date: "2026-06-02T08:35:31Z"
type: advisory
types:
  - advisory
severities:
  - medium
cpes:
  - cpe:2.3:a:sangoma:freepbx:*:*:*:*:*:*:*:*
tags:
  - cve
  - voip
  - freepbx
  - credential-access
vendors:
  - FreePBX project
products:
  - FreePBX (>= 15.0.42, < 16.0.45, >= 17.0.1, < 17.0.7)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-46376
    cvss: 9.8
    epss: 0.00067
references:
  - https://ccb.belgium.be/advisories/warning-critical-vulnerability-freepbx-allows-unauthenticated-attacker-gain-access
  - CVE-2026-46376
rules:
  - title: Detect CVE-2026-46376 Exploitation Attempt - HTTP Access to UCP Login Page
    description: Detects CVE-2026-46376 exploitation attempt - monitors HTTP requests to the FreePBX User Control Panel (UCP) login page, indicating a potential attempt to exploit the hardcoded credential vulnerability.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect CVE-2026-46376 Post-Exploitation - UCP Session Creation with Common User Agent
    description: Detects CVE-2026-46376 post exploitation - monitors for UCP session creation from IPs not in firewall, using very common user agents
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 2
---

A critical vulnerability, CVE-2026-46376, exists in FreePBX versions 15.0.42 to 16.0.45 and 17.0.1 to 17.0.7. This vulnerability stems from the use of hard-coded credentials within the User Control Panel (UCP) generic template setup. The UCP generic template setup process is optional and designed to simplify common UCP deployments. However, if administrators do not immediately change these default credentials, unauthenticated attackers can gain access to the UCP. Successful exploitation grants attackers unauthorized access to user accounts, exposure of sensitive user data, and manipulation of user settings and configurations. The FreePBX project released an advisory for this vulnerability, urging users to apply patches and mitigations immediately to prevent potential exploitation.

## Attack Chain

1. An attacker identifies a FreePBX instance with the UCP enabled and the default UCP generic template setup used.
2. The attacker attempts to access the UCP login page, which is typically exposed over the network.
3. The attacker uses the hard-coded default credentials to authenticate to the UCP.
4. Upon successful authentication, the attacker gains access to user accounts.
5. The attacker then leverages the unauthorized access to view sensitive user data, such as call logs, voicemails, and contact lists.
6. The attacker manipulates user settings and configurations within the UCP.
7. Depending on the scope of the account's permissions, the attacker could modify call routing rules, forwarding numbers, or even disable accounts.
8. The attacker gains control over the VoIP server's functionality, potentially leading to call interception, eavesdropping, or denial of service.

## Impact

Successful exploitation of CVE-2026-46376 can lead to unauthorized access to user accounts, exposing sensitive user data like call logs and voicemails. Attackers can manipulate user settings and configurations, potentially disrupting VoIP services and gaining control over the communication infrastructure. Given the widespread use of FreePBX in various sectors, including small businesses and large enterprises, the impact could range from data breaches and financial losses to significant disruptions in communication services. The vulnerability has a CVSS score of 9.3, highlighting the severity of the risk.

## Recommendation

*   Immediately update the userman module to the latest version, which randomizes the password, as recommended by FreePBX.
*   Ensure only authorized users have access to the FreePBX Administrator Control Panel (ACP) by using FreePBX User Management, SysAdmin VPN, MFA, or SAML modules, as mentioned in the advisory.
*   Implement access control measures, such as using the FreePBX Firewall module, to deny access from hostile networks to the ACP and the UCP, as stated in the FreePBX advisory.
*   Monitor and detect suspicious activity related to unauthorized access attempts on the UCP. Organizations should enhance their monitoring capabilities as recommended by the CCB.
