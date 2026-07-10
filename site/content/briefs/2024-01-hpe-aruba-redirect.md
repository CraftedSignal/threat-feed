---
title: HPE Aruba Networking Private 5G Core On-Prem Open Redirect Vulnerability (CVE-2026-23818)
slug: 2024-01-hpe-aruba-redirect
description: CVE-2026-23818 is an open redirect vulnerability in the HPE Aruba Networking Private 5G Core On-Prem GUI that enables attackers to redirect authenticated users to attacker-controlled login pages to steal credentials.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - aruba
  - open-redirect
  - credential-theft
  - cve-2026-23818
  - network
vendors:
  - HPE Aruba
products:
  - HPE Aruba Networking Private 5G Core On-Prem
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
cves:
  - id: CVE-2026-23818
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-23818
rules:
  - title: Detect Aruba Open Redirect Attempt
    description: Detects attempts to exploit the Aruba open redirect vulnerability (CVE-2026-23818) by monitoring web server logs for suspicious URL parameters.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
      - T1566.001
    data_sources:
      - webserver
      - linux
  - title: Detect Aruba Open Redirect Destination
    description: Detects connections to domains used as redirect destinations in Aruba open redirect attempts.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
      - initial_access
    techniques:
      - T1071.001
      - T1566.001
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

A critical vulnerability, CVE-2026-23818, has been discovered in the graphical user interface (GUI) of HPE Aruba Networking Private 5G Core On-Prem. This open redirect vulnerability resides within the login flow and allows an attacker to craft a malicious URL that, when accessed by an authenticated user, redirects them to a spoofed login page. The attacker hosts this spoofed page to mimic the legitimate Aruba login, prompting the user to enter their credentials. This attack is particularly dangerous because the user, after submitting their credentials on the fake page, may be redirected to the real login page, making the attack less obvious. This vulnerability impacts the security of the HPE Aruba Networking Private 5G Core On-Prem systems by potentially allowing unauthorized access through stolen credentials.

## Attack Chain

1.  Attacker crafts a malicious URL containing a redirect to an attacker-controlled server. This URL exploits the open redirect vulnerability (CVE-2026-23818) in the HPE Aruba Networking Private 5G Core On-Prem login flow.
2.  The attacker distributes the crafted URL to potential victims, possibly through phishing emails or other social engineering methods.
3.  The victim, an authenticated user of the HPE Aruba Networking Private 5G Core On-Prem system, clicks on the malicious URL.
4.  The Aruba Networking Private 5G Core On-Prem GUI processes the crafted URL and redirects the victim's browser to the attacker-controlled server.
5.  The attacker-controlled server hosts a spoofed login page that mimics the legitimate Aruba Networking Private 5G Core On-Prem login interface.
6.  The victim, believing the spoofed page is genuine, enters their username and password.
7.  The attacker captures the victim's credentials from the spoofed login page.
8.  The attacker redirects the victim to the legitimate Aruba Networking Private 5G Core On-Prem login page, potentially masking the malicious activity. The attacker now possesses valid credentials for the Aruba system.

## Impact

Successful exploitation of CVE-2026-23818 can lead to the compromise of user accounts on HPE Aruba Networking Private 5G Core On-Prem systems. This allows an attacker to gain unauthorized access to the system's administrative functions and sensitive data. The impact could range from data breaches and service disruption to complete system takeover, depending on the privileges of the compromised account. The vulnerability poses a significant risk to organizations relying on HPE Aruba Networking Private 5G Core On-Prem for network management and security.

## Recommendation

*   Apply the patch or upgrade provided by HPE to remediate CVE-2026-23818 on all affected Aruba Networking Private 5G Core On-Prem systems.
*   Implement web server access logging and deploy the provided Sigma rule `Detect Aruba Open Redirect Attempt` to identify attempts to exploit the open redirect vulnerability in real-time.
*   Monitor web server logs for unusual URL patterns and redirects originating from the Aruba Networking Private 5G Core On-Prem GUI, as indicated by the `webserver` log source in the provided Sigma rules.
*   Educate users about the dangers of clicking on suspicious links and the importance of verifying the legitimacy of login pages to mitigate phishing risks (T1566).
