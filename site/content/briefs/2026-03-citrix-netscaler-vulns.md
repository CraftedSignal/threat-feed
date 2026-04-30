---
title: Citrix NetScaler ADC and Gateway Vulnerabilities
slug: 2026-03-citrix-netscaler-vulns
description: Citrix has released a security advisory addressing multiple vulnerabilities in NetScaler ADC and NetScaler Gateway that could lead to sensitive information disclosure and user session mix-up under specific configurations.
date: "2026-03-23T19:03:59Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - citrix
  - netscaler
  - vulnerability
  - information-disclosure
references:
  - https://cert.europa.eu/publications/security-advisories/2026-003/
rules:
  - title: Detect Suspicious HTTP Requests to NetScaler
    description: Detects suspicious HTTP requests that may indicate an attempt to exploit NetScaler vulnerabilities.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1595.002
    data_sources:
      - webserver
      - linux
  - title: Detect NetScaler Session Mix-up Attempt
    description: Detects unusual session activity indicative of a session mix-up attempt.
    platform: sigma
    severity: low
    tactics:
      - defense_evasion
    techniques:
      - T1078
    data_sources:
      - webserver
      - linux
rules_count: 2
---

On March 23, 2026, Citrix released a security advisory detailing several vulnerabilities affecting NetScaler ADC and NetScaler Gateway products. These vulnerabilities, if exploited, could lead to sensitive information disclosure and user session mix-up. While there is currently no evidence of active exploitation, the potential impact warrants immediate attention and remediation, particularly for internet-facing assets. The advisory urges organizations to update their affected NetScaler instances promptly and preserve any relevant logs for potential future investigations. This disclosure highlights the ongoing risk associated with perimeter security devices and the need for proactive patching and monitoring.

## Attack Chain

1.  An attacker identifies a vulnerable NetScaler ADC or Gateway instance accessible over the internet.
2.  The attacker crafts a malicious HTTP request targeting a specific vulnerable endpoint or functionality within the NetScaler device.
3.  The vulnerable NetScaler processes the malicious request without proper sanitization or validation.
4.  Due to the vulnerability, the attacker gains unauthorized access to sensitive information, such as configuration details, session tokens, or user credentials.
5.  Alternatively, the attacker exploits the vulnerability to manipulate user sessions, potentially hijacking legitimate user accounts.
6.  The attacker uses the stolen credentials or hijacked sessions to access internal network resources or sensitive applications behind the NetScaler device.
7.  The attacker exfiltrates sensitive data or performs unauthorized actions within the compromised internal network.

## Impact

Successful exploitation of these vulnerabilities could lead to the disclosure of sensitive configuration data, including credentials and internal network topology. User session mix-up could grant attackers access to legitimate user accounts, allowing them to perform unauthorized actions and potentially compromise sensitive data. While the exact scope and number of potential victims is unknown, organizations using affected NetScaler products are at risk.

## Recommendation

*   Immediately update affected NetScaler ADC and Gateway instances to the latest patched versions as recommended by Citrix in their security advisory [https://cert.europa.eu/publications/security-advisories/2026-003/].
*   Prioritize patching internet-facing NetScaler assets to minimize the attack surface.
*   Enable verbose logging on NetScaler devices and preserve logs for potential future incident investigation.
*   Deploy the Sigma rules provided in this brief to your SIEM to detect potential exploitation attempts against NetScaler devices.
