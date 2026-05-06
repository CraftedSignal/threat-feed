---
title: Multiple Vulnerabilities in Zabbix
slug: 2026-05-zabbix-vulns
description: Multiple vulnerabilities in Zabbix versions 6.0.x before 6.0.45, 7.0.x before 7.0.24, and 7.4.x before 7.4.8 allow for data confidentiality breaches and remote cross-site scripting (XSS) attacks.
date: "2026-05-06T00:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - zabbix
  - xss
  - vulnerability
vendors:
  - Zabbix
products:
  - Zabbix < 6.0.45
  - Zabbix < 7.0.24
  - Zabbix < 7.4.8
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-23926
  - id: CVE-2026-23927
  - id: CVE-2026-23928
references:
  - https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0541/
  - https://support.zabbix.com/browse/ZBX-27758
  - https://support.zabbix.com/browse/ZBX-27759
  - https://support.zabbix.com/browse/ZBX-27760
  - https://www.cve.org/CVERecord?id=CVE-2026-23926
  - https://www.cve.org/CVERecord?id=CVE-2026-23927
  - https://www.cve.org/CVERecord?id=CVE-2026-23928
rules:
  - title: Detect Suspicious Zabbix HTTP URI
    description: Detects potential exploitation attempts by looking for suspicious patterns in Zabbix HTTP URIs.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Suspicious Zabbix HTTP POST Request
    description: Detects potential exploitation attempts by looking for suspicious patterns in Zabbix HTTP POST requests.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Multiple vulnerabilities have been discovered in Zabbix, a popular open-source monitoring solution. These vulnerabilities, detailed in Zabbix security bulletins ZBX-27758, ZBX-27759, and ZBX-27760, can lead to a breach of data confidentiality and enable remote cross-site scripting (XSS) attacks. The affected versions include Zabbix 6.0.x prior to 6.0.45, Zabbix 7.0.x prior to 7.0.24, and Zabbix 7.4.x prior to 7.4.8. Successful exploitation of these vulnerabilities could allow attackers to gain unauthorized access to sensitive information or execute malicious scripts within the context of a user's browser. This poses a significant risk to organizations relying on Zabbix for their monitoring infrastructure.

## Attack Chain

1.  The attacker identifies a vulnerable Zabbix instance running a version prior to 6.0.45, 7.0.24, or 7.4.8.
2.  The attacker crafts a malicious HTTP request targeting an endpoint susceptible to XSS.
3.  The Zabbix server processes the malicious request without proper sanitization.
4.  The server reflects the malicious payload back to the user's browser.
5.  The user's browser executes the attacker-injected script.
6.  The injected script steals the user's session cookies.
7.  The attacker uses the stolen session cookies to authenticate to the Zabbix web interface.
8.  The attacker gains unauthorized access to sensitive monitoring data or performs administrative actions.

## Impact

Successful exploitation of these vulnerabilities can lead to unauthorized access to sensitive monitoring data, potentially exposing critical infrastructure details, credentials, and network configurations. The XSS vulnerability can also be leveraged to perform actions on behalf of legitimate users, leading to further compromise of the Zabbix system and potentially impacting the wider network. Given the widespread use of Zabbix in IT infrastructure monitoring, a successful attack could have significant repercussions for affected organizations.

## Recommendation

*   Immediately upgrade Zabbix instances to versions 6.0.45, 7.0.24, 7.4.8 or later to patch the vulnerabilities described in Zabbix security bulletins ZBX-27758, ZBX-27759, and ZBX-27760.
*   Deploy the Sigma rule "Detect Suspicious Zabbix HTTP URI" to identify potential exploitation attempts targeting vulnerable Zabbix instances.
*   Monitor web server logs for unusual activity and patterns indicative of XSS attacks.
