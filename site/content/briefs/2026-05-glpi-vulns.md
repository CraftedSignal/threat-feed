---
title: Multiple Vulnerabilities in GLPI Allow Data Confidentiality Breach and Security Policy Bypass
slug: 2026-05-glpi-vulns
description: Multiple vulnerabilities in GLPI versions prior to 11.0.7 and 10.0.25 allow an attacker to compromise data confidentiality and bypass security policies.
date: "2026-05-19T12:12:35Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - glpi
  - vulnerability
  - security-policy-bypass
  - data-breach
vendors:
  - GLPI
products:
  - glpi
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1005
    technique_name: Data From Local System
cves:
  - id: CVE-2026-32312
references:
  - https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0609/
  - https://github.com/glpi-project/glpi/security/advisories/GHSA-58j6-94cf-gcx5
  - https://github.com/glpi-project/glpi/security/advisories/GHSA-cg63-qchq-q626
  - https://www.cve.org/CVERecord?id=CVE-2026-32312
  - https://www.cve.org/CVERecord?id=CVE-2026-42320
rules:
  - title: Detect GLPI Security Policy Bypass
    description: Detects potential attempts to bypass security policies in GLPI, potentially leading to unauthorized access or data breaches.
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
  - title: Detect GLPI Data Confidentiality Breach Attempt
    description: Detects attempts to access sensitive data within GLPI, indicative of a potential data breach (CVE-2026-32312, CVE-2026-42320).
    platform: sigma
    severity: high
    tactics:
      - credential_access
      - discovery
    techniques:
      - T1005
    data_sources:
      - webserver
rules_count: 2
---

Multiple vulnerabilities have been discovered in GLPI, a web-based IT service management software. These vulnerabilities, affecting GLPI versions 11.0.x prior to 11.0.7 and versions prior to 10.0.25, can be exploited by an attacker to achieve unauthorized access to sensitive information and circumvent established security policies. The vulnerabilities are detailed in GLPI security advisories GHSA-58j6-94cf-gcx5 and GHSA-cg63-qchq-q626, published on May 18, 2026. Successful exploitation could lead to significant data breaches and unauthorized modification of GLPI configurations.

## Attack Chain

While the specific exploitation methods for CVE-2026-32312 and CVE-2026-42320 are not detailed in the source, a generalized attack chain based on the vulnerability descriptions can be inferred:

1. An attacker identifies a vulnerable GLPI instance running a version prior to 11.0.7 or 10.0.25.
2. The attacker crafts a malicious request targeting one of the identified vulnerabilities (CVE-2026-32312 or CVE-2026-42320).
3. Depending on the vulnerability, this request may involve manipulating input parameters or exploiting insecure deserialization.
4. The crafted request bypasses security policy checks implemented within GLPI.
5. The attacker gains unauthorized access to sensitive data stored within the GLPI system, such as user credentials, configuration details, or ticket information.
6. Alternatively, the attacker modifies GLPI configurations, granting themselves elevated privileges or disabling security features.
7. The attacker may then use their elevated privileges to further compromise the system or exfiltrate sensitive data.

## Impact

Successful exploitation of these vulnerabilities could lead to a significant breach of data confidentiality within the GLPI system. Attackers could gain access to sensitive information such as user credentials, system configurations, and customer data. This can result in financial loss, reputational damage, and legal liabilities for the affected organization. The vulnerabilities also allow for the circumvention of security policies, potentially enabling attackers to perform unauthorized actions and further compromise the system.

## Recommendation

*   Apply the patches provided by GLPI in their security advisories GHSA-58j6-94cf-gcx5 and GHSA-cg63-qchq-q626 to remediate the vulnerabilities.
*   Monitor web server logs for suspicious activity targeting GLPI instances, looking for unusual requests or patterns that might indicate exploitation attempts.
*   Deploy a web application firewall (WAF) rule to detect and block requests exploiting CVE-2026-32312 and CVE-2026-42320.
*   Implement the Sigma rule "Detect GLPI Security Policy Bypass" to identify potential attempts to circumvent security policies within GLPI.
