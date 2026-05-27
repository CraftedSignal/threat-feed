---
title: Multiple Vulnerabilities in Check Point Products
slug: 2026-05-checkpoint-vulns
description: Multiple vulnerabilities in Check Point Security Gateways and Spark Firewalls allow for remote denial of service, data confidentiality breaches, and data integrity compromise.
date: "2026-05-27T14:32:27Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - vulnerability
  - denial-of-service
  - data-breach
  - sql-injection
vendors:
  - Check Point
products:
  - Security Gateways R81.20
  - Security Gateways R82
  - Security Gateways R82.10
  - Spark Firewalls R81
  - Spark Firewalls R82
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1068
    technique_name: Software Discovery
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1114
    technique_name: Email Collection
cves:
  - id: CVE-2026-48131
    cvss: 8.1
  - id: CVE-2026-48136
    cvss: 4.1
  - id: CVE-2026-48134
    cvss: 5.6
  - id: CVE-2026-48135
    cvss: 5.3
references:
  - https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0650/
  - https://support.checkpoint.com/results/sk/sk184981
  - https://support.checkpoint.com/results/sk/sk184982
  - https://support.checkpoint.com/results/sk/sk184983
  - https://support.checkpoint.com/results/sk/sk184991
  - https://support.checkpoint.com/results/sk/sk184992
  - https://support.checkpoint.com/results/sk/sk184993
  - https://www.cve.org/CVERecord?id=CVE-2026-48131
  - https://www.cve.org/CVERecord?id=CVE-2026-48132
  - https://www.cve.org/CVERecord?id=CVE-2026-48133
  - https://www.cve.org/CVERecord?id=CVE-2026-48134
  - https://www.cve.org/CVERecord?id=CVE-2026-48135
  - https://www.cve.org/CVERecord?id=CVE-2026-48136
rules:
  - title: Detect CVE-2026-48131-48136 Exploitation Attempt - Suspicious URI
    description: Detects CVE-2026-48131-48136 exploitation attempts based on suspicious URI patterns indicative of SQL injection.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect CVE-2026-48131-48136 Exploitation Attempt - Error Responses with Keywords
    description: Detects CVE-2026-48131-48136 exploitation attempts based on error responses containing SQL-related keywords.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 2
---

Multiple vulnerabilities have been identified in Check Point products, specifically Security Gateways and Spark Firewalls. These vulnerabilities can lead to significant security breaches, including remote denial-of-service (DoS) attacks, unauthorized access to sensitive data, and modification of data integrity. The affected products include Security Gateways versions R81.20 without hotfix 141, R82 without hotfix 103, and R82.10 without hotfix 19, as well as Spark Firewalls versions R81 prior to R81.10.17 and R82 prior to R82.00.10. Successful exploitation of these vulnerabilities could allow attackers to disrupt services, steal confidential information, or manipulate critical data.

## Attack Chain

1.  Attacker identifies a vulnerable Check Point Security Gateway or Spark Firewall running an unpatched version.
2.  The attacker crafts a malicious request to exploit one of the vulnerabilities (CVE-2026-48131 through CVE-2026-48136), such as an SQL injection.
3.  The malicious request is sent to the targeted device via network protocols (e.g., HTTP/HTTPS).
4.  The targeted device processes the request, triggering the vulnerability due to insufficient input validation or other security flaws.
5.  Depending on the specific vulnerability, the attacker achieves one or more of the following:
    *   Remote Denial of Service: The device becomes unresponsive or crashes, disrupting normal operations.
    *   Data Confidentiality Breach: Sensitive information is exposed to the attacker.
    *   Data Integrity Compromise: Data stored on or processed by the device is modified or corrupted.
6.  The attacker may leverage the initial compromise to gain further access to the network.
7.  The attacker may attempt to escalate privileges or move laterally within the network.
8.  The attacker exfiltrates sensitive data, disrupts operations, or causes further damage.

## Impact

Exploitation of these vulnerabilities can lead to severe consequences, including service disruption, data theft, and data corruption. Successful attacks could impact businesses of all sizes that rely on Check Point security solutions to protect their networks. The vulnerabilities affect Security Gateways and Spark Firewalls, potentially impacting network security, data confidentiality, and regulatory compliance.

## Recommendation

*   Apply the appropriate hotfixes as outlined in Check Point's security advisories (sk184981, sk184982, sk184983, sk184991, sk184992, sk184993) to patch the identified vulnerabilities in Security Gateways and Spark Firewalls.
*   Deploy the Sigma rules below to detect potential exploitation attempts targeting these vulnerabilities.
*   Monitor network traffic for suspicious activity that may indicate exploitation attempts, focusing on unusual requests to Check Point devices.
*   Review and enforce strict access control policies to limit the impact of potential data breaches.
