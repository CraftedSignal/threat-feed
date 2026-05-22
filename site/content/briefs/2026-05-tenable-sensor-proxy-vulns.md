---
title: Multiple Vulnerabilities in Tenable Sensor Proxy
slug: 2026-05-tenable-sensor-proxy-vulns
description: Multiple vulnerabilities in Tenable Sensor Proxy versions prior to 1.4.0 could allow a remote attacker to cause a denial of service, data confidentiality breaches, and other unspecified security impacts.
date: "2026-05-22T13:04:43Z"
type: advisory
types:
  - advisory
severities:
  - medium
cpes:
  - cpe:2.3:a:f5:nginx_open_source:*:*:*:*:*:*:*:*
  - cpe:2.3:a:f5:nginx_plus:r30:-:*:*:*:*:*:*
  - cpe:2.3:a:f5:nginx_plus:r30:p1:*:*:*:*:*:*
  - cpe:2.3:a:f5:nginx_plus:r30:p2:*:*:*:*:*:*
  - cpe:2.3:a:f5:nginx_plus:r31:-:*:*:*:*:*:*
  - cpe:2.3:a:f5:nginx_plus:r31:p1:*:*:*:*:*:*
  - cpe:2.3:o:fedoraproject:fedora:39:*:*:*:*:*:*:*
  - cpe:2.3:o:fedoraproject:fedora:40:*:*:*:*:*:*:*
  - cpe:2.3:a:f5:nginx_open_source:1.27.0:*:*:*:*:*:*:*
  - cpe:2.3:a:f5:nginx_plus:*:*:*:*:*:*:*:*
  - cpe:2.3:a:f5:nginx_plus:r32:-:*:*:*:*:*:*
tags:
  - vulnerability
  - dos
  - dataleak
vendors:
  - Tenable
products:
  - Sensor Proxy (versions prior to 1.4.0)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
cves:
  - id: CVE-2024-31079
    cvss: 4.8
    epss: 0.00483
  - id: CVE-2024-32760
    cvss: 6.5
    epss: 0.00483
  - id: CVE-2024-34161
    cvss: 5.3
    epss: 0.00719
  - id: CVE-2024-35200
    cvss: 5.3
    epss: 0.00433
  - id: CVE-2024-7347
    cvss: 4.7
    epss: 0.00197
references:
  - https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0630/
  - https://www.tenable.com/security/tns-2026-15
  - https://www.cve.org/CVERecord?id=CVE-2024-24989
  - https://www.cve.org/CVERecord?id=CVE-2024-24990
  - https://www.cve.org/CVERecord?id=CVE-2024-31079
  - https://www.cve.org/CVERecord?id=CVE-2024-32760
  - https://www.cve.org/CVERecord?id=CVE-2024-34161
  - https://www.cve.org/CVERecord?id=CVE-2024-35200
  - https://www.cve.org/CVERecord?id=CVE-2024-39702
  - https://www.cve.org/CVERecord?id=CVE-2024-7347
rules:
  - title: Detect Potential Tenable Sensor Proxy DoS Attempts
    description: Detects potential denial-of-service attempts against Tenable Sensor Proxy based on suspicious HTTP requests. This is a generic rule and should be tuned.
    platform: sigma
    severity: medium
    tactics:
      - availability
    techniques:
      - T1499.001
    data_sources:
      - webserver
rules_count: 1
---

On May 22, 2026, CERT-FR published an advisory regarding multiple vulnerabilities discovered in Tenable Sensor Proxy. The advisory highlights that these vulnerabilities could allow an attacker to remotely trigger a denial-of-service condition, compromise data confidentiality, and potentially cause other unspecified security issues. The affected product is Tenable Sensor Proxy versions prior to 1.4.0. Organizations using these versions are vulnerable to these exploits and should upgrade immediately. The specific nature of the unspecified security issue isn't detailed.

## Attack Chain

Due to the lack of specific details about the vulnerabilities themselves, a detailed attack chain cannot be constructed. However, a general attack chain based on the described impacts is possible:

1.  Attacker identifies a vulnerable Tenable Sensor Proxy instance running a version prior to 1.4.0.
2.  Attacker exploits CVE-2024-24989, CVE-2024-24990, CVE-2024-31079, CVE-2024-32760, CVE-2024-34161, CVE-2024-35200, CVE-2024-39702, or CVE-2024-7347 to gain unauthorized access. The specific method depends on the individual vulnerability.
3.  If the vulnerability leads to a denial of service, the attacker crafts a specific request to exhaust resources.
4.  If the vulnerability leads to a data confidentiality breach, the attacker may access sensitive data handled by the Sensor Proxy.
5.  Attacker may further exploit the system due to unspecified vulnerabilities.
6.  The attacker maintains access for future malicious activities or moves laterally within the network.

## Impact

Successful exploitation of these vulnerabilities could have severe consequences, including disruption of services due to denial-of-service attacks and unauthorized access to sensitive data. The specific impact from the unspecified vulnerability is unknown, but could lead to further system compromise. Organizations running vulnerable versions of Tenable Sensor Proxy are at risk.

## Recommendation

*   Immediately upgrade Tenable Sensor Proxy to version 1.4.0 or later to remediate the vulnerabilities ([https://www.tenable.com/security/tns-2026-15](https://www.tenable.com/security/tns-2026-15)).
*   Monitor network traffic for suspicious activity targeting Tenable Sensor Proxy instances, using the provided Sigma rule as a base.
*   Review Tenable's security bulletin (tns-2026-15) for detailed information on each vulnerability and mitigation steps.
*   Investigate any past security events associated with the identified CVEs: CVE-2024-24989, CVE-2024-24990, CVE-2024-31079, CVE-2024-32760, CVE-2024-34161, CVE-2024-35200, CVE-2024-39702, and CVE-2024-7347.
