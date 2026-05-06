---
title: Multiple Vulnerabilities in Asterisk Allow for Remote Denial of Service
slug: 2026-05-asterisk-dos
description: Multiple vulnerabilities in Asterisk versions 20.18.x before 20.19.0, 21.12.x before 21.12.2, 22.8.x before 22.9.0, 23.2.x before 23.3.0, certified-asterisk 20.x before 20.7-cert10, and certified-asterisk 22.x before 22.8-cert2 allow a remote attacker to cause a denial of service.
date: "2026-05-06T00:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - asterisk
  - voip
  - denial-of-service
vendors:
  - Asterisk
products:
  - Asterisk versions 20.18.x
  - Asterisk versions 21.12.x
  - Asterisk versions 22.8.x
  - Asterisk versions 23.2.x
  - certified-asterisk versions 20.x
  - certified-asterisk versions 22.x
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1498
    technique_name: Denial of Service
cves:
  - id: CVE-2026-25994
    cvss: 9.8
    epss: 0.00024
  - id: CVE-2026-28799
    cvss: 7.5
    epss: 0.0006
  - id: CVE-2026-32942
    cvss: 8.1
    epss: 0.00057
references:
  - https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0538/
  - https://github.com/asterisk/asterisk/security/advisories/GHSA-f948-v379-526c
  - https://github.com/asterisk/asterisk/security/advisories/GHSA-rrfc-6662-c6hm
  - https://github.com/asterisk/asterisk/security/advisories/GHSA-x2f3-ccvh-2rr2
  - https://github.com/asterisk/asterisk/security/advisories/GHSA-x6qg-jfj6-6f93
  - https://www.cve.org/CVERecord?id=CVE-2026-25994
  - https://www.cve.org/CVERecord?id=CVE-2026-28799
  - https://www.cve.org/CVERecord?id=CVE-2026-32942
  - https://www.cve.org/CVERecord?id=CVE-2026-33069
rules:
  - title: Detect Asterisk Server Errors
    description: Detects potential denial of service attempts by monitoring for frequent Asterisk server error messages in logs.
    platform: sigma
    severity: medium
    tactics:
      - availability
    techniques:
      - T1498
    data_sources:
      - webserver
      - linux
  - title: Detect Asterisk Excessive Traffic
    description: Detects potential denial of service attempts by monitoring for a high volume of network connections to Asterisk service ports.
    platform: sigma
    severity: medium
    tactics:
      - availability
    techniques:
      - T1498
    data_sources:
      - network_connection
      - linux
rules_count: 2
---

On May 6, 2026, CERT-FR published an advisory regarding multiple vulnerabilities in Asterisk, a widely-used open-source framework for building communications applications. The vulnerabilities, detailed in Asterisk security advisories GHSA-f948-v379-526c, GHSA-rrfc-6662-c6hm, GHSA-x2f3-ccvh-2rr2, and GHSA-x6qg-jfj6-6f93, can be exploited by a remote attacker to trigger a denial of service (DoS) condition. The affected versions include multiple branches of Asterisk, specifically versions 20.18.x prior to 20.19.0, 21.12.x prior to 21.12.2, 22.8.x prior to 22.9.0, 23.2.x prior to 23.3.0, certified-asterisk versions 20.x prior to 20.7-cert10, and certified-asterisk versions 22.x prior to 22.8-cert2. These vulnerabilities pose a significant risk to organizations relying on Asterisk for their communication infrastructure, as successful exploitation can disrupt critical services.

## Attack Chain

While specific exploitation details are not provided, the general attack chain for a denial-of-service vulnerability typically follows these steps:

1.  **Reconnaissance:** The attacker identifies a target Asterisk server and determines its version.
2.  **Vulnerability Identification:** The attacker confirms the presence of one of the disclosed vulnerabilities in the target Asterisk version.
3.  **Exploit Selection:** The attacker selects or crafts a suitable exploit for the identified vulnerability.
4.  **Exploit Delivery:** The attacker sends a malicious request to the Asterisk server. The nature of this request depends on the specific vulnerability being exploited.
5.  **Vulnerability Trigger:** The malicious request triggers a flaw in Asterisk's code, such as a buffer overflow, excessive resource consumption, or a crash.
6.  **Denial of Service:** The Asterisk server becomes unresponsive or crashes due to the triggered vulnerability, leading to a denial of service for legitimate users.
7.  **Service Disruption:** Users are unable to make or receive calls, access voicemail, or utilize other Asterisk-based services.

## Impact

Successful exploitation of these vulnerabilities leads to a denial-of-service condition, disrupting communication services reliant on Asterisk. The advisory does not specify the number of victims or sectors targeted. However, given the widespread use of Asterisk in various industries, including telecommunications, healthcare, and customer service, the impact could be significant. A successful attack can result in business disruption, financial losses, and reputational damage.

## Recommendation

*   Upgrade Asterisk to the latest patched version. Specifically, upgrade asterisk versions 20.18.x to 20.19.0 or later, 21.12.x to 21.12.2 or later, 22.8.x to 22.9.0 or later, 23.2.x to 23.3.0 or later, certified-asterisk versions 20.x to 20.7-cert10 or later, and certified-asterisk versions 22.x to 22.8-cert2 or later, as detailed in the advisory.
*   Monitor network traffic for suspicious patterns indicative of denial-of-service attacks targeting Asterisk servers. Deploy network intrusion detection systems (NIDS) with signatures to detect known Asterisk exploit attempts.
*   Review Asterisk server logs for error messages or unusual activity that might indicate a vulnerability exploitation attempt. Enable verbose logging to capture detailed information about incoming requests and server responses.
