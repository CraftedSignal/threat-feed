---
title: Multiple Vulnerabilities in Exim Mail Transfer Agent
slug: 2026-04-exim-vulns
description: Multiple vulnerabilities in Exim versions prior to 4.99.2 allow an attacker to cause a remote denial of service, a breach of data confidentiality, and an unspecified security problem.
date: "2026-04-30T00:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - vulnerability
  - denial-of-service
  - information-disclosure
vendors:
  - Exim
products:
  - Exim (< 4.99.2)
mitre_ttps:
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1021
    technique_name: Remote Services
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1068
    technique_name: Software Discovery
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1498
    technique_name: Denial of Service
references:
  - https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0524/
  - https://www.exim.org/static/doc/security/cve-2026-04.1/
  - https://www.cve.org/CVERecord?id=CVE-2026-40684
  - https://www.cve.org/CVERecord?id=CVE-2026-40685
  - https://www.cve.org/CVERecord?id=CVE-2026-40686
  - https://www.cve.org/CVERecord?id=CVE-2026-40687
rules:
  - title: Detect Exim process crashes
    description: Detects potential Exim process crashes which can be caused by denial of service attacks.
    platform: sigma
    severity: high
    tactics:
      - availability
    techniques:
      - T1498
    data_sources:
      - process_creation
      - linux
  - title: Detect Malicious Exim SMTP Traffic
    description: Detects potentially malicious SMTP traffic to Exim servers by looking for unusual message sizes, high connection rates, or other anomalies indicative of exploitation attempts. Requires network connection logging.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1566
    data_sources:
      - network_connection
      - linux
  - title: Detect Exim Configuration File Modifications
    description: Detects modifications to Exim configuration files which could indicate malicious activity.
    platform: sigma
    severity: low
    tactics:
      - persistence
    techniques:
      - T1547
    data_sources:
      - file_event
      - linux
rules_count: 3
---

On April 30, 2026, CERT-FR published an advisory regarding multiple vulnerabilities affecting Exim versions prior to 4.99.2. These vulnerabilities could allow a remote attacker to perform a denial-of-service attack, achieve unauthorized data access, or cause other unspecified security impacts. The vulnerabilities are detailed in the Exim security bulletin cve-2026-04.1. Due to the widespread use of Exim as a mail transfer agent (MTA), these vulnerabilities pose a significant risk to organizations that have not yet applied the necessary patches. Successful exploitation can disrupt email services and potentially lead to sensitive information disclosure.

## Attack Chain

1.  Attacker identifies an Exim server running a vulnerable version (prior to 4.99.2).
2.  The attacker crafts a malicious network packet targeting a specific vulnerability, such as CVE-2026-40684, CVE-2026-40685, CVE-2026-40686, or CVE-2026-40687.
3.  The attacker sends the crafted packet to the vulnerable Exim server via SMTP.
4.  The Exim process receives the malicious packet and processes it due to missing or insufficient input validation.
5.  Depending on the exploited vulnerability, this could lead to a denial-of-service condition by crashing the Exim process.
6.  Alternatively, successful exploitation may lead to an information leak by disclosing sensitive data from Exim's memory.
7.  In other cases, the unspecified security issue could grant further access to the underlying system, depending on the nature of vulnerability.
8.  The attacker exploits this access to achieve goals like data exfiltration or further system compromise (depending on the specific vulnerability triggered).

## Impact

Successful exploitation of these vulnerabilities could lead to denial-of-service conditions, preventing legitimate users from sending and receiving emails. Data confidentiality could also be compromised if sensitive information is exposed. The advisory does not specify the number of victims or specific sectors targeted, but given the widespread use of Exim, a large number of organizations could be affected. Failure to patch Exim servers could result in significant disruption of email services and potential data breaches.

## Recommendation

*   Immediately upgrade Exim servers to version 4.99.2 or later to remediate the vulnerabilities mentioned in the Exim security bulletin cve-2026-04.1.
*   Monitor network traffic for suspicious activity targeting Exim servers, and correlate with the known CVEs (CVE-2026-40684, CVE-2026-40685, CVE-2026-40686, CVE-2026-40687).
*   Implement rate limiting and connection filtering to mitigate potential denial-of-service attacks against Exim servers.
*   Deploy a web server rule that monitors for requests matching known attack patterns related to Exim vulnerabilities.
