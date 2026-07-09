---
title: CVE-2026-60108 - Zeek FTP Analyzer Uncontrolled Memory Consumption leading to DoS
slug: 2026-07-zeek-ftp-dos
description: An uncontrolled memory consumption vulnerability in the Zeek FTP analyzer, versions prior to 8.0.9, allows unauthenticated remote attackers to cause process termination and denial of service of the Zeek sensor. This occurs when a crafted FTP control session with AUTH GSSAPI and a large ADAT control line exploits the NVT_Analyzer component's lack of a maximum line length check, leading to an unbounded internal buffer during base64 decoding.
date: "2026-07-09T15:19:23Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - cve
  - dos
  - zeek
  - network-protocol
  - vulnerability
vendors:
  - Zeek
products:
  - Zeek (< 8.0.9)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: Attackers can exploit the NVT_Analyzer component's lack of a maximum line length check, causing it to continuously double its internal buffer without bounds during base64 decoding of an attacker-controlled ADAT token, resulting in denial of service of the Zeek sensor.
    confidence_band: high
cves:
  - id: CVE-2026-60108
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-60108
---

Zeek before 8.0.9 contains an uncontrolled memory consumption vulnerability in the FTP analyzer that allows unauthenticated remote attackers to cause process termination by sending a crafted FTP control session negotiating AUTH GSSAPI followed by a large ADAT control line. Attackers can exploit the NVT_Analyzer component's lack of a maximum line length check, causing it to continuously double its internal buffer without bounds during base64 decoding of an attacker-controlled ADAT token, resulting in denial of service of the Zeek sensor. This vulnerability, tracked as CVE-2026-60108, impacts versions prior to 8.0.9 and poses a significant risk to the availability and stability of network monitoring operations where Zeek sensors are deployed, as it can be triggered remotely without authentication.

## Attack Chain

1. Unauthenticated remote attacker establishes an FTP control connection to a vulnerable Zeek sensor.
2. Attacker sends a crafted FTP command to initiate GSSAPI authentication negotiation within the session.
3. Zeek's FTP analyzer, specifically the NVT_Analyzer component, begins processing the GSSAPI authentication.
4. Attacker sends an excessively large Authentication Data (ADAT) control line within the ongoing FTP control session.
5. The NVT_Analyzer attempts to base64 decode the large ADAT token without an internal buffer size limit.
6. The NVT_Analyzer continuously allocates and reallocates memory, doubling its buffer size without bounds, in an attempt to handle the oversized input.
7. This uncontrolled memory consumption rapidly exhausts the Zeek sensor's available system resources.
8. The Zeek sensor process terminates unexpectedly, resulting in a complete denial of service for the network monitoring system.

## Impact

The successful exploitation of CVE-2026-60108 results in the unauthenticated remote termination of the Zeek sensor process. This leads to a denial of service, rendering the Zeek instance incapable of network traffic analysis and security monitoring. For organizations relying on Zeek for critical threat detection, incident response, and compliance logging, this means a complete loss of visibility over network activity during the attack, potentially allowing other malicious activities to go undetected.

## Recommendation

- Patch CVE-2026-60108 immediately by updating all affected Zeek installations to version 8.0.9 or later to address the uncontrolled memory consumption vulnerability.
