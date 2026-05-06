---
title: 'CVE-2026-32071: Windows LSASS Null Pointer Dereference DoS'
slug: 2026-04-lsass-dos
description: CVE-2026-32071 is a null pointer dereference vulnerability in the Windows Local Security Authority Subsystem Service (LSASS), allowing an unauthorized network attacker to cause a denial-of-service condition.
date: "2026-04-15T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - cve-2026-32071
  - denial-of-service
  - windows
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1498
    technique_name: Denial of Service
cves:
  - id: CVE-2026-32071
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-32071
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-32071
rules:
  - title: Detect LSASS Process Crash
    description: Detects LSASS process termination which may indicate a denial-of-service attack
    platform: sigma
    severity: high
    tactics:
      - availability
    techniques:
      - T1498
    data_sources:
      - process_creation
      - windows
  - title: Detect Network traffic to LSASS
    description: Detects network connections to LSASS service which may indicate an exploit attempt
    platform: sigma
    severity: medium
    tactics:
      - availability
    techniques:
      - T1498
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

CVE-2026-32071 is a security vulnerability affecting the Windows Local Security Authority Subsystem Service (LSASS). This vulnerability, reported on April 14, 2026, stems from a null pointer dereference error. An unauthenticated attacker, positioned on the network, can exploit this flaw to trigger a denial-of-service (DoS) condition. LSASS is a critical component responsible for security policies, user authentication, and access token management. A successful exploitation of this vulnerability can disrupt these core functionalities, leading to system instability and potential service outages. The vulnerability has a CVSS v3.1 score of 7.5, indicating a high severity.

## Attack Chain

1.  The attacker identifies a vulnerable Windows system with LSASS exposed on the network.
2.  The attacker crafts a malicious network request specifically designed to trigger the null pointer dereference within LSASS.
3.  The attacker sends the crafted network request to the targeted Windows system.
4.  LSASS receives the malicious request and attempts to process it.
5.  During the processing of the request, LSASS encounters a null pointer.
6.  LSASS attempts to dereference the null pointer, leading to an unhandled exception.
7.  The exception causes LSASS to crash or become unresponsive, resulting in a denial-of-service condition.
8.  The targeted Windows system experiences authentication failures and other security-related issues due to the disruption of LSASS.

## Impact

Successful exploitation of CVE-2026-32071 leads to a denial-of-service condition on the targeted Windows system. This means legitimate users will be unable to authenticate, access resources, or perform other security-dependent operations. The impact can range from temporary service disruptions to complete system unavailability, potentially affecting all users and applications relying on the compromised system. The vulnerability affects all Windows systems where LSASS is exposed over a network and has not been patched.

## Recommendation

*   Apply the security update provided by Microsoft to patch CVE-2026-32071 on all affected Windows systems. Reference the Microsoft advisory linked in the references section.
*   Deploy the Sigma rule "Detect LSASS process crash" to identify potential exploitation attempts based on LSASS process termination events.
*   Monitor network traffic for suspicious activity targeting LSASS, and correlate with system logs for potential exploitation attempts.
