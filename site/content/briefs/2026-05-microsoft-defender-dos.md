---
title: Microsoft Defender Denial of Service Vulnerability (CVE-2026-45498)
slug: 2026-05-microsoft-defender-dos
description: CVE-2026-45498 is a denial-of-service vulnerability in Microsoft Defender that could disrupt endpoint protection capabilities, requiring timely mitigation per vendor instructions.
date: "2026-05-20T17:32:31Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - denial-of-service
  - vulnerability
  - microsoft-defender
vendors:
  - Microsoft
products:
  - Defender
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
cves:
  - id: CVE-2026-45498
    cvss: 4
references:
  - https://www.cve.org/CVERecord?id=CVE-2026-45498
  - https://msrc.microsoft.com/update-guide/en-US/vulnerability/CVE-2026-45498
  - https://nvd.nist.gov/vuln/detail/CVE-2026-45498
rules:
  - title: Detect possible exploitation of CVE-2026-45498 - Defender process crash
    description: Detects potential exploitation of CVE-2026-45498 based on abnormal process termination of the Defender service.
    platform: sigma
    severity: medium
    tactics:
      - impact
    techniques:
      - T1499.004
    data_sources:
      - process_creation
      - windows
  - title: Detect possible exploitation of CVE-2026-45498 - Defender service stop
    description: Detects potential exploitation of CVE-2026-45498 based on abnormal service termination of the Defender service.
    platform: sigma
    severity: medium
    tactics:
      - impact
    techniques:
      - T1499.004
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

On May 20, 2026, Microsoft disclosed CVE-2026-45498, a denial-of-service (DoS) vulnerability affecting Microsoft Defender. The specifics of the vulnerability are not detailed in the initial disclosure, but successful exploitation could impair the availability of the Defender service on affected systems, potentially leaving them unprotected against malware and other threats. This vulnerability requires immediate attention from security teams to apply vendor-provided mitigations. The absence of detailed exploitation steps underscores the need for proactive measures to safeguard systems.

## Attack Chain

1.  Attacker identifies a system running a vulnerable version of Microsoft Defender.
2.  Attacker crafts a malicious input or triggers a specific condition that exploits CVE-2026-45498. (Details of the trigger are unspecified but assumed to exist.)
3.  The malicious input is processed by the Microsoft Defender engine.
4.  The vulnerability causes the Defender service to enter a non-responsive state.
5.  The system experiences degraded performance or complete failure of Microsoft Defender's real-time protection features.
6.  The targeted system becomes susceptible to malware infections and other security threats due to the disabled or impaired protection mechanism.
7.  Attacker exploits the unprotected system to further compromise the network.

## Impact

A successful denial-of-service attack against Microsoft Defender could result in widespread disruption of endpoint protection across an organization. While the precise number of potential victims and affected sectors are unknown, the ubiquitous deployment of Microsoft Defender in enterprise environments signifies a broad potential impact. Systems left without active Defender protection are at increased risk of malware infection, data breach, and other security incidents.

## Recommendation

*   Immediately apply mitigations provided by Microsoft for CVE-2026-45498 as detailed in the [Microsoft Security Response Center advisory](https://msrc.microsoft.com/update-guide/en-US/vulnerability/CVE-2026-45498).
*   Monitor the health and availability of Microsoft Defender across your environment.
*   Enable logging for Microsoft Defender to capture events related to potential exploitation attempts.
*   Deploy the Sigma rule to detect potential exploitation attempts.
