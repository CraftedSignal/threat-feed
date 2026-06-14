---
title: TRENDnet TEW-432BRP Stack-Based Buffer Overflow Vulnerability (CVE-2026-10123)
slug: 2026-05-trendnet-buffer-overflow
description: A stack-based buffer overflow vulnerability (CVE-2026-10123) exists in TRENDnet TEW-432BRP version 3.10B20 within the formSetDomainFilter function, allowing a remote attacker to execute arbitrary code by manipulating specific arguments in a request to /goform/formSetDomainFilter.
date: "2026-05-30T16:24:25Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - cve
  - buffer overflow
  - remote code execution
  - network device
vendors:
  - TRENDnet
products:
  - TEW-432BRP 3.10B20
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-10123
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-10123
  - CVE-2026-10123
rules:
  - title: Detect TRENDnet TEW-432BRP Buffer Overflow Attempt
    description: Detects CVE-2026-10123 exploitation attempt - Suspiciously long parameter values in requests to /goform/formSetDomainFilter, potentially indicating a buffer overflow attempt.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect TRENDnet TEW-432BRP POST Request to formSetDomainFilter
    description: Detects HTTP POST requests to the /goform/formSetDomainFilter endpoint on TRENDnet TEW-432BRP devices, which could be indicative of exploitation attempts targeting CVE-2026-10123.
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

A stack-based buffer overflow vulnerability, identified as CVE-2026-10123, has been discovered in TRENDnet TEW-432BRP router, version 3.10B20. The vulnerability resides in the `formSetDomainFilter` function within the `/goform/formSetDomainFilter` file. This flaw allows a remote attacker to execute arbitrary code on the device by carefully crafting malicious input to the `blocked_domain`, `permitted_domain`, `blocked_domain_list`, or `permitted_domain_list` arguments. The vendor has stated that the affected product has been end-of-life (EOL) since 2009 and will not be providing a fix. This vulnerability poses a significant risk to users who are still operating this outdated and unsupported device, as it could be easily exploited due to the public availability of the exploit.

## Attack Chain

1.  The attacker identifies a vulnerable TRENDnet TEW-432BRP router running firmware version 3.10B20.
2.  The attacker crafts a malicious HTTP POST request targeting the `/goform/formSetDomainFilter` endpoint.
3.  Within the POST request, the attacker manipulates the `blocked_domain`, `permitted_domain`, `blocked_domain_list`, or `permitted_domain_list` parameters.
4.  The crafted input exceeds the buffer size allocated for these parameters within the `formSetDomainFilter` function.
5.  The overflow overwrites adjacent memory on the stack, including the return address.
6.  The overwritten return address is replaced with the address of malicious code controlled by the attacker.
7.  The `formSetDomainFilter` function completes its execution and attempts to return.
8.  Instead of returning to the intended location, the execution jumps to the attacker-controlled malicious code, achieving remote code execution.

## Impact

Successful exploitation of this vulnerability (CVE-2026-10123) allows a remote attacker to execute arbitrary code on the vulnerable TRENDnet TEW-432BRP device. This could lead to complete compromise of the router, allowing the attacker to eavesdrop on network traffic, modify router settings, or use the device as a bot in a larger attack. Given that the product has been EOL since 2009, users still running this device are unlikely to receive security updates, leaving them permanently vulnerable. The impact is considered high due to the ease of exploitation and the potential for significant damage.

## Recommendation

*   Implement network segmentation to isolate vulnerable TRENDnet TEW-432BRP devices if they cannot be decommissioned.
*   Deploy the Sigma rule `Detect TRENDnet TEW-432BRP Buffer Overflow Attempt` to identify suspicious requests to the `/goform/formSetDomainFilter` endpoint.
*   Monitor web server logs for abnormally long values in the `blocked_domain`, `permitted_domain`, `blocked_domain_list`, and `permitted_domain_list` parameters within requests to `/goform/formSetDomainFilter`.
