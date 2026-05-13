---
title: CVE-2026-42409 - F5 BIG-IP TMM Process Termination via HTTP/2 and iRules
slug: 2026-05-f5-tmm-termination
description: CVE-2026-42409 describes a vulnerability in F5 BIG-IP where undisclosed requests can cause the Traffic Management Microkernel (TMM) process to terminate when an HTTP/2 profile and an iRule containing the HTTP::redirect or HTTP::respond command are configured on a virtual server, potentially leading to denial of service.
date: "2026-05-13T16:30:50Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - denial-of-service
  - f5
vendors:
  - F5 Networks
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Denial of Service
cves:
  - id: CVE-2026-42409
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-42409
  - https://my.f5.com/manage/s/article/K000159034
rules:
  - title: Detect CVE-2026-42409 Exploitation Attempts - HTTP/2 Request Patterns
    description: Detects potential attempts to exploit CVE-2026-42409 by identifying suspicious patterns in HTTP/2 requests targeting F5 BIG-IP systems. Note that detecting the root cause of the TMM termination is difficult from webserver logs alone; this rule looks for generic anomalies.
    platform: sigma
    severity: low
    tactics:
      - denial_of_service
    techniques:
      - T1499.001
    data_sources:
      - webserver
  - title: Detect CVE-2026-42409 - F5 TMM Process Crash
    description: Detects CVE-2026-42409 - Monitors for unexpected termination of the Traffic Management Microkernel (TMM) process on F5 BIG-IP systems, which could indicate exploitation. Note that this rule cannot directly attribute the crash to the specific CVE, but flags unusual TMM termination events.
    platform: sigma
    severity: medium
    tactics:
      - denial_of_service
    techniques:
      - T1499.001
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

CVE-2026-42409 exposes a vulnerability within F5 BIG-IP systems that can lead to a denial-of-service condition. The vulnerability is triggered when an HTTP/2 profile and an iRule containing either the `HTTP::redirect` or `HTTP::respond` command are both configured on a virtual server. In this specific configuration, specially crafted requests can cause the Traffic Management Microkernel (TMM) process to terminate unexpectedly. The scope of impact is limited to affected F5 BIG-IP systems that are configured in this manner. Note that software versions which have reached End of Technical Support (EoTS) are not evaluated. This issue was reported on May 13, 2026.

## Attack Chain

1. An attacker identifies a target F5 BIG-IP system configured with an HTTP/2 profile and an iRule using `HTTP::redirect` or `HTTP::respond`.
2. The attacker crafts a malicious HTTP/2 request.
3. The attacker sends the malicious HTTP/2 request to the vulnerable virtual server.
4. The BIG-IP system processes the request through the configured HTTP/2 profile and iRule.
5. The crafted request triggers a null pointer dereference within the TMM process (CWE-476).
6. The TMM process terminates unexpectedly due to the unhandled exception.
7. The interruption of the TMM process causes a denial-of-service condition, impacting traffic processing.

## Impact

Successful exploitation of CVE-2026-42409 results in the termination of the TMM process, leading to a denial-of-service condition. This can disrupt network traffic managed by the affected F5 BIG-IP system. The vulnerability has a CVSS v3.1 score of 7.5, indicating a high impact on availability. The number of potential victims is dependent on the number of F5 BIG-IP systems with the described vulnerable configuration.

## Recommendation

- Apply the mitigations or patches recommended by F5 Networks to prevent the TMM process from terminating. Refer to [https://my.f5.com/manage/s/article/K000159034](https://my.f5.com/manage/s/article/K000159034) for specific instructions.
- Monitor web server logs for anomalous HTTP/2 requests that might be attempting to trigger CVE-2026-42409. Use the webserver log monitoring rule to detect suspicious patterns.
- Review F5 BIG-IP configurations to identify virtual servers using both HTTP/2 profiles and iRules containing `HTTP::redirect` or `HTTP::respond`, and prioritize patching or mitigation for these configurations.
