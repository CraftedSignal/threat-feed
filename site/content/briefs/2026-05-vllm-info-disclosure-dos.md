---
title: vllm Vulnerability Allows Information Disclosure and DoS
slug: 2026-05-vllm-info-disclosure-dos
description: A remote, authenticated attacker can exploit a vulnerability in vllm to disclose information or cause a denial-of-service condition.
date: "2026-05-21T07:38:08Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - vulnerability
  - denial-of-service
  - information-disclosure
products:
  - vllm
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1068
    technique_name: Exploitation for Information Discovery
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-0233
rules:
  - title: Detect Suspicious vllm Request Parameters
    description: Detects unusual patterns in request parameters sent to a vllm instance that may indicate a vulnerability exploitation attempt.
    platform: sigma
    severity: medium
    tactics:
      - denial_of_service
      - discovery
    data_sources:
      - webserver
  - title: Detect Repeated Authentication Failures to vllm
    description: Detects repeated authentication failures to a vllm instance from the same source IP, potentially indicating a brute-force attack.
    platform: sigma
    severity: low
    tactics:
      - initial_access
    data_sources:
      - webserver
rules_count: 2
---

A vulnerability exists in vllm that could be exploited by a remote, authenticated attacker. Successful exploitation of this vulnerability can lead to information disclosure and/or a denial-of-service condition. This vulnerability requires the attacker to have valid credentials to access the vllm instance. Defenders should implement appropriate access controls and monitoring to detect and prevent potential exploitation attempts. The exact nature of the vulnerability is not specified but falls within information disclosure or denial of service when successfully exploited.

## Attack Chain

1. The attacker obtains valid credentials for a vllm instance, either through credential harvesting, brute-forcing, or social engineering.
2. The attacker authenticates to the vllm instance using the obtained credentials.
3. The attacker sends a crafted request to the vllm instance, triggering the vulnerability. The exact nature of the request depends on the specific vulnerability.
4. If the vulnerability is information disclosure, the vllm instance responds with sensitive data that the attacker is not authorized to access.
5. If the vulnerability is denial of service, the vllm instance becomes unresponsive or crashes due to the crafted request.
6. The attacker may repeat the crafted requests to maintain the denial of service state.
7. The attacker may exfiltrate the disclosed information to an external location.

## Impact

Successful exploitation of this vulnerability can lead to the exposure of sensitive information, potentially compromising confidential data handled by vllm. A denial-of-service condition can disrupt the availability of vllm, impacting dependent services and users. The number of victims is unknown, as is the sector or type of information exposed.

## Recommendation

*   Monitor vllm access logs for suspicious authentication attempts, looking for unusual IP addresses or login patterns.
*   Deploy the Sigma rule to detect unusual patterns in request parameters potentially related to this vulnerability.
*   Implement rate limiting to mitigate potential denial-of-service attacks and limit the impact of a successful vulnerability exploitation.
