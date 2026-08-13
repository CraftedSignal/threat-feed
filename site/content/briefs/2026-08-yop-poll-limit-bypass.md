---
title: Voting Limit Bypass in YOP Poll Plugin via X-Forwarded-For Spoofing
slug: 2026-08-yop-poll-limit-bypass
description: A publicly available exploit targets CVE-2026-14840, a vulnerability in the YOP Poll plugin (v7.0.5) that allows attackers to bypass voting rate limits by spoofing IP addresses via the X-Forwarded-For HTTP header.
date: "2026-08-13T00:27:22Z"
type: advisory
types:
  - advisory
severities:
  - medium
vendors:
  - YOP Poll
products:
  - YOP Poll (7.0.5)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: YOP Poll 7.0.5 allows voting limit bypass via X-Forwarded-For IP spoofing.
    confidence_band: high
cves:
  - id: CVE-2026-14840
    cvss: 5.3
    epss: 0.0021
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Audit web application logs for high-frequency POST requests to poll endpoints containing rotating X-Forwarded-For values
      owner: SOC
      due: 48h
      evidence: The wp_yoppoll_votes table grows by one row per spoofed IP, confirming the per-IP limit is bypassed.
  mitigation_plan:
    - priority: short_term
      action: Upgrade YOP Poll plugin to a patched version once released
      owner: IT Operations
      addresses: CVE-2026-14840
      evidence: YOP Poll 7.0.5 allows voting limit bypass.
---

CVE-2026-14840 affects the YOP Poll plugin (version 7.0.5) for WordPress, enabling unauthorized manipulation of poll results. The vulnerability arises from improper validation of the client's IP address when determining voting eligibility. An attacker can bypass per-IP rate limiting by injecting arbitrary IP addresses into the X-Forwarded-For HTTP header, causing the application to treat each request as originating from a unique, previously uncounted user. This vulnerability allows for the automated submission of multiple votes, potentially skewing public perception or poll outcomes. A functional proof-of-concept exploit was released on 2026-08-13, significantly lowering the barrier for exploitation. Defenders should monitor for anomalous spikes in voting activity from single sources and validate IP-based restrictions against header-based spoofing.

## Attack Chain

1. Attacker identifies a target website utilizing the YOP Poll WordPress plugin version 7.0.5.
2. Attacker inspects the polling mechanism to determine the endpoint processing vote submissions.
3. Attacker crafts a series of HTTP POST requests directed at the poll submission endpoint.
4. Attacker inserts a custom 'X-Forwarded-For' header in each request with unique or spoofed IP address values.
5. The YOP Poll plugin processes the request and incorrectly trusts the 'X-Forwarded-For' value over the source IP for rate-limiting checks.
6. The backend database, 'wp_yoppoll_votes', records each request as a legitimate vote from a new user.
7. Attacker repeats the process to accumulate a large number of votes, effectively rigging the poll results.

## Impact

Successful exploitation allows an attacker to bypass business logic controls, leading to the integrity compromise of poll results. While the impact is primarily service-level manipulation rather than data exfiltration or system compromise, it directly affects the trustworthiness of user engagement features deployed across WordPress websites. Organizations relying on this plugin for public sentiment analysis or high-stakes voting should consider the risk of automated manipulation.

## Recommendation

- Implement request logging for the 'X-Forwarded-For' header in web application firewalls or load balancers to detect irregular patterns of IP rotation.
- Patch the YOP Poll plugin to the latest version as soon as a fix is available from the vendor.
- Review web server configurations to ensure that 'X-Forwarded-For' headers are sanitized or trusted only from verified proxy ranges.
