---
title: 'CVE-2026-64619: FileCodeBox Rate Limit Bypass Vulnerability'
slug: 2026-07-filecodebox-rate-limit-bypass
description: Unauthenticated attackers can bypass rate limits in FileCodeBox versions before 2.4 due to a vulnerability in the IPRateLimit class, allowing them to enumerate share codes and retrieve other users' files without authentication by spoofing X-Real-IP and X-Forwarded-For headers without proper verification.
date: "2026-07-20T19:28:03Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - rate-limit-bypass
  - vulnerability
  - web-application
  - file-sharing
  - data-exfiltration
  - cve
vendors:
  - vastsa
products:
  - FileCodeBox
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: FileCodeBox before 2.4 contains a rate-limit bypass vulnerability in the IPRateLimit class that allows unauthenticated attackers to circumvent request throttling by supplying attacker-controlled X-Real-IP and X-Forwarded-For headers without verification of trusted reverse proxy origin.
    confidence_band: high
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1005
    technique_name: Data from Local System
    evidence: Attackers can supply unique spoofed IP values on each request to enumerate all possible share codes and retrieve other users' files without authentication.
    confidence_band: high
cves:
  - id: CVE-2026-64619
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-64619
  - https://github.com/vastsa/FileCodeBox/commit/1b6d8e7277d3cfa34dc7a85803731d927b2147da
  - https://github.com/vastsa/FileCodeBox/issues/479
  - https://github.com/vastsa/FileCodeBox/releases/tag/V2.4
  - https://www.vulncheck.com/advisories/filecodebox-anti-bruteforce-rate-limit-bypass-via-spoofed-headers
iocs:
  - type: url
    value: https://github.com/vastsa/FileCodeBox/commit/1b6d8e7277d3cfa34dc7a85803731d927b2147da
  - type: url
    value: https://github.com/vastsa/FileCodeBox/issues/479
  - type: url
    value: https://github.com/vastsa/FileCodeBox/releases/tag/V2.4
  - type: url
    value: https://www.vulncheck.com/advisories/filecodebox-anti-bruteforce-rate-limit-bypass-via-spoofed-headers
ioc_counts:
  url: 4
---

CVE-2026-64619 describes a critical rate-limit bypass vulnerability affecting FileCodeBox versions prior to 2.4. This flaw resides within the `IPRateLimit` class, where the application fails to adequately verify the origin of `X-Real-IP` and `X-Forwarded-For` HTTP headers. Threat actors can exploit this by supplying unique, attacker-controlled IP values in these headers with each request, effectively circumventing the application's throttling mechanisms. This allows unauthenticated attackers to rapidly enumerate all possible share codes for files hosted on the platform. The primary goal of such an attack is to gain unauthorized access to and retrieve files belonging to other users, leading to data exfiltration. The vulnerability is attributed to a "Use of Less Trusted Source" (CWE-348) when processing these headers.

## Attack Chain

1. An unauthenticated attacker identifies a FileCodeBox instance running a vulnerable version (prior to 2.4).
2. The attacker crafts HTTP requests targeting FileCodeBox endpoints that handle shared content or are subject to rate limiting for access attempts.
3. The attacker injects `X-Real-IP` and `X-Forwarded-For` HTTP headers into these requests, assigning unique, attacker-controlled IP addresses for each individual request.
4. The vulnerable `IPRateLimit` class in FileCodeBox processes these requests without adequately verifying the trustworthiness of the `X-Real-IP` and `X-Forwarded-For` headers.
5. This critical flaw bypasses the application's rate limiting mechanism, enabling the attacker to send a high volume of requests in rapid succession.
6. The attacker leverages these rapid requests to systematically enumerate or brute-force all possible share codes for files hosted on the platform.
7. Upon successfully identifying valid share codes, the attacker makes subsequent requests using these codes to retrieve the corresponding files.
8. The attacker successfully gains unauthorized access to and exfiltrates sensitive or private files belonging to other FileCodeBox users without requiring any form of authentication.

## Impact

Successful exploitation of CVE-2026-64619 allows unauthenticated attackers to bypass security controls designed to prevent brute-force attacks and unauthorized access. The primary impact is the unauthorized retrieval of other users' files, potentially leading to widespread data exfiltration. While no specific victim counts or targeted sectors are provided in the advisory, any organization or individual using FileCodeBox versions prior to 2.4 could be at risk of having their shared files accessed by malicious actors without their consent. This can result in significant privacy breaches, exposure of sensitive information, and reputational damage.

## Recommendation

* Immediately update FileCodeBox instances to version 2.4 or later to patch CVE-2026-64619. Refer to the GitHub release at `https://github.com/vastsa/FileCodeBox/releases/tag/V2.4`.
* Review the commit `https://github.com/vastsa/FileCodeBox/commit/1b6d8e7277d3cfa34dc7a85803731d927b2147da` for details on the fix and implement similar robust verification of `X-Real-IP` and `X-Forwarded-For` headers if running a custom or forked version.
* Monitor web server access logs for a high volume of requests with rapidly changing `X-Real-IP` or `X-Forwarded-For` headers, particularly those targeting file sharing or download endpoints.
