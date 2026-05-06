---
title: GPT Researcher Server-Side Request Forgery Vulnerability (CVE-2026-5633)
slug: 2026-04-gpt-researcher-ssrf
description: A server-side request forgery (SSRF) vulnerability exists in assafelovic gpt-researcher up to version 3.4.3, affecting the ws Endpoint component, allowing a remote attacker to manipulate the source_urls argument and potentially access internal resources or conduct further attacks.
date: "2026-04-06T08:16:39Z"
severities:
  - high
type: advisory
types:
  - advisory
tags:
  - ssrf
  - cve-2026-5633
  - gpt-researcher
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-5633
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-5633
  - https://github.com/assafelovic/gpt-researcher/
  - https://github.com/assafelovic/gpt-researcher/issues/1696
  - https://vuldb.com/vuln/355421
iocs:
  - type: url
    value: https://github.com/assafelovic/gpt-researcher/
ioc_counts:
  url: 1
rules:
  - title: Detect GPT Researcher SSRF Attempt via URL Parameter
    description: Detects potential SSRF attempts against GPT Researcher by monitoring for suspicious URL patterns in the source_urls parameter.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1078
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect GPT Researcher SSRF Attempt via External URL
    description: Detects potential SSRF attempts against GPT Researcher by monitoring for suspicious URL patterns in the source_urls parameter to external non-standard ports.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1078
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A server-side request forgery (SSRF) vulnerability, identified as CVE-2026-5633, affects assafelovic's gpt-researcher version 3.4.3 and earlier. The vulnerability resides within the ws Endpoint component and is triggered by manipulating the `source_urls` argument. This flaw allows a remote attacker to potentially force the application to make requests to arbitrary internal or external resources. A publicly disclosed exploit exists, increasing the risk of exploitation. The developers were notified through an issue report, but have not yet responded. This vulnerability is a significant concern for organizations using gpt-researcher, as it can lead to sensitive data exposure or further attacks originating from the application's server.

## Attack Chain

1.  Attacker identifies a gpt-researcher instance running version 3.4.3 or earlier.
2.  Attacker crafts a malicious request containing a manipulated `source_urls` argument. This URL points to an internal resource or an external server controlled by the attacker.
3.  The gpt-researcher application, specifically the ws Endpoint component, processes the request without proper validation of the `source_urls` parameter.
4.  The application initiates a request to the attacker-specified URL, effectively acting as a proxy.
5.  If the URL points to an internal resource, the attacker gains access to potentially sensitive data or internal services not intended for public access.
6.  If the URL points to an external server controlled by the attacker, the server receives the request, revealing information about the gpt-researcher instance, such as its IP address.
7.  The attacker can then leverage this information to further compromise the server or the network it resides on, potentially leading to lateral movement or data exfiltration.

## Impact

Successful exploitation of CVE-2026-5633 can allow an attacker to perform actions they are not authorized to do. This includes reading internal data, accessing internal services, or using the vulnerable server as a proxy for further attacks. While the exact number of victims is unknown, any organization using a vulnerable version of gpt-researcher is at risk. The consequences of a successful SSRF attack can range from information disclosure to full server compromise, depending on the internal resources accessible to the application.

## Recommendation

*   Inspect web server access logs for requests containing suspicious URLs in the `source_urls` parameter that point to internal or unexpected external resources. This can aid in detecting ongoing exploitation attempts (logsource: webserver, product: linux/windows).
*   Apply input validation to the `source_urls` parameter to ensure that the application only makes requests to authorized and expected resources.
*   Monitor network connections originating from the gpt-researcher server for unusual outbound traffic to internal or external IP addresses (logsource: network_connection, product: windows/linux).
*   Deploy the provided Sigma rule to detect potential SSRF attempts by monitoring for suspicious URL patterns in web server logs.
