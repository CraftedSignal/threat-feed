---
title: Unauthenticated Server-Side Request Forgery (SSRF) Vulnerability in stoatchat CVE-2026-63306
slug: 2026-07-stoatchat-unauthenticated-ssrf
description: An unauthenticated server-side request forgery vulnerability, tracked as CVE-2026-63306, exists in stoatchat versions prior to 0.13.5 in the /proxy and /embed endpoints, allowing attackers to enumerate internal services, fingerprint applications, and access instance metadata endpoints, leading to unauthorized information disclosure and potential further compromise of internal infrastructure.
date: "2026-07-16T13:22:57Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - ssrf
  - vulnerability
  - web-application
  - unauthenticated
  - information-disclosure
vendors:
  - stoatchat
products:
  - stoatchat
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: stoatchat before 0.13.5 contains an unauthenticated server-side request forgery vulnerability in the /proxy and /embed endpoints that accept arbitrary URLs without DNS resolution filtering or private IP range validation.
    confidence_band: high
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1046
    technique_name: Network Service Discovery
    evidence: Attackers can enumerate internal services, fingerprint applications, and reach instance metadata endpoints by supplying malicious URLs or leveraging redirect chains to access internal infrastructure.
    confidence_band: high
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1526
    technique_name: Cloud Service Discovery
    evidence: Attackers can enumerate internal services, fingerprint applications, and reach instance metadata endpoints by supplying malicious URLs or leveraging redirect chains to access internal infrastructure.
    confidence_band: high
cves:
  - id: CVE-2026-63306
    cvss: 8.6
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-63306
  - https://github.com/stoatchat/stoatchat/security/advisories/GHSA-xhww-5g9p-vvq5
  - https://www.vulncheck.com/advisories/stoatchat-before-unauthenticated-ssrf-via-proxy-and-embed-endpoints
rules:
  - title: Detects CVE-2026-63306 Exploitation - Unauthenticated SSRF via /proxy or /embed
    description: Detects exploitation attempts of CVE-2026-63306, an unauthenticated Server-Side Request Forgery (SSRF) vulnerability in stoatchat's /proxy and /embed endpoints by identifying requests targeting internal IP addresses or metadata services.
    platform: sigma
    severity: high
    tactics:
      - discovery
      - initial_access
    techniques:
      - T1046
      - T1190
      - T1526
    data_sources:
      - webserver
rules_count: 1
---

CVE-2026-63306 details an unauthenticated server-side request forgery (SSRF) vulnerability affecting stoatchat versions before 0.13.5. The flaw resides within the `/proxy` and `/embed` endpoints, which are designed to accept arbitrary URLs. However, these endpoints lack crucial security controls, specifically DNS resolution filtering and private IP range validation. This absence of validation allows any unauthenticated attacker to supply specially crafted malicious URLs. By exploiting this, attackers can force the stoatchat server to make requests to internal network resources, thereby facilitating the enumeration of internal services, fingerprinting of applications, and direct access to sensitive instance metadata endpoints. This vulnerability poses a significant risk for information disclosure and could serve as an initial stepping stone for more advanced network compromises, impacting organizations using vulnerable stoatchat deployments.

## Attack Chain

1. An unauthenticated attacker identifies a public-facing stoatchat instance running a version prior to 0.13.5.
2. The attacker discovers the vulnerable `/proxy` or `/embed` endpoints.
3. The attacker crafts an HTTP GET or POST request to one of these endpoints, embedding an internal target URL (e.g., `http://127.0.0.1/admin` or `http://169.254.169.254/latest/meta-data/`) as a parameter.
4. The stoatchat application processes the request, failing to validate the provided URL against internal or private IP ranges.
5. The stoatchat server, acting on the attacker's behalf, initiates an outbound request to the specified internal network resource.
6. The internal resource responds to the stoatchat server, which then relays the response content back to the attacker via the original `/proxy` or `/embed` request.
7. The attacker analyzes the received response to enumerate accessible internal services, identify application banners, or extract cloud instance metadata.
8. The gathered information is then used to plan further attacks, potentially leading to deeper network penetration or data exfiltration.

## Impact

Successful exploitation of CVE-2026-63306 can lead to severe information disclosure within an organization's network. Attackers can remotely enumerate sensitive internal services and their configurations, gain insights into the network topology, and fingerprint internal applications. Critically, the vulnerability allows access to cloud instance metadata endpoints, which often contain highly sensitive credentials, API keys, and configuration data, enabling subsequent privilege escalation or unauthorized access to other cloud resources. While no specific victim count or sectors are detailed, any organization utilizing vulnerable stoatchat versions is at risk of unauthorized access to their internal network infrastructure and sensitive data, potentially leading to significant operational disruption and data breaches.

## Recommendation

* Immediately upgrade all stoatchat instances to version 0.13.5 or newer to remediate CVE-2026-63306.
* Deploy the provided Sigma rule to your SIEM to detect attempted exploitation of the `/proxy` and `/embed` SSRF vulnerability in your webserver logs.
* Implement strong network segmentation to limit internal service exposure and reduce the blast radius of successful SSRF attacks.
* Ensure web application firewalls (WAFs) are configured to detect and block requests attempting to access internal IP addresses or specific metadata endpoints via public-facing application paths.
