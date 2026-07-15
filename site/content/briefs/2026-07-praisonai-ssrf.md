---
title: PraisonAI web_crawl Tool Vulnerable to DNS Rebinding SSRF (CVE-2026-61430)
slug: 2026-07-praisonai-ssrf
description: PraisonAI versions prior to 1.6.78 are vulnerable to server-side request forgery (SSRF) within its web_crawl tool, allowing attackers to bypass hostname validation using DNS rebinding and retrieve sensitive internal HTTP response bodies from private or loopback services.
date: "2026-07-15T12:28:48Z"
lastmod: "2026-07-15T12:34:07Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - ssrf
  - dns-rebinding
  - vulnerability
  - web-application
  - code-injection
  - remote-code-execution
  - python
  - cve
  - webhook-bypass
  - improper-authentication
  - application-vulnerability
  - path-traversal
vendors:
  - MervinPraison
products:
  - PraisonAI
  - PraisonAI (< 1.6.78)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: PraisonAI before 1.6.78 contains a server-side request forgery vulnerability in the web_crawl tool
    confidence_band: high
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1082
    technique_name: System Information Discovery
    evidence: retrieve internal HTTP response bodies from private or loopback services
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Attackers can inject arbitrary Python expressions through the deploy.api.host and agents_file configuration parameters that execute when the generated server starts or handles requests.
    confidence_band: high
cves:
  - id: CVE-2026-61430
    cvss: 8.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-61430
  - https://github.com/MervinPraison/PraisonAI/security/advisories/GHSA-qg25-6gc4-48mg
  - https://www.vulncheck.com/advisories/praisonai-before-dns-rebinding-ssrf-via-web-crawl
  - https://nvd.nist.gov/vuln/detail/CVE-2026-61433
  - https://github.com/MervinPraison/PraisonAI/commit/1620b49f36945d8cc8ee5635b906c960df5097a0
  - https://github.com/MervinPraison/PraisonAI/security/advisories/GHSA-79fv-7hq9-w7xg
  - https://www.vulncheck.com/advisories/praisonai-before-code-injection-via-api-deployment-generator
  - https://nvd.nist.gov/vuln/detail/CVE-2026-61436
  - https://github.com/MervinPraison/PraisonAI/commit/2a855c470077c7d2e2479a575f7ef7f548d51c33
  - https://github.com/MervinPraison/PraisonAI/commit/846568c7a5d8ce9e71e56e4c213f027c04909753
  - https://github.com/MervinPraison/PraisonAI/security/advisories/GHSA-7c92-x8vg-4258
  - https://www.vulncheck.com/advisories/praisonai-before-missing-webhook-signature-verification
  - https://nvd.nist.gov/vuln/detail/CVE-2026-61443
  - https://github.com/MervinPraison/PraisonAI/security/advisories/GHSA-c44f-37qr-gw3f
  - https://www.vulncheck.com/advisories/praisonai-before-remote-code-execution-via-skilltools
rules:
  - title: Detects CVE-2026-61443 Exploitation - PraisonAI Script Execution from Unusual Paths
    description: Detects CVE-2026-61443 exploitation by identifying script interpreters (like Python) executing scripts using absolute paths outside of expected application directories, which can indicate unauthorized remote code execution in PraisonAI.
    platform: sigma
    severity: high
    tactics:
      - execution
      - impact
    techniques:
      - T1059
      - T1059.006
      - T1505.003
    data_sources:
      - process_creation
      - windows
rules_count: 1
updates:
  - at: "2026-07-15T12:30:05Z"
    level: L2
    summary: 'merged source coverage: PraisonAI Code Injection Vulnerability via Configuration Parameters (CVE-2026-61433)'
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-61433
  - at: "2026-07-15T12:31:56Z"
    level: L2
    summary: 'merged source coverage: CVE-2026-61436: PraisonAI Svix Webhook Signature Bypass'
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-61436
  - at: "2026-07-15T12:34:07Z"
    level: L2
    summary: 'added detection rule: Detects CVE-2026-61443 Exploitation - PraisonAI Script Execution from Unusual Paths'
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-61443
---

PraisonAI, an artificial intelligence platform, contains a critical server-side request forgery (SSRF) vulnerability, identified as CVE-2026-61430, affecting versions prior to 1.6.78. This flaw resides within the `web_crawl` tool, which is designed to validate hostnames during an initial check but then re-resolves them without IP pinning at the connection phase. Attackers can leverage DNS rebinding techniques to exploit this time-of-check-time-of-use (TOCTOU) vulnerability. By manipulating DNS resolution, an attacker can trick the `web_crawl` tool into making requests to internal private or loopback services, even if the initial hostname appears legitimate. The successful exploitation of this vulnerability allows adversaries to retrieve internal HTTP response bodies, potentially leading to information disclosure, reconnaissance of internal networks, and further compromise.

## Attack Chain

1. An attacker identifies a PraisonAI instance running a vulnerable version (prior to 1.6.78) with the `web_crawl` tool exposed.
2. The attacker sets up a malicious DNS server configured to perform DNS rebinding, capable of rapidly changing the IP address associated with a controlled domain.
3. The attacker crafts a request to the PraisonAI `web_crawl` tool, providing a hostname that is initially configured to resolve to a public IP address controlled by their malicious DNS server.
4. PraisonAI's `web_crawl` tool performs an initial DNS resolution and hostname validation. The hostname resolves to the public IP, and the validation check passes.
5. Before or during the connection establishment phase, the attacker's malicious DNS server quickly updates the DNS record for the same hostname, causing it to re-resolve to an internal IP address (e.g., 127.0.0.1, 192.168.x.x, or another private network address) with a very short time-to-live (TTL).
6. The `web_crawl` tool connects to the newly re-resolved internal IP address without performing a secondary hostname or IP validation, effectively bypassing the intended SSRF protection mechanism.
7. The `web_crawl` tool fetches the HTTP response body from the internal service located at the re-resolved internal IP address.
8. The internal HTTP response body is returned to the attacker as part of the `web_crawl` tool's output, thereby exposing sensitive internal information such as configuration data, API keys, or application secrets.

## Impact

Successful exploitation of CVE-2026-61430 allows attackers to access internal network resources that should not be publicly exposed. This can lead to the retrieval of sensitive HTTP response bodies from private or loopback services, enabling deep reconnaissance of an organization's internal infrastructure. Attackers can map internal networks, discover hidden services, access administrative interfaces, or exfiltrate sensitive data from internal applications. While no specific victim counts or sectors are detailed in the advisory, any organization utilizing vulnerable PraisonAI instances faces a high risk of information disclosure and potential lateral movement within their network.

## Recommendation

* Upgrade PraisonAI to version 1.6.78 or later immediately to patch CVE-2026-61430.
* Implement network segmentation to restrict PraisonAI's access to only necessary external and internal resources.
* Monitor outbound DNS queries from web application servers for unusual re-resolutions to private IP ranges, which may indicate DNS rebinding attempts.
* Implement web application firewalls (WAFs) or API gateways to filter and inspect requests to the `web_crawl` tool, looking for suspicious hostnames or patterns indicative of SSRF attempts.
