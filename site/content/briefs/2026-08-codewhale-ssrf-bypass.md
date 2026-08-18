---
title: SSRF Bypass in CodeWhale via DNS Pinning TOCTOU
slug: 2026-08-codewhale-ssrf-bypass
description: CodeWhale versions before 0.8.64 contain a time-of-check-time-of-use vulnerability in DNS pinning logic, allowing attackers to bypass SSRF mitigations and access internal resources.
date: "2026-08-18T16:55:56Z"
lastmod: "2026-08-18T16:56:24Z"
type: advisory
types:
  - advisory
severities:
  - high
vendors:
  - Hmbown
products:
  - CodeWhale
  - CodeWhale (0.8.64)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1562.001
    technique_name: 'Impair Defenses: Disable or Modify System Firewall'
    evidence: Attackers can manipulate DNS responses to fail initial resolution checks and succeed on secondary requests, allowing requests to internal IP addresses and bypassing SSRF mitigations.
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: A malicious .codewhale/config.toml file in a cloned repository can specify paths outside the workspace that are read and injected into the AI system prompt for exfiltration.
    confidence_band: high
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1048
    technique_name: Exfiltration Over Alternative Protocol
    evidence: The contents of these files are subsequently injected into the AI system prompt, providing a mechanism for an attacker to exfiltrate sensitive data.
    confidence_band: high
cves:
  - id: CVE-2026-75856
    cvss: 8.6
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-75856
  - https://github.com/Hmbown/CodeWhale/security/advisories/GHSA-6v2g-fpxh-pmmh
  - https://www.vulncheck.com/advisories/codewhale-before-ssrf-bypass-via-dns-pinning-toctou
  - https://nvd.nist.gov/vuln/detail/CVE-2026-75859
  - https://github.com/Hmbown/CodeWhale/security/advisories/GHSA-62f5-cp2p-vq95
  - https://www.vulncheck.com/advisories/codewhale-before-arbitrary-file-read-via-instructions
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Upgrade CodeWhale to version 0.8.64 or later.
      owner: IT Operations
      due: 48h
      evidence: Vendor advisory indicates fix in version 0.8.64.
updates:
  - at: "2026-08-18T16:56:24Z"
    level: L2
    summary: added coverage for CodeWhale (0.8.64)
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-75859
---

CodeWhale versions before 0.8.64 are susceptible to a server-side request forgery (SSRF) bypass vulnerability (CVE-2026-75856). The flaw resides in the product's DNS pinning logic, which fails to correctly implement protection against time-of-check-time-of-use (TOCTOU) attacks. In a standard secure configuration, an application validates a hostname's resolution to ensure it does not map to an internal, sensitive, or restricted IP address before proceeding with the request. 

In this vulnerability, an attacker can manipulate DNS responses such that the initial resolution check - used by CodeWhale to validate the target - succeeds as a benign, external address, while the subsequent actual request resolves to an unauthorized internal address. This bypasses existing SSRF mitigations. If successfully exploited, an attacker could interact with internal services that are not exposed to the public internet, potentially leading to unauthorized data exfiltration or interaction with local network infrastructure.

## Attack Chain

1. The attacker configures a malicious DNS server under their control to serve dynamic responses for a specific domain.
2. The attacker triggers CodeWhale to initiate a request to a URL controlled by the attacker.
3. CodeWhale performs an initial DNS lookup of the malicious domain to validate the target address for SSRF protection.
4. The attacker's DNS server responds with a legitimate external IP address to pass the initial validation check.
5. CodeWhale, having validated the address, initiates the secondary connection request to the domain.
6. The attacker's DNS server provides a different, restricted internal IP address (e.g., 127.0.0.1 or 10.x.x.x) for the secondary request.
7. CodeWhale uses the internal IP address for the connection, bypassing the previously applied SSRF checks.
8. The underlying application interacts with the internal resource, facilitating unauthorized access or exfiltration.

## Impact

Successful exploitation allows an unauthenticated, remote attacker to bypass SSRF mitigations. This effectively grants the ability to perform requests against internal-only resources, such as internal web services, metadata services, or databases that are inaccessible from the external network. The impact includes potential compromise of internal data, unauthorized control over internal systems, and circumvention of network segmentation security policies.

## Recommendation

Prioritize the following actions to address CVE-2026-75856:
* Upgrade CodeWhale to version 0.8.64 or later immediately.
* Audit application access logs for unexpected outbound requests to private or internal IP ranges originating from CodeWhale services.
* If upgrading is not immediately possible, restrict the outgoing network access of the CodeWhale service to only necessary, explicitly allowlisted external endpoints.
