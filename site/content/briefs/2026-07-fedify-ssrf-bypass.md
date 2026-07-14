---
title: Fedify SSRF Mitigation Bypass via Incomplete IPv4 Validation (CVE-2026-50131)
slug: 2026-07-fedify-ssrf-bypass
description: Fedify's `validatePublicUrl()` function, intended to mitigate Server-Side Request Forgery (SSRF), contains an incomplete IPv4 validation logic. It incorrectly treats several special-use, reserved, multicast, benchmarking, and carrier-grade NAT IPv4 ranges as valid public destinations, allowing an attacker to bypass the SSRF protection and cause the Fedify server to initiate requests to internal or non-public network ranges when processing attacker-controlled ActivityPub object, activity, document, or media URLs.
date: "2026-07-14T19:20:16Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - ssrf
  - incomplete-fix
  - bypass
  - network-access
  - vulnerability
  - fedify
  - npm
vendors:
  - Fedify
products:
  - '@fedify/fedify (versions >= 0.11.2 < 1.9.12)'
  - '@fedify/fedify (versions >= 1.10.0 < 1.10.11)'
  - '@fedify/fedify (versions >= 2.0.0 < 2.0.19)'
  - '@fedify/fedify (versions >= 2.1.0 < 2.1.15)'
  - '@fedify/fedify (versions >= 2.2.0 < 2.2.4)'
  - '@fedify/vocab-runtime (versions < 2.0.19)'
  - '@fedify/vocab-runtime (versions >= 2.1.0 < 2.1.15)'
  - '@fedify/vocab-runtime (versions >= 2.2.0 < 2.2.4)'
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: This may allow an attacker-controlled ActivityPub object or media URL to cause a Fedify server to initiate requests to non-public or special-use network ranges, depending on the deployment environment and network routing.
    confidence_band: high
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1046
    technique_name: Network Service Discovery
    evidence: This may allow an attacker-controlled ActivityPub object or media URL to cause a Fedify server to initiate requests to non-public or special-use network ranges, depending on the deployment environment and network routing.
    confidence_band: high
cves:
  - id: CVE-2026-50131
    cvss: 8.6
    epss: 0.00269
references:
  - https://github.com/advisories/GHSA-xw9q-2mv6-9fr8
rules:
  - title: Detects CVE-2026-50131 Exploitation - Outbound Connection to Fedify SSRF Bypass Ranges
    description: Detects CVE-2026-50131 exploitation - outbound network connections originating from a Fedify server to specific special-use IPv4 ranges that are incorrectly validated as public by Fedify's isValidPublicIPv4Address() function, indicating potential Server-Side Request Forgery (SSRF) exploitation.
    platform: sigma
    severity: high
    tactics:
      - discovery
      - initial_access
    techniques:
      - T1046
      - T1190
    data_sources:
      - network_connection
      - linux
rules_count: 1
---

A recently disclosed vulnerability, CVE-2026-50131, impacts Fedify's Server-Side Request Forgery (SSRF) protection mechanism. Following an earlier SSRF fix (GHSA-p9cg-vqcc-grcx), Fedify introduced `validatePublicUrl()` to ensure outbound fetches are directed only to public URLs. However, the underlying `isValidPublicIPv4Address()` function contains an incomplete implementation for identifying non-public IPv4 address ranges. While it correctly blocks common private ranges like `10.0.0.0/8` and `192.168.0.0/16`, it fails to classify several special-use, reserved, multicast, benchmarking, and carrier-grade NAT IPv4 ranges (e.g., `100.64.0.0/10`, `198.18.0.0/15`, `224.0.0.0/4`, `240.0.0.0/4`) as non-public. This flaw allows an attacker to craft specific ActivityPub object, activity, document, or media URLs that, when processed by a vulnerable Fedify instance, can force the server to make outbound connections to internal or restricted network segments, bypassing the intended SSRF protection. This issue affects various versions of `@fedify/fedify` and `@fedify/vocab-runtime`, posing a significant risk for internal network reconnaissance and potential access to sensitive services.

## Attack Chain

1. An attacker crafts a malicious ActivityPub object, activity, document, or media URL (e.g., `http://100.64.0.1/internal_service_endpoint`) that embeds an IP address from one of the incorrectly validated special-use IPv4 ranges.
2. The attacker delivers this malicious URL to a vulnerable Fedify instance through a legitimate input channel, such as publishing an ActivityPub post or updating a profile that the Fedify server is configured to fetch.
3. The Fedify server begins processing the received ActivityPub content, triggering its internal logic to fetch the remote URL specified by the attacker.
4. Before making the outbound request, the Fedify server's `validatePublicUrl()` function invokes `isValidPublicIPv4Address()` to determine if the destination IP is public.
5. Due to the incomplete validation logic in `isValidPublicIPv4Address()`, the attacker-specified special-use IPv4 address (e.g., `100.64.0.1`) is incorrectly classified as a "public" destination.
6. Believing the destination to be public, the Fedify server proceeds to initiate an outbound network connection from its internal network to the attacker-controlled special-use IP address.
7. This outbound connection bypasses the intended SSRF protection, allowing the Fedify server to communicate with internal services or other non-public resources within the target's network that are reachable via the special-use IP range.
8. The attacker can then use this unauthorized connection to perform internal network reconnaissance, gather sensitive information, or interact with services not intended for external exposure, achieving goals like network mapping, data exfiltration, or unauthorized access.

## Impact

Successful exploitation of CVE-2026-50131 allows attackers to bypass Fedify's SSRF protection, leading to severe consequences for the compromised organization. Attackers can force Fedify servers to initiate requests to internal network resources that should be inaccessible from external sources. This can facilitate internal network reconnaissance, allowing the attacker to map an organization's network topology and identify other vulnerable internal services. Depending on the network configuration and the specific services running, this could lead to unauthorized access to sensitive data, internal system compromise, or further lateral movement within the network. The vulnerability acts as a gateway to an organization's internal infrastructure, circumventing a critical security control.

## Recommendation

* **Patch CVE-2026-50131:** Immediately update all `@fedify/fedify` and `@fedify/vocab-runtime` installations to versions that address CVE-2026-50131. Refer to the affected products list for specific patched versions.
* **Implement Network Monitoring:** Deploy the Sigma rule "Detects CVE-2026-50131 Exploitation - Outbound Connection to Fedify SSRF Bypass Ranges" to your SIEM. Configure network connection logging for all servers hosting Fedify to capture outbound connections, particularly those to the IOC IP addresses listed in this brief.
* **Review Network Segmentation:** Ensure robust network segmentation is in place to limit the impact of potential SSRF vulnerabilities, even if a bypass occurs.
