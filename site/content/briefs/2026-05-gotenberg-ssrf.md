---
title: Gotenberg SSRF via IPv6 Address Confusion (CVE-2026-45741)
slug: 2026-05-gotenberg-ssrf
description: Gotenberg's `IsPublicIP` function incorrectly classifies IPv6 6to4, NAT64, and deprecated site-local addresses as public IPs, enabling an unauthenticated attacker to reach internal destinations such as cloud metadata services.
date: "2026-05-29T16:52:16Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:lfprojects:mcp_registry:*:*:*:*:*:*:*:*
tags:
  - ssrf
  - gotenberg
  - ipv6
  - cve-2026-45741
vendors:
  - GitHub
products:
  - gotenberg/gotenberg/v8
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-44430
    cvss: 4
    epss: 0.00027
references:
  - https://github.com/advisories/GHSA-86m8-88fq-xfxp
rules:
  - title: Detect Gotenberg SSRF Attempt via IPv6 Prefixes
    description: Detects CVE-2026-45741 exploitation - Outbound HTTP requests to specific IPv4 addresses embedded in IPv6 prefixes known to bypass Gotenberg's private IP protection.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - network_connection
      - windows
  - title: Detect Gotenberg SSRF Attempt via IPv6 Prefixes (Process Creation)
    description: Detects CVE-2026-45741 exploitation - Process creation with command line arguments that may trigger SSRF via IPv6 prefixes.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

A vulnerability exists in Gotenberg version 8 up to 8.32.0 where the `IsPublicIP` function within `pkg/gotenberg/outbound.go` fails to properly classify certain IPv6 addresses, specifically those using 6to4 (RFC 3056), NAT64 (RFC 6052 & RFC 8215), and deprecated site-local (RFC 3879) prefixes. Due to this misclassification, addresses intended for internal or private networks are incorrectly treated as public. This flaw allows an unauthenticated attacker to bypass intended restrictions and potentially access sensitive internal resources. The vulnerability is a variant of CVE-2026-44430 and has been assigned CVE-2026-45741. This poses a risk to deployments that rely on `WithDenyPrivateIPs(true)` to prevent access to internal IPs, particularly when hosted in dual-stack or NAT64-enabled cloud environments.

## Attack Chain

1. An attacker crafts a DNS AAAA record that resolves to an IPv6 address using a 6to4, NAT64, or site-local prefix (e.g., `2002:a9fe:a9fe::`).
2. The attacker sends a request to Gotenberg, specifying a URL with a hostname that resolves to the crafted IPv6 address.
3. Gotenberg's `IsPublicIP` function is called to validate the IP address.
4. The `IsPublicIP` function fails to recognize the IPv6 prefix as internal due to inadequate checks beyond `addr.Unmap()`.
5. The function incorrectly classifies the IPv6 address as a public IP.
6. Gotenberg proceeds to make an outbound HTTP request to the internal IPv4 address embedded within the IPv6 address (e.g., `169.254.169.254`).
7. The target service (e.g., AWS IMDS) responds with sensitive data such as IAM credentials.
8. The Chromium URL convert route within Gotenberg returns the full response as a PDF, exfiltrating the sensitive data to the attacker (full-read SSRF).

## Impact

This SSRF vulnerability allows an unauthenticated attacker to access internal resources, such as cloud metadata services (AWS IMDS, GCP metadata server, Azure Instance Metadata Service), and potentially leak sensitive information, including IAM credentials. This can lead to privilege escalation, data breaches, and unauthorized access to cloud resources. The vulnerability affects Gotenberg deployments configured to deny private IPs (`WithDenyPrivateIPs(true)`) and hosted in dual-stack or NAT64-enabled environments.

## Recommendation

*   Apply the patch or upgrade to a version of Gotenberg greater than 8.32.0 that includes the fix for CVE-2026-45741 to mitigate the IPv6 address misclassification.
*   Deploy the Sigma rule "Detect Gotenberg SSRF Attempt via IPv6 Prefixes" to detect attempts to exploit this vulnerability by monitoring outbound requests to known internal IP ranges via IPv6 addresses with the specified prefixes.
*   Review and harden network configurations to prevent or limit the impact of successful SSRF attacks, even if the application-level vulnerability is present.
*   Implement network segmentation to limit the blast radius of any potential SSRF attack and restrict access to sensitive internal resources.
