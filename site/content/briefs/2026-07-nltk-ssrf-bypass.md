---
title: NLTK pathsec DNS Rebinding SSRF Filter Bypass
slug: 2026-07-nltk-ssrf-bypass
description: A DNS rebinding vulnerability in the NLTK pathsec module allows attackers to bypass SSRF filters and access restricted internal resources by manipulating hostname resolution during the validation and connection phases.
date: "2026-07-31T19:29:56Z"
lastmod: "2026-07-31T19:30:20Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - ssrf
  - dns-rebinding
  - vulnerability
  - path-traversal
  - arbitrary-file-read
  - library-vulnerability
products:
  - NLTK (<= 3.9.4)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The vulnerability stems from a race condition or logic flaw involving independent DNS resolutions... An attacker can exploit this via DNS rebinding.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-qvv7-cg9c-w4x3
  - CVE-2026-12075
  - https://github.com/advisories/GHSA-xh95-f55m-82fw
  - https://nvd.nist.gov/vuln/detail/CVE-2026-12074
updates:
  - at: "2026-07-31T19:30:20Z"
    level: L2
    summary: 'merged source coverage: NLTK FramenetCorpusReader Path Traversal Vulnerability'
    sources:
      - ghsa
    source_urls:
      - https://github.com/advisories/GHSA-xh95-f55m-82fw
---

The NLTK library (version 3.9.4 and earlier) contains a critical SSRF filter bypass vulnerability in its `nltk.pathsec` module, specifically within the `urlopen` function and underlying utilities like `nltk.data.load`. The vulnerability stems from a race condition or logic flaw involving independent DNS resolutions: `validate_network_url` performs an initial check against forbidden IP ranges (loopback, private, link-local), but the subsequent HTTP connection initiated by `urllib` performs a second, independent DNS resolution.

An attacker can exploit this via DNS rebinding by providing a domain that returns a legitimate public IP during the first check, and an unauthorized internal or loopback IP during the second check. Even when `nltk.pathsec.ENFORCE` is set to `True`, the security control is rendered ineffective. This allows for non-blind SSRF, enabling attackers to exfiltrate data from internal interfaces, administrative consoles, or cloud metadata services (e.g., 169.254.169.254), leading to potential credential theft or deeper network penetration.

## Attack Chain

1. Attacker sets up a malicious authoritative DNS server for a domain (e.g., rebind.attacker.test) with a TTL of 0.
2. Attacker provides the malicious domain as an input to a function utilizing `nltk.pathsec.urlopen`.
3. `nltk.pathsec` calls `_resolve_hostname`, which performs the first DNS lookup; the attacker's server returns a benign public IP.
4. The validation logic compares the benign IP against blocklists, deems the URL safe, and allows the request to proceed.
5. `urlopen` passes the raw hostname to the `urllib` connection layer.
6. `urllib` initiates a second DNS lookup to establish the actual TCP connection.
7. The attacker's DNS server returns a loopback or internal private IP for this second resolution.
8. The application establishes a connection to the sensitive internal resource and returns the response body to the attacker.

## Impact

The vulnerability facilitates full-response (non-blind) SSRF. Attackers can read data from internal services protected by perimeter firewalls. In cloud-hosted environments, this is frequently leveraged to query instance metadata services for IAM roles, API keys, and service tokens, leading to full compromise of the affected application's identity and subsequent unauthorized access to broader cloud infrastructure.

## Recommendation

* Update NLTK to the latest patched version that pins the resolved IP address across the validation and connection phases.
* If patching is not immediately possible, restrict outbound network access from servers running NLTK processing tasks to prevent connections to internal RFC1918 and link-local address spaces.
* Implement host-level egress filtering (e.g., using `iptables` or local firewall rules) to explicitly block NLTK-related service accounts from initiating connections to 127.0.0.1 or 169.254.169.254.
