---
title: datamodel-code-generator Vulnerable to SSRF Protection Bypass via DNS Rebinding
slug: 2026-07-datamodel-ssrf-bypass
description: The `datamodel-code-generator` tool is vulnerable to a Server-Side Request Forgery (SSRF) protection bypass, identified as CVE-2026-55391, due to a time-of-check/time-of-use (TOCTOU) race condition through DNS rebinding, allowing attackers to access internal services like cloud instance metadata endpoints when processing attacker-influenced URLs.
date: "2026-07-28T21:49:12Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - ssrf
  - dns-rebinding
  - vulnerability
  - supply-chain
  - python
vendors:
  - datamodel-code-generator
products:
  - datamodel-code-generator (<= 0.62.0)
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1564
    technique_name: Hide Artifacts
    evidence: A hostname that resolves to a public IP at validation time and a private IP at connection time (DNS rebinding) bypasses the guard and reaches loopback, link-local cloud-metadata endpoints (`169.254.169.254`), and other internal services
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
    evidence: Consequences include reading cloud instance-metadata credentials (`169.254.169.254`)
    confidence_band: high
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1046
    technique_name: Network Service Scanning
    evidence: port/host probing of the internal network
    confidence_band: high
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1005
    technique_name: Data from Local System
    evidence: the document fetched from the internal target is also parsed and can be reflected into the generated output
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-vx7x-vcc2-c44g
  - https://github.com/koxudaxi/datamodel-code-generator-ghsa-vx7x-vcc2-c44g/pull/1
  - https://gist.github.com/thegr1ffyn/c1d54dd6ff2a4c0d7d0dabe00c4985f4
iocs:
  - type: ip
    value: 169.254.169.254
ioc_counts:
  ip: 1
---

The `datamodel-code-generator` Python library, specifically versions `0.62.0` and earlier, contains a high-severity Server-Side Request Forgery (SSRF) protection bypass vulnerability, tracked as CVE-2026-55391. Discovered by Hamza Haroon (thegr1ffyn), this flaw stems from a time-of-check/time-of-use (TOCTOU) race condition during DNS resolution, allowing a DNS rebinding attack. The library's anti-SSRF guard performs an initial IP validation that passes if a hostname resolves to a public IP; however, the subsequent `httpx` connection performs a separate, unpinned DNS resolution. An attacker can leverage this by controlling a low-TTL DNS record that resolves to a public IP during the validation phase and then switches to a private IP (e.g., `127.0.0.1` or `169.254.169.254`) during the connection phase. This bypasses the intended private network protection, enabling access to internal network services, cloud instance metadata APIs, and internal host/port probing when the tool processes attacker-influenced URLs, such as those provided via the `--url` argument or remote `$ref` references in schemas. The vulnerability is present in versions up to `0.62.0` and was fixed in version `0.63.0`.

## Attack Chain

1. An attacker registers a domain name (e.g., `attacker.com`) and configures its DNS records with a very low Time-To-Live (TTL).
2. The attacker configures the domain to initially resolve to a public, internet-routable IP address.
3. The attacker influences a victim's `datamodel-code-generator` instance (e.g., in a CI pipeline or local development environment) to fetch a URL pointing to `http://attacker.com/schema.json` via the `--url` command-line argument or a remote `$ref` within a schema.
4. The `datamodel-code-generator`'s `_validate_url_for_fetch()` function performs the initial DNS resolution of `attacker.com` (resolution #1). The public IP passes the SSRF guard's check.
5. Between validation and connection, the attacker rapidly changes the DNS record for `attacker.com` to resolve to a private IP address (e.g., `127.0.0.1`, `169.254.169.254`, or another internal network address).
6. The `httpx.get()` function within `datamodel-code-generator` performs its own, independent DNS resolution for `attacker.com` (resolution #2). Due to the low TTL and attacker's control, this resolution now returns the private IP address.
7. `httpx` connects to the private IP address, bypassing the initial validation and establishing an SSRF connection to an internal service or resource.
8. The attacker gains unauthorized access to internal HTTP services, reads cloud instance metadata credentials, or conducts internal network reconnaissance.

## Impact

This Server-Side Request Forgery (SSRF) vulnerability (CWE-918) via a time-of-check/time-of-use (TOCTOU) resolution gap (CWE-367) affects any service or CI pipeline that executes `datamodel-code-generator` against attacker-influenced URLs. Successful exploitation allows attackers to bypass network segmentation controls, leading to the unauthorized disclosure of sensitive information such as cloud instance-metadata credentials (e.g., from `169.254.169.254`). Attackers can also access internal-only HTTP services, perform port and host probing of the internal network, and reflect the content fetched from internal targets into the generated output, potentially exposing internal data. While specific victim counts are not available, the widespread use of `datamodel-code-generator` implies a broad attack surface for organizations using the tool in potentially vulnerable configurations.

## Recommendation

* Upgrade `datamodel-code-generator` to version `0.63.0` or later immediately to remediate CVE-2026-55391.
* Implement strict network egress filtering on systems running `datamodel-code-generator` to restrict outbound connections to only necessary and trusted external destinations, blocking access to private IP ranges, especially `169.254.169.254`.
* Monitor DNS query logs for suspicious or rapid changes in IP resolution for external domains accessed by internal tools.
* Avoid running `datamodel-code-generator` in environments where `--url` parameters or remote `$ref` references can be influenced by untrusted external input.
