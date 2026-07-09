---
title: Ruby CSS Parser Vulnerable to SSRF and Local File Disclosure via `read_remote_file`
slug: 2026-07-ruby-css-parser-ssrf-lfi
description: The `css_parser` library, specifically in versions up to and including 2.2.0, is vulnerable to Server-Side Request Forgery (SSRF) and local file disclosure through improper URI validation in the `CssParser::Parser#read_remote_file` method, allowing attackers to access internal network resources or read local files when processing attacker-controlled CSS.
date: "2026-07-09T13:47:12Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - ssrf
  - lfi
  - supply-chain
  - ruby
  - vulnerability
  - web-application
vendors:
  - Premailer
products:
  - css_parser <= 2.2.0
affected_os:
  - Windows
  - Linux
  - macOS
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1592
    technique_name: Gather Victim Host Information
    evidence: An attacker can iterate `file://` targets to enumerate filesystem layout, usernames, installed software, etc.
    confidence_band: high
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1005
    technique_name: Data from Local System
    evidence: The `file://` branch of `read_remote_file` does an unconditional `File.read`, but the contents are then handed back to `add_block!` and fed through the CSS tokenizer...Configuration files written in block-style DSLs (nginx, HCL/Terraform, Caddy, etc.) leak heavily.
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The attacker only needs the ability to land one `@import url(...)` in the CSS that the host application parses.
    confidence_band: high
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Defacement
    evidence: Side-effecting GETs against unprotected internal admin endpoints...Internal services that act on GET (legacy admin panels, debug endpoints, cache busters, queue triggers) execute.
    confidence_band: med
references:
  - https://github.com/advisories/GHSA-9pmc-p236-855h
---

The Ruby `css_parser` library, specifically versions 2.2.0 and earlier, contains a critical vulnerability (SSRF and local file disclosure) within its `CssParser::Parser#read_remote_file` method. This function, utilized by `load_uri!` and the `@import`-following branch of `add_block!`, lacks proper validation, allowing HTTP/HTTPS requests to arbitrary hosts and ports, including internal, loopback, and RFC-1918 addresses. The vulnerability escalates to arbitrary local file disclosure when a malicious HTTP redirect leads to a `file://` URI. This flaw enables attackers to conduct internal network discovery, exfiltrate sensitive data from block-style configuration files, enumerate file existence, and perform Denial of Service attacks via decompression bombs or by triggering side-effecting GET requests on internal services. Applications like Premailer, which hand attacker-influenced CSS with a `base_uri:` option to `css_parser`, are particularly exposed, requiring only a single `@import url(...)` rule in the parsed CSS.

## Attack Chain

1. An attacker crafts a malicious CSS stylesheet containing an `@import url(...)` directive, pointing to an attacker-controlled HTTP/HTTPS server.
2. A vulnerable application, which uses the `css_parser` library (version 2.2.0 or earlier) to process untrusted CSS with a `base_uri:` option (e.g., via Premailer), encounters the malicious `@import` rule.
3. The `css_parser` library's `CssParser::Parser#add_block!` or `Parser#load_uri!` methods invoke `read_remote_file` with the attacker-controlled URL.
4. **SSRF (Internal Network Access):** The `read_remote_file` method makes an HTTP/HTTPS request to an internal target (e.g., `http://127.0.0.1:18080/admin-credentials`). If the response is CSS-shaped, its content can be exfiltrated via the application's output.
5. **Local File Disclosure (LFI) Escalation:** The attacker-controlled server responds with an HTTP 302 redirect, sending a `Location:` header pointing to a `file://` URI (e.g., `Location: file:///etc/nginx/nginx.conf`).
6. `read_remote_file` recursively follows this cross-scheme redirect and directly calls `File.read` on the specified local file path.
7. If the content of the local file is CSS-shaped (e.g., block-style configuration files like nginx configs, HCL, Caddy), it is parsed by `css_parser` and its contents (selectors, declarations) become recoverable via the parser's API.
8. The application then outputs the parsed CSS (e.g., Premailer renders it into HTML), effectively exfiltrating the sensitive local file content to the attacker.

## Impact

The vulnerability in `css_parser` allows for significant impact on systems processing untrusted CSS. Successful exploitation can lead to unauthorized access to internal network resources, including sensitive administrative interfaces and cloud metadata services (e.g., AWS IMDS, GCP/Azure equivalents). It facilitates arbitrary local file disclosure, potentially exposing critical system configurations, API keys, or other sensitive data, particularly from files structured in block-style DSLs (like nginx or HCL configuration files). Attackers can also use this flaw as a file-existence oracle to enumerate system filesystem layouts and installed software. Furthermore, the forced decompression functionality can be abused to trigger Denial of Service conditions through decompression bombs, exhausting system resources.

## Recommendation

* Upgrade the `css_parser` gem to a patched version immediately to remediate CVE-2024-XXXX (CVE ID will be assigned).
* Implement strict input validation and sanitization for all CSS content originating from untrusted sources before it is processed by the `css_parser` library.
* Configure network egress filtering to prevent unexpected outbound connections from application servers to internal IP ranges, loopback addresses, or the internet, for processes that should not initiate such connections.
* Monitor application logs for unusual URI access attempts, particularly those attempting to access `file://` schemes or internal HTTP/HTTPS endpoints from CSS processing functions.
