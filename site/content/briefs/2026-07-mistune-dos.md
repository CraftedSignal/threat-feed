---
title: Mistune Markdown Parser Vulnerable to CPU Exhaustion DoS (CVE-2026-49851)
slug: 2026-07-mistune-dos
description: The Mistune Python Markdown parser is vulnerable to a CPU exhaustion Denial of Service (DoS) attack, identified as CVE-2026-49851, due to a superlinear (O(n²)) parsing behavior in the `parse_link_text` function when processing specially crafted input containing repeated square brackets, allowing an attacker to significantly degrade application performance with a small payload.
date: "2026-07-09T23:53:38Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - denial-of-service
  - python
  - library
  - vulnerability
  - markdown
vendors:
  - Mistune
products:
  - mistune (< 3.3.0)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: Mistune is vulnerable to a CPU exhaustion DoS due to superlinear (approximately O(n²)) behavior in parse_link_text. An attacker-controlled Markdown input can therefore trigger excessive CPU usage with a very small payload.
    confidence_band: high
cves:
  - id: CVE-2026-49851
    cvss: 7.5
    epss: 0.0035
references:
  - https://github.com/advisories/GHSA-qcq2-496w-v96p
---

A significant CPU exhaustion Denial of Service (DoS) vulnerability, tracked as CVE-2026-49851, has been identified in the Mistune Python Markdown parser. This vulnerability stems from inefficient parsing logic within the `parse_link_text` function, which exhibits superlinear (approximately O(n²)) time complexity when processing specific malicious inputs. Attackers can exploit this by submitting Markdown content containing a large number of consecutive `[` characters. This forces Mistune to repeatedly scan and re-scan the input, leading to excessive CPU utilization. The issue affects Mistune versions prior to 3.3.0 and poses a critical risk to any application that uses Mistune to process user-supplied Markdown, including web applications, API services, and documentation rendering systems.

## Attack Chain

1. An attacker crafts a malicious Markdown payload consisting of a large number of consecutive opening square bracket characters (e.g., `s = "[" * 6400`).
2. The malicious Markdown payload is delivered to a target application that uses Mistune for parsing user-supplied content, via HTTP request body, API input, or other means.
3. The application processes the input, invoking the `mistune.create_markdown()` function to parse the content.
4. During parsing, the `InlineParser.parse()` function in `mistune/inline_parser.py` attempts to interpret the malformed link text.
5. When `parse_link()` fails to find a valid link, the outer loop in `InlineParser.parse()` advances only one character at a time.
6. Each failed attempt triggers `parse_link_text()` which performs an O(n) scan to the end of the string searching for a closing `]`.
7. The combination of the O(n) scan in `parse_link_text()` within an outer loop that iterates O(n) times results in a total O(n²) CPU exhaustion, causing the application to become unresponsive or crash.

## Impact

Successful exploitation of CVE-2026-49851 can lead to a denial of service for any application that parses user-supplied Markdown using vulnerable versions of Mistune. This includes web applications handling comments or posts, API services processing Markdown content, and documentation rendering systems. With a relatively small malicious payload (e.g., 6,400 characters, approximately 6 KB), an attacker can cause CPU exhaustion for multiple seconds on the targeted server, significantly degrading performance or rendering the service completely unavailable. There is no specific victim count or sector mentioned, but any organization using vulnerable Mistune installations in internet-facing applications is at risk.

## Recommendation

* Immediately patch the Mistune library to version 3.3.0 or later to address **CVE-2026-49851**.
* Implement robust input validation and sanitization for all user-supplied Markdown content processed by your applications to prevent malformed inputs that exploit **CVE-2026-49851**.
* Monitor application CPU usage for unexpected spikes as a potential indicator of a DoS attack attempt.
