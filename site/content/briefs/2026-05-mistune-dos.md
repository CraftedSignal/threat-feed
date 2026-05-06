---
title: Mistune Markdown Parser Denial-of-Service Vulnerability
slug: 2026-05-mistune-dos
description: A denial-of-service vulnerability exists in Mistune version 3.2.0 due to excessive parsing and CPU consumption when processing specially crafted reference links, leading to application hangs and service unavailability.
date: "2026-05-06T16:56:26Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - dos
  - vulnerability
  - mistune
vendors:
  - pip
products:
  - mistune (= 3.2.0)
affected_os:
  - Kali-linux-2025.4
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
references:
  - https://github.com/advisories/GHSA-hjph-f4mc-wx4c
rules:
  - title: Mistune DOS - Process CPU Spike
    description: Detects a process consuming excessive CPU resources, indicative of the Mistune DoS vulnerability.
    platform: sigma
    severity: high
    tactics:
      - impact
    techniques:
      - T1499.001
    data_sources:
      - process_creation
      - linux
  - title: Mistune DOS - Request Pattern
    description: Detects suspicious request patterns with excessive escape character sequences, indicative of the Mistune DoS exploit attempt.
    platform: sigma
    severity: medium
    tactics:
      - impact
    techniques:
      - T1499.001
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A denial-of-service vulnerability has been identified in Mistune version 3.2.0, a Python Markdown parser. This vulnerability stems from the `parse_link_title()` function within `helpers.py`, which is susceptible to excessive backtracking and parsing loops when processing malformed reference links. An attacker can exploit this by providing specially crafted Markdown input that causes the application to consume excessive CPU resources, leading to application hangs and service unavailability. Publicly available PoC exploit code demonstrates the vulnerability. This poses a significant threat to applications that rely on Mistune to parse untrusted Markdown content, such as web applications and APIs.

## Attack Chain

1.  An attacker crafts a malicious Markdown document containing specially crafted reference links with excessive escape character sequences.
2.  The attacker submits the malicious Markdown document to a web application or API that uses Mistune for Markdown parsing.
3.  The application calls the `mistune.html()` function to render the Markdown content into HTML.
4.  Within `mistune.html()`, the `parse` method in `mistune/markdown.py` is invoked.
5.  The `parse_ref_link` function in `mistune/block_parser.py` is called to process the reference links.
6.  The `parse_link_title` function in `mistune/helpers.py` is then called to parse the link title.
7.  Due to the malformed reference link structure, `parse_link_title` enters an excessive parsing loop with significant backtracking.
8.  The excessive parsing consumes CPU resources, eventually leading to a denial-of-service condition as the application hangs and becomes unresponsive.

## Impact

Successful exploitation of this vulnerability results in a denial-of-service (DoS) condition. Specifically, the targeted application experiences high CPU usage and ultimately hangs, rendering it unavailable to legitimate users. This can disrupt services, cause financial losses, and damage the reputation of organizations that rely on the affected application. The vulnerability impacts any application using Mistune 3.2.0 to parse untrusted markdown, including web applications and APIs.

## Recommendation

*   Apply mitigations suggested by the vendor, including parsing depth and iteration limits within `parse_link_title()`.
*   Implement input validation to limit reference-link title length, mitigating the impact of excessively long titles.
*   Deploy the Sigma rule `Mistune_DOS_Process_CPU_Spike` to detect processes exhibiting high CPU usage during Markdown parsing.
*   Deploy the Sigma rule `Mistune_DOS_Request_Pattern` to detect suspicious request patterns indicative of the exploit being attempted.
*   Monitor web server logs for suspicious requests containing excessive escape character sequences indicative of the provided PoC exploit.
