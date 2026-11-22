---
brief_id: brief-2026-10-23-cacti-command-injection
event_id: brief-2026-10-23-cacti-command-injection
revision: 2
activity_at: "2026-11-22T03:25:51Z"
revision_history:
  - revision: 2
    at: "2026-11-22T03:25:51Z"
    checksum: sha256:dbf79d80f3a44c248752895f8b91e23fc36f641a8c916c2fd3833ddc4a53bf51
    summary: 'added detection rule: Suspicious Cacti Administrative Input'
    changed_fields:
      - affected_products
      - affected_vendors
      - content
      - cpes
      - has_poc
      - lastmod
      - poc_references
      - priority_score
      - priority_signals
      - references
      - rules
      - summary
      - tags
      - title
      - ttps
      - updates
    source_urls:
      - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-KX00007-CVE-2026-39902&utm_source=rss&utm_medium=rss
title: Cacti Authenticated Command Injection (CVE-2026-39902)
slug: 2026-10-cacti-command-injection
description: Cacti versions prior to 1.2.31 are vulnerable to authenticated OS command injection due to an insufficient input blocklist, allowing an authenticated administrator to execute arbitrary commands.
date: "2026-10-23T15:43:15Z"
lastmod: "2026-11-22T03:25:36Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "2"
  rating: A2
  likelihood: roughly even chance
cpes:
  - cpe:2.3:a:cacti:cacti:*:*:*:*:*:*:*:*
has_poc: true
poc_references:
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-KX00007-CVE-2026-39902&utm_source=rss&utm_medium=rss
tags:
  - cve
  - rce
  - command-injection
vendors:
  - Cacti
products:
  - Cacti
product_versions:
  - product: Cacti
    range: < 1.2.31
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: An authenticated admin could save an input_string containing single-quote, redirect operator, or subshell parens, and pass the check.
    confidence_band: high
cves:
  - id: CVE-2026-39902
    cvss: 7.2
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-39902
  - https://cveawg.mitre.org/api/cve/CVE-2026-39902
  - https://github.com/Cacti/cacti/security/advisories/GHSA-c4qp-j9r9-fq24#event-871227
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-KX00007-CVE-2026-39902
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-KX00007-CVE-2026-39902&utm_source=rss&utm_medium=rss
rules:
  - title: Suspicious Cacti Administrative Input
    description: Detects administrative input strings containing shell metacharacters that may bypass filtering, such as quotes, redirection, or subshell syntax.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1059
    data_sources:
      - webserver
rules_count: 1
updates:
  - at: "2026-11-22T03:25:36Z"
    level: L2
    summary: 'added detection rule: Suspicious Cacti Administrative Input'
    sources:
      - sploitus
    source_urls:
      - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-KX00007-CVE-2026-39902&utm_source=rss&utm_medium=rss
---

## Overview
Cacti is an open source performance and fault management framework. In versions prior to 1.2.31, the application's input blocklist for `input_string` failed to adequately filter shell metacharacters, specifically omitting single-quotes, double-quotes, redirect operators, and subshell parentheses or braces.

## Attack Chain
An authenticated administrator can submit a crafted `input_string` containing shell metacharacters that bypasses existing checks. This allows for the injection and execution of arbitrary OS commands on the host system.

## Impact
Successful exploitation results in OS command injection (CWE-78), enabling an authenticated administrator to execute arbitrary commands with the privileges of the Cacti application.

## Recommendation
Upgrade to Cacti version 1.2.31 or later, as this issue has been patched in this version.
