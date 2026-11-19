---
brief_id: brief-2026-10-30-virtualenv-command-injection-08b06e4e
event_id: brief-2026-10-30-virtualenv-command-injection-08b06e4e
revision: 2
activity_at: "2026-11-19T23:07:23Z"
revision_history:
  - revision: 2
    at: "2026-11-19T23:07:23Z"
    checksum: sha256:1ac25914c2691a71a93d56e1cbdbad3f167881e2128df9e69bac0ffa8ad3d06f
    summary: OS posix
    changed_fields:
      - affected_os
      - affected_products
      - affected_vendors
      - content
      - cpes
      - cves
      - lastmod
      - priority
      - priority_score
      - priority_signals
      - references
      - summary
      - tags
      - title
      - updates
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-113718
title: 'virtualenv: Xonsh activation code injection (CVE-2026-113718)'
slug: 2026-10-virtualenv-command-injection-08b06e4e
description: A command injection vulnerability in the virtualenv POSIX xonsh activation process allows for arbitrary command execution when a user sources an activate.xsh script containing attacker-influenced data in an environment using legacy multibyte codecs.
date: "2026-10-30T18:48:33Z"
lastmod: "2026-11-19T23:06:49Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: not_observed
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
cpes:
  - cpe:2.3:a:virtualenv:virtualenv:*:*:*:*:*:*:*:*
tags:
  - attack.execution
  - attack.t1059
vendors:
  - pypa
products:
  - virtualenv
product_versions:
  - product: virtualenv
    range: '>= 21.3.0, < 21.14.9'
affected_os:
  - POSIX
cves:
  - id: CVE-2026-113718
    epss: 0.00242
    kev_status: "false"
references:
  - https://github.com/pypa/virtualenv/blob/a795ab116356afde11039cf2763d77e8a06da738/src/virtualenv/activation/xonsh/__init__.py
  - https://github.com/pypa/virtualenv/pull/3432
  - https://github.com/advisories/GHSA-394h-qwmc-48pf
  - https://cveawg.mitre.org/api/cve/CVE-2026-113718
  - https://nvd.nist.gov/vuln/detail/CVE-2026-113718
updates:
  - at: "2026-11-19T23:06:49Z"
    level: L1
    summary: OS posix
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-113718
---

## Overview
A vulnerability exists in virtualenv versions prior to 21.14.9 related to the POSIX xonsh activation script (activate.xsh). The quote() function uses repr() to write non-ASCII prompt or destination data into the script. In environments configured with legacy multibyte codecs (e.g., GBK or Big5), a UTF-8 trail byte can consume the backslash escape character preceding a quote, allowing the literal to close prematurely and enabling the execution of attacker-influenced statements when the user sources the generated activate.xsh script.

## Attack Chain
1. virtualenv generates an activate.xsh file using repr() for non-ASCII data.
2. In environments utilizing legacy multibyte codecs, the backslash character is consumed by a UTF-8 trail byte.
3. The quote character terminates the string literal incorrectly.
4. Sourcing the resulting script leads to the execution of injected statements.

## Impact
Successful exploitation allows for arbitrary code execution with the privileges of the user who sources the generated script.

## Recommendation
Upgrade the virtualenv package to version 21.14.9 or later.
