---
title: OpenClaw NPM Package Vulnerable to Python Package Index Redirection
slug: 2026-04-openclaw-index-redirect
description: The openclaw npm package is vulnerable to Python package-index redirection through host execution due to improper sanitization of `PIP_INDEX_URL` and `UV_INDEX_URL`, affecting versions 2026.3.28 and earlier.
date: "2026-04-02T20:57:44Z"
severities:
  - high
tags:
  - openclaw
  - npm
  - package-index-redirection
  - environment-variable-injection
references:
  - https://github.com/advisories/GHSA-7ggg-pvrf-458v
rules:
  - title: Detect OpenClaw Using Suspicious Index URL
    description: Detects the use of openclaw with potentially malicious PIP_INDEX_URL or UV_INDEX_URL environment variables.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1566.001
    data_sources:
      - process_creation
      - linux
  - title: Detect OpenClaw Execution
    description: Detects execution of openclaw, which should be monitored for suspicious activity given the vulnerability.
    platform: sigma
    severity: low
    tactics:
      - initial_access
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

The `openclaw` npm package, versions 2026.3.28 and earlier, contains a vulnerability that allows for the redirection of Python package-index traffic. This is due to insufficient sanitization of the `PIP_INDEX_URL` and `UV_INDEX_URL` environment variables during host execution. An attacker can potentially exploit this vulnerability to redirect package installation traffic to a malicious index, potentially leading to the installation of compromised packages. The scope of this vulnerability is…
