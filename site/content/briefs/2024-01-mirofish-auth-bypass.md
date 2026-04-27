---
title: 666ghj MiroFish REST API Authentication Bypass (CVE-2026-7042)
slug: 2024-01-mirofish-auth-bypass
description: A missing authentication vulnerability (CVE-2026-7042) exists in 666ghj MiroFish up to version 0.1.2, allowing remote attackers to bypass authentication via manipulation of the REST API Endpoint's create_app function.
date: "2024-01-03T12:00:00Z"
severities:
  - high
tags:
  - cve-2026-7042
  - authentication-bypass
  - rest-api
vendors:
  - 666ghj
products:
  - MiroFish
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-7042
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-7042
rules:
  - title: Detect Anomalous HTTP Method Usage
    description: Detects the use of unusual HTTP methods which can indicate an attempt to exploit web application vulnerabilities
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Web Request to backend/app/__init__.py
    description: Detects requests to the vulnerable file backend/app/__init__.py which can indicate an attempt to exploit CVE-2026-7042
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A critical authentication bypass vulnerability, tracked as CVE-2026-7042, has been identified in 666ghj MiroFish software up to version 0.1.2. The vulnerability lies within the `create_app` function of the `backend/app/__init__.py` file, which manages the REST API Endpoint. A remote attacker can exploit this flaw by manipulating specific parameters within API requests, effectively bypassing authentication mechanisms. This allows unauthorized access to sensitive functionalities and data. Public…
