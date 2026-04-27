---
title: Postiz App SSRF Vulnerability via Next.js
slug: 2026-03-postiz-ssrf
description: A high-severity SSRF vulnerability exists in the Postiz application via Next.js, allowing attackers to bypass firewalls, scan internal networks, access sensitive cloud metadata (AWS IMDS), potentially leak instance credentials, and pivot within the internal network.
date: "2026-03-27T15:46:53Z"
severities:
  - high
tags:
  - ssrf
  - vulnerability
  - cloud
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://github.com/advisories/GHSA-vj2p-7pgw-g2wf
ioc_counts:
  ip: 1
rules:
  - title: Detect SSRF Attempt to AWS IMDS
    description: Detects attempts to exploit SSRF vulnerabilities to access the AWS Instance Metadata Service (IMDS) endpoint.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect SSRF Attempt to AWS IMDS - POST
    description: Detects attempts to exploit SSRF vulnerabilities to access the AWS Instance Metadata Service (IMDS) endpoint using a POST request.
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

The Postiz application, a web application built with Next.js, is vulnerable to Server-Side Request Forgery (SSRF). This vulnerability (CVE-2024-34351) allows an attacker to force the server to make HTTP requests to arbitrary domains. Exploitation can lead to internal network reconnaissance, access to sensitive cloud metadata, and potential credential theft. The vulnerability affects Postiz versions 2.0.12 and earlier. Users are advised to upgrade to version 2.21.1 to mitigate the risk. The…
