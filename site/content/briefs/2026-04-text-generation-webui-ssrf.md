---
title: text-generation-webui SSRF Vulnerability (CVE-2026-35486)
slug: 2026-04-text-generation-webui-ssrf
description: The text-generation-webui application before version 4.3 is vulnerable to server-side request forgery (SSRF) due to insufficient validation of user-supplied URLs by the superbooga and superboogav2 RAG extensions, potentially leading to credential theft and internal network reconnaissance.
date: "2026-04-07T16:16:26Z"
severities:
  - high
tags:
  - ssrf
  - text-generation-webui
  - cve-2026-35486
  - cloud
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-35486
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-35486
  - https://github.com/oobabooga/text-generation-webui/security/advisories/GHSA-jvrj-w5hq-6cp2
ioc_counts:
  email: 1
  url: 1
rules:
  - title: Detect text-generation-webui SSRF Attempt
    description: Detects attempts to exploit the text-generation-webui SSRF vulnerability (CVE-2026-35486) by monitoring requests to cloud metadata endpoints.
    platform: sigma
    severity: high
    tactics:
      - initial_access
      - persistence
    techniques:
      - T1190
      - T1552.005
    data_sources:
      - webserver
      - linux
  - title: Detect text-generation-webui RAG extensions URL fetch
    description: Detects text-generation-webui RAG extensions fetching URL.
    platform: sigma
    severity: low
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

The text-generation-webui application is an open-source web interface for running Large Language Models (LLMs). Prior to version 4.3, the superbooga and superboogav2 RAG (Retrieval-Augmented Generation) extensions are susceptible to a Server-Side Request Forgery (SSRF) vulnerability. These extensions fetch user-provided URLs using the `requests.get()` function without proper validation. Specifically, there are no checks for URL schemes (e.g., `file://`, `gopher://`), IP address filtering, or…
