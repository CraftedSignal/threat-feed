---
title: NVIDIA Triton Inference Server Denial-of-Service Vulnerability (CVE-2026-24146)
slug: 2026-04-nvidia-triton-dos
description: NVIDIA Triton Inference Server is vulnerable to denial of service due to insufficient input validation that, when combined with a large number of outputs, can cause a server crash.
date: "2026-04-07T18:16:39Z"
severities:
  - high
tags:
  - cve-2026-24146
  - denial-of-service
  - nvidia
  - triton
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1498
    technique_name: Denial of Service
cves:
  - id: CVE-2026-24146
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-24146
  - https://nvidia.custhelp.com/app/answers/detail/a_id/5816
  - https://www.cve.org/CVERecord?id=CVE-2026-24146
rules:
  - title: Detect Suspicious Triton Inference Server Requests
    description: Detects requests to the NVIDIA Triton Inference Server that may be attempting to exploit CVE-2026-24146 by sending a large number of outputs.
    platform: sigma
    severity: medium
    tactics:
      - availability
    techniques:
      - T1498
    data_sources:
      - webserver
      - linux
  - title: Detect Triton Server Crashes in Syslog
    description: Detects potential crashes of the NVIDIA Triton Inference Server by monitoring syslog for out-of-memory errors.
    platform: sigma
    severity: high
    tactics:
      - availability
    techniques:
      - T1498
    data_sources:
      - system
      - linux
rules_count: 2
---

NVIDIA Triton Inference Server is susceptible to a denial-of-service (DoS) vulnerability identified as CVE-2026-24146. This flaw stems from insufficient input validation within the server software. An attacker can exploit this by sending specially crafted requests with a large number of expected outputs to the server. If successful, this causes excessive memory allocation leading to a server crash, rendering the service unavailable to legitimate users. This vulnerability impacts any…
