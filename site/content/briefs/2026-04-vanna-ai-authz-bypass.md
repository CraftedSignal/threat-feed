---
title: vanna-ai vanna Improper Authorization Vulnerability (CVE-2026-6977)
slug: 2026-04-vanna-ai-authz-bypass
description: An improper authorization vulnerability (CVE-2026-6977) exists in vanna-ai vanna up to version 2.0.2 due to manipulation of an unknown function within the Legacy Flask API, potentially allowing remote attackers to bypass intended access restrictions.
date: "2026-04-25T11:16:19Z"
severities:
  - medium
tags:
  - vulnerability
  - authorization
  - web application
vendors:
  - vanna-ai
products:
  - vanna
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1555
    technique_name: Credentials on Shared Drives
cves:
  - id: CVE-2026-6977
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-6977
  - https://github.com/yidaozhongqing/York/issues/2
  - https://vuldb.com/submit/795331
  - https://vuldb.com/vuln/359520
  - https://vuldb.com/vuln/359520/cti
rules:
  - title: Detect Potential vanna-ai vanna Unauthorized Access Attempt
    description: Detects suspicious HTTP requests potentially exploiting the CVE-2026-6977 vulnerability in vanna-ai vanna, focusing on unusual methods or parameters targeting the Legacy Flask API.
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1555
    data_sources:
      - webserver
      - linux
  - title: Detect vanna-ai vanna request to github exploit
    description: Detects web requests to a known exploit URL for vanna-ai vanna
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1555
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A security vulnerability, identified as CVE-2026-6977, has been discovered in vanna-ai vanna versions up to 2.0.2. The vulnerability resides within an unspecified function of the Legacy Flask API component. Successful exploitation of this flaw leads to improper authorization, potentially granting unauthorized access to sensitive resources or functionalities. The vulnerability is remotely exploitable and a proof-of-concept exploit is publicly available. The vendor was contacted but did not…
