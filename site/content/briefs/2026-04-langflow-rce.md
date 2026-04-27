---
title: IBM Langflow Desktop Deserialization RCE (CVE-2026-3357)
slug: 2026-04-langflow-rce
description: IBM Langflow Desktop versions 1.6.0 through 1.8.2 is vulnerable to arbitrary code execution due to insecure deserialization of untrusted data, allowing an authenticated user to execute code on the system.
date: "2026-04-08T01:16:41Z"
severities:
  - critical
tags:
  - cve-2026-3357
  - deserialization
  - rce
  - langflow
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
cves:
  - id: CVE-2026-3357
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-3357
  - https://www.ibm.com/support/pages/node/7268428
rules:
  - title: Detect Langflow Deserialization Attempt via Suspicious POST Request
    description: Detects potential exploitation attempts of CVE-2026-3357 by monitoring for suspicious POST requests to the Langflow Desktop application that may contain serialized data.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1204.002
    data_sources:
      - webserver
      - linux
  - title: Detect Langflow Deserialization Attempt via Large POST Request
    description: Detects potential exploitation attempts of CVE-2026-3357 by monitoring for unusually large POST requests. Deserialization exploits often involve sending large amounts of data.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1204.002
    data_sources:
      - webserver
      - linux
rules_count: 2
---

IBM Langflow Desktop, a low-code platform designed to build custom LLM applications, is susceptible to a critical vulnerability (CVE-2026-3357) affecting versions 1.6.0 through 1.8.2. The flaw stems from an insecure default setting within the FAISS (Facebook AI Similarity Search) component, which permits the deserialization of untrusted data. This vulnerability allows an authenticated user to execute arbitrary code on the host system. Successful exploitation grants the attacker full control…
