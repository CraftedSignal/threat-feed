---
title: Undertow Request Smuggling Vulnerability (CVE-2026-28368)
slug: 2026-03-undertow-request-smuggling
description: CVE-2026-28368 is a vulnerability in Undertow that allows a remote attacker to construct specially crafted requests, leading to request smuggling attacks and potential bypass of security controls, resulting in unauthorized resource access.
date: "2026-03-28T12:00:00Z"
severities:
  - high
type: advisory
types:
  - advisory
tags:
  - undertow
  - request-smuggling
  - cve-2026-28368
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-28368
  - https://access.redhat.com/security/cve/CVE-2026-28368
  - https://bugzilla.redhat.com/show_bug.cgi?id=2443261
rules:
  - title: Detect Suspicious HTTP Headers
    description: Detects potentially malicious HTTP requests with unusual or crafted headers that could indicate request smuggling attempts.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Potential Request Splitting via Content-Length
    description: Detects HTTP requests with suspicious Content-Length headers that may be used for request smuggling.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

CVE-2026-28368 is a critical vulnerability found in the Undertow web server. This flaw enables a remote attacker to craft specialized HTTP requests that Undertow parses differently compared to upstream proxies. This discrepancy allows attackers to conduct request smuggling attacks, effectively bypassing security measures and potentially gaining unauthorized access to sensitive resources. The vulnerability stems from inconsistent interpretation of HTTP requests, which is a common issue in web…
