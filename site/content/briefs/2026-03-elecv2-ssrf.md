---
title: elecV2 elecV2P Server-Side Request Forgery Vulnerability (CVE-2026-5016)
slug: 2026-03-elecv2-ssrf
description: A server-side request forgery vulnerability exists in elecV2 elecV2P up to 3.8.3, affecting the eAxios function within the /mock URL handler, allowing remote attackers to manipulate the req argument and potentially conduct internal reconnaissance or other malicious activities.
date: "2026-03-28T22:15:58Z"
severities:
  - medium
type: advisory
types:
  - advisory
tags:
  - cve-2026-5016
  - ssrf
  - elecv2
  - web-application
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1068
    technique_name: Exploit Public-Facing Application
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-5016
  - https://github.com/elecV2/elecV2P/
  - https://github.com/elecV2/elecV2P/issues/202
  - https://vuldb.com/vuln/353901
rules:
  - title: Detect Suspicious elecV2 SSRF via Mock Endpoint
    description: Detects potential Server-Side Request Forgery (SSRF) attempts targeting the /mock endpoint in elecV2 elecV2P by monitoring for suspicious URL patterns in the req parameter.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect elecV2 elecV2P Version Disclosure via HTTP Response
    description: Detects potential version disclosure in elecV2 elecV2P HTTP responses, which can aid attackers in identifying vulnerable instances.
    platform: sigma
    severity: informational
    tactics:
      - reconnaissance
    techniques:
      - T1595.001
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A server-side request forgery (SSRF) vulnerability, tracked as CVE-2026-5016, has been identified in elecV2 elecV2P versions up to 3.8.3. The vulnerability lies within the `eAxios` function of the `/mock` URL handler. By manipulating the `req` argument, a remote attacker can potentially force the server to make requests to arbitrary internal or external addresses. This could lead to the exposure of sensitive information, internal reconnaissance, or other malicious actions. The exploit is…
