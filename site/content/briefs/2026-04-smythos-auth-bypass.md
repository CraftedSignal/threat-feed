---
title: SmythOS sre Authentication Bypass Vulnerability (CVE-2026-7022)
slug: 2026-04-smythos-auth-bypass
description: A remote improper authentication vulnerability exists in SmythOS sre up to version 0.0.15, allowing attackers to bypass authentication by manipulating the X-DEBUG-RUN/X-DEBUG-INJ arguments in the HTTP Header Handler component.
date: "2026-04-26T06:16:02Z"
severities:
  - high
tags:
  - authentication-bypass
  - CVE-2026-7022
products:
  - sre
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-7022
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-7022
rules:
  - title: Detect SmythOS Authentication Bypass Attempt via X-DEBUG Headers
    description: Detects attempts to exploit CVE-2026-7022 by looking for HTTP requests with specific X-DEBUG-RUN or X-DEBUG-INJ headers.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect SmythOS Authentication Bypass Attempt via HTTP Headers
    description: Detects authentication bypass attempts by identifying abnormal HTTP header usage.
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

A security vulnerability, CVE-2026-7022, has been identified in SmythOS sre versions up to 0.0.15. The vulnerability resides in the AgentRuntime function within the packages/core/src/subsystems/AgentManager/AgentRuntime.class.ts file, specifically affecting the HTTP Header Handler. By manipulating the X-DEBUG-RUN and X-DEBUG-INJ arguments within HTTP headers, an attacker can bypass authentication mechanisms. This vulnerability is remotely exploitable and has a publicly available exploit, posing…
