---
title: mingSoft MCMS Server-Side Request Forgery Vulnerability (CVE-2026-4953)
slug: 2026-03-mingsoft-ssrf
description: A server-side request forgery (SSRF) vulnerability (CVE-2026-4953) exists in mingSoft MCMS version 5.5.0, allowing remote attackers to manipulate the 'catchimage' argument in the catchImage function to potentially access or interact with internal resources.
date: "2026-03-27T15:17:02Z"
severities:
  - high
type: advisory
types:
  - advisory
tags:
  - SSRF
  - mingSoft
  - CVE-2026-4953
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1595
    technique_name: Active Scanning
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1588
    technique_name: Obtain Capabilities
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-4953
  - https://github.com/wing3e/public_exp/issues/3
  - https://vuldb.com/?ctiid.353831
  - https://vuldb.com/?id.353831
  - https://vuldb.com/?submit.777516
rules:
  - title: Detect Suspicious SSRF Attempt in mingSoft MCMS
    description: Detects potential Server-Side Request Forgery (SSRF) attempts in mingSoft MCMS by monitoring the 'catchimage' parameter for suspicious URLs or internal IP addresses.
    platform: sigma
    severity: high
    tactics:
      - discovery
      - initial_access
    techniques:
      - T1190
      - T1588
      - T1595.002
    data_sources:
      - webserver
      - linux
  - title: Detect MingSoft MCMS BaseAction.java catchImage SSRF Pattern
    description: Detects exploitation attempts targeting the catchImage function in BaseAction.java of MingSoft MCMS via a crafted URL
    platform: sigma
    severity: high
    tactics:
      - discovery
      - initial_access
    techniques:
      - T1190
      - T1588
      - T1595.002
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A server-side request forgery (SSRF) vulnerability has been identified in mingSoft MCMS version 5.5.0. The vulnerability resides within the `catchImage` function in the `net/mingsoft/cms/action/BaseAction.java` file, specifically affecting the Editor Endpoint component. Attackers can remotely exploit this vulnerability by manipulating the `catchimage` argument. Publicly available exploits exist, increasing the risk of exploitation. Successful exploitation could allow an attacker to probe…
