---
title: XWiki Remote Code Execution via Unprotected Velocity Scripting API
slug: 2026-04-xwiki-rce
description: XWiki is vulnerable to remote code execution due to an improperly protected scripting API, allowing users with script rights to bypass the Velocity scripting API sandbox and execute arbitrary code, leading to full instance compromise.
date: "2026-04-08T15:00:17Z"
severities:
  - high
tags:
  - xwiki
  - rce
  - velocity
  - scripting
  - CVE-2026-33229
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1505
    technique_name: Server Software Component
references:
  - https://github.com/advisories/GHSA-h259-74h5-4rh9
rules:
  - title: Detect Suspicious XWiki Velocity Scripting API Usage
    description: Detects potential exploitation attempts of the XWiki Velocity scripting API vulnerability by monitoring for suspicious HTTP requests.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - webserver
      - linux
  - title: Detect XWiki Web Shell Creation via Scripting API
    description: Detects the creation of web shells within the XWiki web directory, potentially indicating successful exploitation of the Velocity scripting API.
    platform: sigma
    severity: critical
    tactics:
      - persistence
    techniques:
      - T1505.003
    data_sources:
      - file_event
      - linux
rules_count: 2
---

XWiki versions before 17.4.8 and 17.10.1 are susceptible to remote code execution (RCE) due to an improperly protected Velocity scripting API. This vulnerability, identified as CVE-2026-33229, allows users with existing script rights to bypass the intended sandboxing mechanisms of the Velocity scripting API. By exploiting this flaw, attackers can execute arbitrary code, including potentially malicious Python scripts, on the XWiki instance. This vulnerability allows an attacker to gain complete…
