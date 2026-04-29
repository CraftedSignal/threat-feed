---
title: XWiki Remote Code Execution via Unprotected Velocity Scripting API
slug: 2026-04-xwiki-rce
description: XWiki is vulnerable to remote code execution due to an improperly protected scripting API, allowing users with script rights to bypass the Velocity scripting API sandbox and execute arbitrary code, leading to full instance compromise.
date: "2026-04-08T15:00:17Z"
type: coverage
types:
  - coverage
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

XWiki versions before 17.4.8 and 17.10.1 are susceptible to remote code execution (RCE) due to an improperly protected Velocity scripting API. This vulnerability, identified as CVE-2026-33229, allows users with existing script rights to bypass the intended sandboxing mechanisms of the Velocity scripting API. By exploiting this flaw, attackers can execute arbitrary code, including potentially malicious Python scripts, on the XWiki instance. This vulnerability allows an attacker to gain complete control over the XWiki instance, compromising the confidentiality, integrity, and availability of the system and its data. The issue has been addressed in XWiki versions 17.4.8 and 17.10.1 by enforcing a requirement for programming rights to access the vulnerable API.

## Attack Chain

1. An attacker gains script rights within the XWiki instance, either through compromised credentials or misconfigured permissions.
2. The attacker crafts a malicious request leveraging the unprotected Velocity scripting API.
3. This request bypasses the intended sandboxing of the Velocity scripting engine.
4. The attacker injects arbitrary code, such as a Python script, into the Velocity template.
5. The Velocity engine executes the injected code on the XWiki server.
6. The attacker gains arbitrary code execution privileges on the server.
7. The attacker leverages the code execution to install a web shell.
8. Using the web shell, the attacker gains complete control over the XWiki instance, enabling data theft, modification, or denial of service.

## Impact

Successful exploitation of this vulnerability grants attackers complete control over the XWiki instance. This can lead to the theft of sensitive data stored within the XWiki, unauthorized modification of existing data, or a complete denial of service. While the exact number of potential victims is unknown, any XWiki instance running a vulnerable version is at risk, particularly those where script rights are broadly assigned. This vulnerability has the potential to severely impact organizations relying on XWiki for critical business functions.

## Recommendation

*   Upgrade XWiki instances to version 17.4.8 or 17.10.1 or later to patch CVE-2026-33229.
*   Implement the Sigma rule "Detect Suspicious XWiki Velocity Scripting API Usage" to identify potential exploitation attempts.
*   Review and restrict script rights assignments within XWiki to minimize the attack surface, as mentioned in the overview.
