---
title: FoundDream miniclawd Command Injection Vulnerability (CVE-2026-9453)
slug: 2026-05-miniclawd-command-injection
description: A command injection vulnerability (CVE-2026-9453) exists in FoundDream miniclawd, where manipulation of the requires.bins argument in /src/application/skills-loader.ts allows remote command execution, and the exploit is publicly available.
date: "2026-05-26T14:11:59Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - command-injection
  - cve
  - miniclawd
vendors:
  - FoundDream
products:
  - miniclawd
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
cves:
  - id: CVE-2026-9453
    cvss: 7.3
    epss: 0.01039
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-9453
rules:
  - title: Detect Suspicious Process Creation from miniclawd
    description: Detects suspicious process creation originating from the miniclawd application, indicating potential command injection.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - windows
  - title: Detect miniclawd Command Injection Attempt
    description: Detects CVE-2026-9453 exploitation — attempts to exploit command injection in miniclawd via manipulation of requires.bins in /src/application/skills-loader.ts.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 2
---

A command injection vulnerability, identified as CVE-2026-9453, affects FoundDream miniclawd up to commit 2d65665046e2222eeea76cafc8570ed546a8c125. The vulnerability resides within the SkillsLoader component, specifically in the /src/application/skills-loader.ts file. By manipulating the requires.bins argument, a remote attacker can inject and execute arbitrary commands on the target system. The public availability of an exploit for this vulnerability increases the risk of widespread exploitation. Since miniclawd uses a rolling release model, determining specific affected versions is challenging, complicating patching efforts. The lack of vendor response after being informed through an issue report further exacerbates the situation.

## Attack Chain

1.  The attacker identifies a vulnerable instance of FoundDream miniclawd running a version up to commit 2d65665046e2222eeea76cafc8570ed546a8c125.
2.  The attacker crafts a malicious request targeting the SkillsLoader component.
3.  Within the crafted request, the attacker manipulates the requires.bins argument in the /src/application/skills-loader.ts file.
4.  The injected payload contains shell metacharacters to facilitate command injection.
5.  The miniclawd application processes the malicious request and passes the manipulated requires.bins argument to a function that executes commands.
6.  The application executes the attacker-controlled commands on the server.
7.  The attacker gains arbitrary code execution on the target system.
8.  The attacker can then perform further actions, such as installing malware, exfiltrating data, or pivoting to other systems within the network.

## Impact

Successful exploitation of this vulnerability allows attackers to execute arbitrary commands on systems running vulnerable versions of FoundDream miniclawd. This can lead to complete system compromise, data breaches, and potential disruption of services. Due to the public availability of the exploit, a wide range of miniclawd installations are at risk until patches or mitigations are applied.

## Recommendation

*   Monitor process creations for suspicious commands originating from the miniclawd application directory, using the Sigma rule "Detect Suspicious Process Creation from miniclawd".
*   Inspect web server logs for requests containing shell metacharacters in the requires.bins argument targeting /src/application/skills-loader.ts using the Sigma rule "Detect miniclawd Command Injection Attempt".
*   Apply input validation and sanitization to the requires.bins argument in /src/application/skills-loader.ts to prevent command injection (reference CVE-2026-9453).
