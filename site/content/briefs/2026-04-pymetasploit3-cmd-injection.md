---
title: Pymetasploit3 Command Injection Vulnerability (CVE-2026-5463)
slug: 2026-04-pymetasploit3-cmd-injection
description: A command injection vulnerability in pymetasploit3 versions up to 1.0.6 allows attackers to inject newline characters into module options, leading to arbitrary command execution within Metasploit sessions.
date: "2026-04-03T05:16:24Z"
severities:
  - high
type: advisory
types:
  - advisory
tags:
  - command-injection
  - metasploit
  - pymetasploit3
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1550
    technique_name: Use Alternate Authentication Material
cves:
  - id: CVE-2026-5463
    cvss: 8.6
    epss: 0.01784
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-5463
  - https://github.com/DanMcInerney/pymetasploit3
  - https://pypi.org/project/pymetasploit3/
rules:
  - title: Detect Newline Character Injection in pymetasploit3 Module Arguments
    description: Detects attempts to inject newline characters into pymetasploit3 module arguments, potentially leading to command injection (CVE-2026-5463).
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
  - title: Detect Suspicious pymetasploit3 Process Execution with Network Activity
    description: Detects pymetasploit3 processes that initiate network connections, potentially indicating module execution.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
      - execution
    techniques:
      - T1071.001
    data_sources:
      - network_connection
      - linux
rules_count: 2
---

A command injection vulnerability, identified as CVE-2026-5463, affects pymetasploit3 versions up to 1.0.6. This flaw allows an attacker to inject newline characters into module options like RHOSTS when using the `console.run_module_with_output()` function. By exploiting this, attackers can break the intended command structure and inject malicious commands, causing the Metasploit console to execute unintended actions. Successful exploitation can lead to arbitrary command execution, potentially compromising the Metasploit session and the systems it interacts with. This vulnerability highlights the importance of careful input validation in security tools, as it can be leveraged to subvert their intended functionality. Defenders should be aware of the potential for unexpected behavior when using pymetasploit3 with untrusted input.

## Attack Chain

1.  Attacker crafts a malicious input string containing newline characters (`\n`) within a module option, such as the `RHOSTS` parameter.
2.  The attacker supplies this malicious input to the `console.run_module_with_output()` function in pymetasploit3.
3.  Pymetasploit3 fails to properly sanitize or validate the input, allowing the newline characters to pass through.
4.  When the `run_module_with_output()` function processes the input, the newline characters are interpreted as command separators.
5.  Metasploit console executes the injected commands alongside the intended module command, potentially leading to arbitrary command execution within the context of the Metasploit session.
6.  Attacker gains control of the Metasploit session, allowing them to interact with target systems or pivot to other internal resources.
7.  The attacker can then execute further commands to install malware, exfiltrate data, or perform other malicious activities.

## Impact

Successful exploitation of CVE-2026-5463 allows an attacker to execute arbitrary commands within the context of the Metasploit console. This could lead to the complete compromise of systems targeted by the Metasploit framework, potentially impacting numerous systems within a network depending on the attacker's objectives and the scope of the Metasploit session. If the attacker gains elevated privileges, the impact could include data breaches, system downtime, and reputational damage.

## Recommendation

*   Upgrade pymetasploit3 to a version beyond 1.0.6 to remediate CVE-2026-5463.
*   Implement strict input validation and sanitization on any user-supplied data used in conjunction with `console.run_module_with_output()` to prevent command injection.
*   Monitor Metasploit console logs for unusual or unexpected commands being executed, as this could indicate exploitation attempts (enable enhanced logging if necessary to capture command details).
*   Deploy the Sigma rule provided to detect attempts to inject newline characters within arguments passed to modules via the `console.run_module_with_output()` function.
