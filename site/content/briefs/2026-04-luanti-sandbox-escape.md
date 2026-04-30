---
title: Luanti LuaJIT Sandbox Escape (CVE-2026-40959)
slug: 2026-04-luanti-sandbox-escape
description: Luanti 5 before 5.15.2, when LuaJIT is used, allows a Lua sandbox escape via a crafted mod, potentially leading to arbitrary code execution.
date: "2026-04-16T01:16:11Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - sandbox-escape
  - luanti
  - luajit
  - cve-2026-40959
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-40959
    cvss: 9.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-40959
  - https://github.com/luanti-org/luanti/commit/53cef183e2a85a4daff84ac1a9a7946f940da8f8
  - https://github.com/luanti-org/luanti/commit/8a929dfb97aa08337f49ba1bb96a56d6557dc896
  - https://github.com/luanti-org/luanti/security/advisories/GHSA-g596-mf82-w8c3
rules:
  - title: Detect Luanti Loading Suspicious Lua Mods
    description: Detects the loading of Lua mods by Luanti that originate from unusual or untrusted locations, potentially indicating a sandbox escape attempt.
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - process_creation
      - windows
  - title: Detect Suspicious File Creation by LuaJIT
    description: Detects suspicious file creation by luajit.exe, potentially indicating successful sandbox escape
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1105
    data_sources:
      - file_event
      - windows
rules_count: 2
---

CVE-2026-40959 describes a critical vulnerability in Luanti 5, specifically in versions prior to 5.15.2, when used with LuaJIT. The vulnerability allows a malicious actor to escape the Lua sandbox environment by exploiting a crafted "mod." This escape could lead to unauthorized access and control over the system, potentially allowing for arbitrary code execution outside of the intended sandbox. The vulnerability was reported to MITRE and assigned a CVSS v3.1 score of 9.3, indicating a critical severity. This vulnerability poses a significant threat to systems relying on Luanti for sandboxed Lua execution.

## Attack Chain

1.  Attacker crafts a malicious Lua "mod" specifically designed to exploit the sandbox escape vulnerability in Luanti.
2.  The malicious mod leverages weaknesses in the LuaJIT implementation within Luanti to bypass sandbox restrictions.
3.  The crafted mod is loaded into a vulnerable Luanti 5 instance.
4.  Upon execution of the malicious mod, the attacker gains the ability to execute arbitrary Lua code outside the intended sandbox.
5.  The attacker can then utilize this escaped context to interact with the underlying operating system.
6.  Using OS-level access, the attacker escalates privileges further.
7.  The attacker installs persistent backdoors or other malicious software.
8.  Finally, the attacker achieves complete system compromise, exfiltrates sensitive data, or causes other damage.

## Impact

Successful exploitation of CVE-2026-40959 could lead to a complete compromise of systems utilizing vulnerable versions of Luanti 5 with LuaJIT. An attacker could gain unauthorized access to sensitive data, install malware, or disrupt critical services. Given the critical CVSS score of 9.3, the potential impact is high, especially in environments where Luanti is used to sandbox untrusted Lua code. The number of potential victims depends on the adoption rate of Luanti 5 and the prevalence of LuaJIT usage within those installations.

## Recommendation

*   Upgrade Luanti to version 5.15.2 or later to patch CVE-2026-40959.
*   Monitor for the loading of unsigned or untrusted Lua mods within Luanti environments (see process_creation rule below).
*   Inspect Lua mods for suspicious code patterns indicative of sandbox escape attempts (develop custom rules based on the specific LuaJIT weaknesses exploited).
