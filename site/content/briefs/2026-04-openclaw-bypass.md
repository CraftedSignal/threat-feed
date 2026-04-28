---
title: OpenClaw Allowlist Bypass Vulnerability (CVE-2026-35666)
slug: 2026-04-openclaw-bypass
description: OpenClaw before 2026.3.22 contains an allowlist bypass vulnerability (CVE-2026-35666) in system.run approvals that fails to properly handle /usr/bin/time wrappers, allowing attackers to bypass executable binding restrictions.
date: "2026-04-11T12:00:00Z"
severities:
  - high
tags:
  - cve
  - allowlist-bypass
  - execution
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1027
    technique_name: Obfuscated Files or Information
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1210
    technique_name: Exploitation of Remote Services
cves:
  - id: CVE-2026-35666
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-35666
  - https://github.com/openclaw/openclaw/commit/39409b6a6dd4239deea682e626bac9ba547bfb14
  - https://github.com/openclaw/openclaw/commit/630f1479c44f78484dfa21bb407cbe6f171dac87
  - https://github.com/openclaw/openclaw/security/advisories/GHSA-qm9x-v7cx-7rq4
  - https://www.vulncheck.com/advisories/openclaw-allowlist-bypass-via-unregistered-time-dispatch-wrapper
rules:
  - title: Detect Execution via Unregistered Time Wrapper
    description: Detects the execution of commands using unregistered /usr/bin/time wrappers, potentially bypassing allowlist restrictions in OpenClaw.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1202
    data_sources:
      - process_creation
      - linux
  - title: Detect Unregistered Time Executable Creation
    description: Detects the creation of new executable files in /tmp or other common writable directories that have 'time' in the name.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1027
    data_sources:
      - file_event
      - linux
rules_count: 2
---

OpenClaw, a security-focused application, is susceptible to an allowlist bypass vulnerability affecting versions prior to 2026.3.22.  This flaw, identified as CVE-2026-35666, resides within the system.run approval mechanism, specifically in its handling of `/usr/bin/time` wrappers. The vulnerability stems from the system's failure to properly unwrap these wrappers, leading to an exploitable condition where attackers can circumvent intended executable binding restrictions. By employing an unregistered `time` wrapper, an attacker can reuse the approval state established for the wrapper to execute unauthorized inner commands. This issue allows malicious actors to potentially execute arbitrary code within the OpenClaw environment, undermining its security guarantees.

## Attack Chain

1.  Attacker identifies an OpenClaw instance running a version prior to 2026.3.22.
2.  Attacker crafts a command that utilizes an unregistered `time` wrapper around a malicious executable. For example `/path/to/unregistered_time /path/to/malicious_executable`.
3.  The system.run approval mechanism is invoked to execute the crafted command.
4.  The system incorrectly evaluates the allowlist based on the `time` wrapper, failing to recognize it as untrusted.
5.  The approval state of the `time` wrapper is reused for the inner, malicious executable.
6.  The malicious executable is executed with the permissions granted to the wrapper.
7.  The attacker gains unauthorized access and control within the OpenClaw environment.

## Impact

Successful exploitation of this vulnerability could allow an attacker to bypass intended security controls within OpenClaw. This could lead to the execution of arbitrary code, potentially granting the attacker elevated privileges and the ability to compromise the system's integrity. The number of affected installations is currently unknown, but any OpenClaw deployment using versions before 2026.3.22 is vulnerable. If successfully exploited, an attacker could potentially gain complete control over the OpenClaw instance and any systems it manages, leading to data breaches, system compromise, and further lateral movement within the network.

## Recommendation

*   Upgrade OpenClaw to version 2026.3.22 or later to patch CVE-2026-35666.
*   Monitor process execution for the use of unregistered `/usr/bin/time` wrappers as described in the Attack Chain (see example Sigma rule below).
*   Implement strict allowlisting and validation of executables allowed to be run via `system.run` to mitigate the impact of a successful bypass.
