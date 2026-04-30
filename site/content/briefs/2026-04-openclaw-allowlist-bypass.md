---
title: OpenClaw Exec Allowlist Bypass Vulnerability (CVE-2026-41390)
slug: 2026-04-openclaw-allowlist-bypass
description: OpenClaw before version 2026.3.28 contains an exec allowlist bypass vulnerability (CVE-2026-41390) that allows attackers to persist trust for wrapper binaries like /usr/bin/script to execute different underlying programs, potentially leading to privilege escalation.
date: "2026-04-28T19:37:42Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - allowlist bypass
  - privilege escalation
  - cve-2026-41390
products:
  - OpenClaw
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1027
    technique_name: Obfuscated Files or Information
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-41390
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-41390
  - https://github.com/openclaw/openclaw/security/advisories/GHSA-6pfc-6m7w-m8fx
  - https://www.vulncheck.com/advisories/openclaw-exec-allowlist-bypass-via-unregistered-usr-bin-script-wrapper
rules:
  - title: Detect Suspicious Script Wrapper Execution
    description: Detects the execution of script wrappers with potentially malicious commands. This can indicate an attempt to bypass security restrictions.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1027
      - T1059.004
    data_sources:
      - process_creation
      - linux
  - title: Detect Script command using /dev/null
    description: Detects the execution of script with output redirected to /dev/null. This can indicate an attempt to hide the execution output.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1027
      - T1059.004
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

OpenClaw, a security application, is vulnerable to an allowlist bypass (CVE-2026-41390) affecting versions prior to 2026.3.28. The core issue lies in how OpenClaw handles "allow-always" persistence, specifically when dealing with wrapper binaries like `/usr/bin/script`. The application fails to properly unwrap or inspect the underlying commands executed by these wrappers before storing trust decisions. This oversight allows an attacker to gain user approval for a benign, wrapped command. Once approved, the trust is incorrectly associated with the wrapper binary itself, enabling the execution of arbitrary, potentially malicious, commands through the same wrapper. This vulnerability can lead to privilege escalation or other unauthorized activities, as the attacker can bypass intended security restrictions by leveraging the improperly granted trust.

## Attack Chain

1.  Attacker identifies a vulnerable OpenClaw installation running a version prior to 2026.3.28.
2.  Attacker crafts a seemingly benign command using a wrapper binary like `/usr/bin/script`, such as `script -q /tmp/output bash -c "id"`.
3.  The user is prompted by OpenClaw to approve the execution of `/usr/bin/script`.
4.  The user, believing the command is safe, approves the execution and adds `/usr/bin/script` to the "allow-always" list.
5.  OpenClaw incorrectly persists trust for `/usr/bin/script` without unwrapping the command.
6.  Attacker then executes a malicious command using the same wrapper, e.g., `script -q /tmp/output bash -c "rm -rf /"`.
7.  OpenClaw allows the execution of the malicious command because `/usr/bin/script` is already trusted.
8.  The malicious command executes, resulting in data loss or system compromise.

## Impact

Successful exploitation of this vulnerability allows attackers to bypass the intended access controls enforced by OpenClaw. An attacker can leverage a trusted wrapper binary to execute arbitrary commands, potentially leading to privilege escalation and full system compromise. The impact can range from data theft and system corruption to complete control over the affected system. This vulnerability affects any system running a vulnerable version of OpenClaw.

## Recommendation

*   Upgrade OpenClaw to version 2026.3.28 or later to patch the vulnerability described in CVE-2026-41390.
*   Implement process monitoring to detect the execution of `/usr/bin/script` or similar wrappers with potentially malicious commands as a defense in depth. Use the "Detect Suspicious Script Wrapper Execution" Sigma rule provided below.
*   Review existing "allow-always" rules in OpenClaw and remove any entries for wrapper binaries like `/usr/bin/script` that might have been added inadvertently.
