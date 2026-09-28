---
title: Local Privilege Escalation in Parallels Desktop via Argument Injection
slug: 2026-09-parallels-pe
description: Parallels Desktop versions prior to 27.0.0 are vulnerable to local privilege escalation via an argument injection flaw in the root-privileged prl_disp_service.
date: "2026-09-28T10:10:22Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:parallels:parallels_desktop:*:*:*:*:*:macos:*:*
tags:
  - privilege-escalation
  - macos
  - vulnerability
  - cve-2026-90894
vendors:
  - Parallels
products:
  - Parallels Desktop (< 27.0.0)
affected_os:
  - macOS
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: The dispatcher always runs a 5-token command (tar -xf <archive> -C <dir>), so any additional arguments indicate an attacker-controlled folder name injecting extra tar flags.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1202
    technique_name: Indirect Command Execution
    evidence: A --use-compress-program value pointing at an attacker-writable path (commonly /tmp) is executed as root.
    confidence_band: high
cves:
  - id: CVE-2026-90894
    cvss: 7.8
    epss: 0.00168
references:
  - https://research.jfrog.com/vulnerabilities/parallels-desktop-is-vulnerable-to-a-local-privilege-escalation-via-appliance-extract-argument-injection-cve-2026-90894/
  - https://www.cve.org/CVERecord?id=CVE-2026-90894
rules:
  - title: Detect CVE-2026-90894 Exploitation - Parallels Appliance Extract Argument Injection
    description: Detects prl_disp_service spawning tar/bsdtar with an excessive number of arguments, indicating potential argument injection for privilege escalation.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
      - privilege_escalation
    techniques:
      - T1068
      - T1202
    data_sources:
      - process_creation
      - macos
rules_count: 1
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Upgrade Parallels Desktop to 27.0.0 or later
      owner: IT Operations
      due: 24h
      evidence: Parallels Desktop < 27.0.0
  mitigation_plan:
    - priority: immediate
      action: Restrict local login access on affected macOS hosts
      owner: IT Operations
      addresses: CVE-2026-90894
      evidence: Dispatcher socket is reachable by any local account
---

Parallels Desktop for macOS versions prior to 27.0.0 contain a critical local privilege escalation (LPE) vulnerability tracked as CVE-2026-90894. The flaw exists within the 'prl_disp_service', a background service running with root privileges that exposes a world-writable socket to local users. An attacker can interact with this socket to trigger an appliance installation process. 

The service implements an insecure re-tokenization mechanism when executing 'tar' or 'bsdtar' for archive extraction. By providing a malicious archive name containing additional tar flags, an attacker can perform argument injection. This allows the execution of arbitrary commands as root, most notably through the '--use-compress-program' flag, which can point to an attacker-controlled file residing in a user-writable directory like /tmp. Successful exploitation grants the attacker full root access to the host system.

## Attack Chain

1. Attacker establishes local access on the target macOS host as a standard user.
2. Attacker interacts with the world-writable IPC socket exposed by 'prl_disp_service'.
3. Attacker sends a malformed request to the service to trigger the appliance installation routine.
4. The service constructs a command string incorporating an attacker-provided archive folder name.
5. The attacker-supplied name injects malicious arguments, specifically '--use-compress-program', into the command string.
6. 'prl_disp_service' executes 'tar' or 'bsdtar' with the injected flags running as root.
7. 'tar' spawns the specified external program defined in the injected argument, executing it with root privileges.
8. Attacker gains full root control over the system.

## Impact

Successful exploitation of CVE-2026-90894 allows any local unprivileged user on a macOS system to elevate privileges to root. This impacts all Parallels Desktop installations on macOS prior to version 27.0.0. The ability to execute arbitrary code as root provides an attacker with complete control over the host, enabling data exfiltration, installation of persistence mechanisms, and bypassing of macOS security controls.

## Recommendation

- Upgrade Parallels Desktop to version 27.0.0 or later immediately to address CVE-2026-90894.
- For hosts that cannot be upgraded, restrict local login access as an interim control, as the dispatcher socket is reachable by any local account.
- Deploy the provided detection logic to identify 'prl_disp_service' spawning 'tar' or 'bsdtar' with an anomalous number of arguments.
- Investigate any child processes spawned by 'tar' or 'bsdtar' that originate from 'prl_disp_service', especially those referencing paths in /tmp or /var/tmp.
