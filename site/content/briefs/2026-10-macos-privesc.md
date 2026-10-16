---
title: CVE-2023-42931 Privilege Escalation in macOS diskutil
slug: 2026-10-macos-privesc
description: A local privilege escalation vulnerability in the macOS diskutil utility allows unprivileged users to gain root access via manipulated filesystem mounting.
date: "2026-10-16T10:33:12Z"
type: threat
types:
  - threat
severities:
  - high
exploited: true
cpes:
  - cpe:2.3:o:apple:macos:*:*:*:*:*:*:*:*
tags:
  - privilege-escalation
  - macos
  - local-exploitation
vendors:
  - Apple
products:
  - macOS (< 12.7.2, 13.6.3, 14.2)
affected_os:
  - macOS Monterey
  - macOS Ventura
  - macOS Sonoma
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: The vulnerability allows unprivileged users to gain full root control over the system by exploiting the 'diskutil' command line utility.
    confidence_band: high
cves:
  - id: CVE-2023-42931
    cvss: 7.8
    epss: 0.01171
references:
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-D0RB-CVE-2023-42931
  - https://www.alter-solutions.fr/blog/local-privilege-escalating-my-way-to-root-throught-apple-macos-filesystems
rules:
  - title: Detect Suspicious diskutil Execution for Mounting
    description: Detects the use of the diskutil utility to mount filesystems, which may be a precursor to CVE-2023-42931 exploitation by unprivileged users.
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - process_creation
      - macos
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Patch macOS systems to versions 12.7.2, 13.6.3, or 14.2
      owner: IT Operations
      due: 48h
      evidence: Source advisory
  hunt_leads:
    - lead: Search for unauthorized setuid binary creation following diskutil execution
      technique_id: T1068
      data_needed:
        - File integrity monitoring logs
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: Exploit script creates a setuid shell payload
  mitigation_plan:
    - priority: immediate
      action: Upgrade Apple macOS to 12.7.2, 13.6.3, 14.2
      owner: IT Operations
      addresses: CVE-2023-42931
      evidence: Source documentation
---

CVE-2023-42931 is a local privilege escalation vulnerability affecting multiple versions of macOS, including Monterey, Ventura, and Sonoma. The vulnerability resides in the 'diskutil' command-line utility, which fails to properly restrict filesystem mounting options when invoked by unprivileged users. An attacker can leverage this flaw to gain full root control of the host system. The vulnerability was publicly disclosed alongside a functional proof-of-concept exploit that automates the exploitation process. The exploit targets how 'diskutil' manages filesystem permissions, allowing for the deployment and execution of setuid binaries. Given the availability of this exploit code, unpatched systems are at significant risk of unauthorized administrative access.

## Attack Chain

1. The unprivileged attacker initiates the exploit script on a local macOS endpoint.
2. The script interacts with the 'diskutil' utility to trigger a filesystem mount operation.
3. The attacker provides crafted filesystem options to 'diskutil' to bypass existing security restrictions.
4. The script creates a malicious setuid shell payload.
5. The payload is moved to a target placeholder file on the mounted filesystem.
6. The script uses 'diskutil' or system utilities to explicitly set the setuid bit on the malicious binary.
7. The attacker executes the setuid binary to execute code with root privileges.
8. The final objective is the acquisition of a root shell for full system control and persistence.

## Impact

Successful exploitation of CVE-2023-42931 results in a full local privilege escalation, granting the attacker root privileges on the compromised macOS device. This provides the actor with unrestricted access to sensitive user data, system configuration, and the ability to disable security controls or maintain persistent access. The vulnerability affects macOS versions prior to 12.7.2, 13.6.3, and 14.2.

## Recommendation

* Prioritize updating all macOS endpoints to versions 12.7.2, 13.6.3, 14.2 or later to patch CVE-2023-42931.
* Monitor process execution logs for suspicious usage of 'diskutil' in combination with setuid or chmod commands by non-administrative users.
* Review audit logs for instances where non-privileged accounts successfully elevate to root (uid 0) using unauthorized binaries.
