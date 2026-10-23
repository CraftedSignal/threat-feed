---
brief_id: brief-2026-10-macos-privesc
event_id: brief-2026-10-macos-privesc
revision: 2
activity_at: "2026-10-23T09:36:43Z"
revision_history:
  - revision: 2
    at: "2026-10-23T09:36:43Z"
    checksum: sha256:cf71280c4ab1d85820f8f99478058d4a4af9d0a8b4ce8431e47fe09fbf1fd68c
    summary: added coverage for macOS (< 26.6)
    changed_fields:
      - action_plan
      - affected_os
      - affected_products
      - cves
      - exploitation_evidence
      - lastmod
      - references
      - tags
      - updates
    source_urls:
      - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-ANDRD3V-CVE-2026-43783&utm_source=rss&utm_medium=rss
title: CVE-2023-42931 Privilege Escalation in macOS diskutil
slug: 2026-10-macos-privesc
description: A local privilege escalation vulnerability in the macOS diskutil utility allows unprivileged users to gain root access via manipulated filesystem mounting.
date: "2026-10-16T10:33:12Z"
lastmod: "2026-10-23T09:34:35Z"
type: threat
types:
  - threat
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: B
  credibility: "2"
  rating: B2
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Source validated, detection logic defined
cpes:
  - cpe:2.3:o:apple:macos:*:*:*:*:*:*:*:*
tags:
  - privilege-escalation
  - macos
  - local-exploitation
  - lpe
  - xpc
  - cve-2026-43783
vendors:
  - Apple
products:
  - macOS (< 12.7.2, 13.6.3, 14.2)
  - macOS (< 26.6)
affected_os:
  - macOS Monterey
  - macOS Ventura
  - macOS Sonoma
  - macOS
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
    kev_status: unknown
  - id: CVE-2026-43783
    cvss: 7.8
    epss: 0.00129
    kev_status: "false"
references:
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-D0RB-CVE-2023-42931
  - https://www.alter-solutions.fr/blog/local-privilege-escalating-my-way-to-root-throught-apple-macos-filesystems
  - https://andrd3v.github.io/cve-2026-43783/index.html
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-ANDRD3V-CVE-2026-43783
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-ANDRD3V-CVE-2026-43783&utm_source=rss&utm_medium=rss
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
    - action: Upgrade macOS to version 26.6 or later
      owner: IT Operations
      due: 72h
      evidence: Source identifies vulnerability in versions < 26.6
  hunt_leads:
    - lead: Search for unauthorized setuid binary creation following diskutil execution
      technique_id: T1068
      data_needed:
        - File integrity monitoring logs
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: Exploit script creates a setuid shell payload
    - lead: Monitor for unusual XPC communication to com.apple.DesktopServicesHelper
      technique_id: T1068
      data_needed:
        - macOS Endpoint Security Framework (ESF) events or system-level XPC monitoring
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: Daemon registers a mach service under com.apple.DesktopServicesHelper and listens for incoming XPC connections.
  mitigation_plan:
    - priority: immediate
      action: Upgrade Apple macOS to 12.7.2, 13.6.3, 14.2
      owner: IT Operations
      addresses: CVE-2023-42931
      evidence: Source documentation
    - priority: immediate
      action: Patch macOS to 26.6 or later
      owner: IT Operations
      addresses: CVE-2026-43783
      evidence: Vulnerability fixed in 26.6
updates:
  - at: "2026-10-23T09:34:35Z"
    level: L2
    summary: added coverage for macOS (< 26.6)
    sources:
      - sploitus
    source_urls:
      - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-ANDRD3V-CVE-2026-43783&utm_source=rss&utm_medium=rss
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
