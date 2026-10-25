---
brief_id: brief-2026-10-25-fidelis-lpe
event_id: brief-2026-10-25-fidelis-lpe
revision: 1
activity_at: "2026-10-25T10:42:51Z"
title: 'Fidelis Network and Deception: Local Privilege Escalation (CVE-2022-0486)'
slug: 2026-10-fidelis-lpe
description: Multiple Fidelis products are vulnerable to local privilege escalation due to insecure file permissions on binaries and scripts owned by the fidelis user, allowing for unauthorized root access via sudo.
date: "2026-10-25T10:42:51Z"
type: advisory
types:
  - advisory
severities:
  - low
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
qa_status:
  verdict: pass
cpes:
  - cpe:2.3:a:fidelissecurity:deception:*:*:*:*:*:*:*:*
  - cpe:2.3:a:fidelissecurity:network:*:*:*:*:*:*:*:*
tags:
  - privilege-escalation
  - local-access
  - insecure-permissions
vendors:
  - Fidelissecurity
products:
  - Fidelis CommandPost (< 9.4.5)
  - Fidelis Collector (< 9.4.5)
  - Fidelis Sensor (< 9.4.5)
  - Fidelis Sandbox (< 9.4.5)
  - Fidelis Deception (< 9.4.5)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: Insecure file permissions in Fidelis Network and Deception below 9.4.5 enable local root escalation.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1548.003
    technique_name: Sudo and Sudo Caching
    evidence: All exploits are due to one NOPASSWD and several password-required sudoers permissions being given to the fidelis user on binaries or scripts that the fidelis user owns.
    confidence_band: high
cves:
  - id: CVE-2022-0486
    cvss: 4.4
    epss: 0.00386
    kev_status: "false"
references:
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-HENRYREED-CVE-2022-0486
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-HENRYREED-CVE-2022-0486&utm_source=rss&utm_medium=rss
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Patch Fidelis products to version 9.4.5 or later.
      owner: IT Operations
      due: 48h
      evidence: CVE-2022-0486 description states updates are available to address this vulnerability.
  hunt_leads:
    - lead: Monitor for chmod modifications on files within the /FSS/ directory.
      technique_id: T1548.003
      data_needed:
        - Linux auditd logs or filesystem integrity monitoring
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: The exploit requires changing file permissions of binaries/scripts in /FSS/ before modification.
    - lead: Monitor sudo execution of binaries within /FSS/ by the fidelis user.
      technique_id: T1548.003
      data_needed:
        - sudoers log (auth.log / secure log)
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: Exploitation relies on executing the modified binaries via sudo.
  mitigation_plan:
    - priority: immediate
      action: Disable SSH/shell access to Fidelis CommandPost and Sensor instances.
      owner: IT Operations
      addresses: CVE-2022-0486
      evidence: Recommended for all users to disable shell access after initial configuration.
---

CVE-2022-0486 encompasses a series of improper file permission vulnerabilities in Fidelis CommandPost, Collector, Sensor, and Sandbox components of Fidelis Network and Deception. The vulnerabilities exist because the 'fidelis' user holds sudo permissions to execute specific binaries and scripts that the user also owns. This allows a local attacker to modify the files, injecting arbitrary code or spawning shells to achieve root-level privilege escalation.

## Attack Chain
1. Attacker gains local command-line interface (CLI) access as the 'fidelis' user.
2. Attacker identifies a vulnerable binary or script in the /FSS/ directory (e.g., /FSS/bin/shutdown.pl) that is owned by the 'fidelis' user.
3. Attacker modifies the file permissions (e.g., chmod 700 or u+w) to allow write access.
4. Attacker overwrites the content of the target script or binary with malicious code (e.g., executing /bin/sh).
5. Attacker executes the modified file via sudo, providing a password if required by the sudoers configuration.
6. The command executes with root privileges, granting the attacker full system control.

## Impact
Successful exploitation grants a local, authenticated 'fidelis' user full root-level control over the affected Fidelis component.

## Recommendation
- Update all Fidelis CommandPost, Collector, Sensor, and Sandbox instances to version 9.4.5 or later immediately.
- Disable shell/SSH access to Fidelis products after initial configuration to prevent local access vectors.
- If patching is not immediately possible, restrict ownership of vulnerable files (e.g., /FSS/bin/shutdown.pl, /FSS/setup/cert_mgmt) to root:fidelis and limit group permissions to read and execute only.
