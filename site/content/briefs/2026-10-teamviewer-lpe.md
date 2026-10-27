---
brief_id: brief-2026-10-27-teamviewer-lpe
event_id: brief-2026-10-27-teamviewer-lpe
revision: 1
activity_at: "2026-10-27T18:05:02Z"
title: 'TeamViewer: Local privilege escalation via installer staging (CVE-2026-111583)'
slug: 2026-10-teamviewer-lpe
description: An improper access control vulnerability in the TeamViewer installer staging directory allows local low-privileged users to achieve arbitrary code execution as SYSTEM via a crafted installer options file.
date: "2026-10-27T18:05:02Z"
lastmod: "2026-10-27T18:05:32Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "2"
  rating: A2
  likelihood: roughly even chance
qa_status:
  verdict: pass
  validation_status: Confirmed against source description.
cpes:
  - cpe:2.3:a:teamviewer:teamviewer:*:*:*:*:*:windows:*:*
  - cpe:2.3:a:teamviewer:teamviewer:*:*:*:*:*:*:*:*
  - cpe:2.3:a:teamviewer:teamviewer:*:*:*:*:*:linux:*:*
  - cpe:2.3:a:teamviewer:teamviewer:*:*:*:*:*:macos:*:*
tags:
  - privilege-escalation
  - windows
  - local-access
  - vulnerability
  - remote-access
  - integer-overflow
  - macos
  - teamviewer
vendors:
  - TeamViewer
products:
  - TeamViewer Full Client (< 15.82)
  - TeamViewer Host (< 15.82)
  - TeamViewer Full Client (< 15.83)
  - TeamViewer Portable (< 15.83)
  - TeamViewer Remote Control App (< 15.83)
  - TeamViewer Host (< 15.83)
affected_os:
  - Windows
  - Linux
  - macOS
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: This flaw allows a local, low-privileged authenticated user to escalate privileges by placing a crafted installer options file, resulting in arbitrary code execution with SYSTEM permissions when the service is activated.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: Exploitation requires a user to establish a remote-control session to an attacker-controlled or compromised host.
    confidence_band: high
cves:
  - id: CVE-2026-111583
    cvss: 7.3
    kev_status: "false"
  - id: CVE-2026-111585
    cvss: 8.8
    kev_status: "false"
  - id: CVE-2026-92372
    cvss: 8.8
    kev_status: "false"
  - id: CVE-2026-92374
    cvss: 7.8
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-111583
  - https://nvd.nist.gov/vuln/detail/CVE-2026-111585
  - https://nvd.nist.gov/vuln/detail/CVE-2026-92372
  - https://nvd.nist.gov/vuln/detail/CVE-2026-92374
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
    - Security Operations
  immediate_actions:
    - action: Upgrade all TeamViewer Full Client and Host installations to version 15.82 or later.
      owner: IT Operations
      due: 48h
      evidence: Vulnerability affects versions prior to 15.82.
    - action: Upgrade TeamViewer Full Client to 15.83 or later on all managed Linux and macOS assets.
      owner: IT Operations
      due: 48h
      evidence: Vulnerability affects versions prior to 15.83.
    - action: Upgrade TeamViewer Full Client and Host to version 15.83 or later
      owner: IT Operations
      due: 72h
      evidence: TeamViewer Full Client and Host prior to version 15.83 for macOS are vulnerable
  hunt_leads:
    - lead: Monitor file system modifications in TeamViewer temporary staging directories for files created or modified by non-SYSTEM, non-Admin users.
      technique_id: T1068
      data_needed:
        - File creation events (e.g., Sysmon Event ID 11) filtering for TeamViewer staging paths
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Vulnerability involves placing a crafted installer options file in the installer staging directory.
    - lead: Identify endpoints initiating TeamViewer connections to unknown or external IP addresses
      technique_id: T1203
      data_needed:
        - Firewall logs
        - Endpoint network connection logs
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Exploitation requires a user to establish a remote-control session to an attacker-controlled or compromised host.
    - lead: Identify endpoints running TeamViewer versions < 15.83 and investigate process lineage for child processes spawning from the TeamViewer binary.
      technique_id: T1203
      data_needed:
        - Endpoint detection and response (EDR) process telemetry
        - Asset management logs
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: Exploitation involves triggering memory corruption leading to potential arbitrary code execution via the TeamViewer process.
    - lead: Identify unauthorized or unexpected package installations in TeamViewer paths
      technique_id: T1068
      data_needed:
        - macOS Unified Logs
        - Endpoint management inventory data
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Vulnerability allows a local attacker to bypass installer package verification
  mitigation_plan:
    - priority: immediate
      action: Upgrade to version 15.82 or later.
      owner: IT Operations
      addresses: CVE-2026-111583
      evidence: Product vendor patch advisory.
    - priority: immediate
      action: Upgrade all TeamViewer clients to version 15.83 or later
      owner: IT Operations
      addresses: CVE-2026-111585
      evidence: TeamViewer clients prior to version 15.83 may allow a malicious remote host to cause a denial of service or... arbitrary code
    - priority: immediate
      action: Patch TeamViewer Full Client to 15.83 or newer.
      owner: IT Operations
      addresses: CVE-2026-92372
      evidence: CVE-2026-92372 disclosure.
    - priority: immediate
      action: Upgrade to version 15.83 or later
      owner: IT Operations
      addresses: CVE-2026-92374
      evidence: TeamViewer Full Client and Host prior to version 15.83 for macOS are vulnerable
updates:
  - at: "2026-10-27T18:05:17Z"
    level: L2
    summary: added coverage for TeamViewer Full Client (< 15.83) +2 products
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-111585
  - at: "2026-10-27T18:05:29Z"
    level: L2
    summary: added coverage for TeamViewer Full Client (< 15.83)
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-92372
  - at: "2026-10-27T18:05:32Z"
    level: L2
    summary: added coverage for TeamViewer Full Client (< 15.83) +1 products
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-92374
---

TeamViewer Full Client and Host for Windows versions prior to 15.82 are vulnerable to a local privilege escalation flaw. During the installation of the Advanced Asset Management component, the installer uses an insecurely permissioned staging directory. A local authenticated user with low privileges can place a crafted installer options file in this directory, which is then processed by the installer, resulting in execution of arbitrary commands with SYSTEM privileges during service activation.

## Impact
Successful exploitation allows a local low-privileged user to gain full SYSTEM access on the affected Windows host.

## Recommendation
- Update all instances of TeamViewer Full Client and TeamViewer Host to version 15.82 or later immediately.
- Review and restrict write permissions on installer staging directories if the upgrade cannot be performed immediately.
- Monitor local file system activity for unexpected file writes to TeamViewer staging directories by non-administrative users.
