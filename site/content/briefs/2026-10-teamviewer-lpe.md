---
brief_id: brief-2026-10-27-teamviewer-lpe
event_id: brief-2026-10-27-teamviewer-lpe
revision: 6
activity_at: "2026-10-28T18:59:25Z"
revision_history:
  - revision: 2
    at: "2026-10-27T20:02:31Z"
    checksum: sha256:f2d8474383cef9a4ea04d003f88706e1df0e3e8579575767decadbdb0d8c47ca
    summary: added coverage for TeamViewer Full Client (< 15.83) +2 products
    changed_fields:
      - action_plan
      - affected_products
      - cves
      - lastmod
      - references
      - tags
      - updates
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-92375
  - revision: 3
    at: "2026-10-28T00:14:42Z"
    checksum: sha256:0e80db4e38b5845dea4c58fd67db64bb5b4dee62abf9449c3bd1bdab48522339
    summary: added CVE-2026-111582 +3; OS android
    changed_fields:
      - affected_os
      - claim_state
      - cves
      - lastmod
      - references
      - updates
    source_urls:
      - https://pwn.watch/i/teamviewer-15-83-security-update-oct-2026
  - revision: 4
    at: "2026-10-28T03:18:17Z"
    checksum: sha256:81543c852ecfef984799697ac621b79e6d3647f23e4e0ede0eb800383acaa153
    summary: new product
    changed_fields:
      - affected_products
      - lastmod
      - updates
    source_urls:
      - https://pwn.watch/i/teamviewer-15-83-security-update-oct-2026
  - revision: 5
    at: "2026-10-28T07:33:18Z"
    checksum: sha256:a1e359d18143fb935bee48993f8bfa55ea0770611a73f5115e4c51f2fc3e16fe
    summary: new product
    changed_fields:
      - affected_products
      - lastmod
      - updates
    source_urls:
      - https://pwn.watch/i/teamviewer-15-83-security-update-oct-2026
  - revision: 6
    at: "2026-10-28T18:59:25Z"
    checksum: sha256:fb44f841a4ba9792641eecfe1a239a4af3169e079e7f1746c521868a4fe4e136
    summary: new product
    changed_fields:
      - affected_products
      - lastmod
      - updates
    source_urls:
      - https://pwn.watch/i/teamviewer-15-83-security-update-oct-2026
title: 'TeamViewer: Local privilege escalation via installer staging (CVE-2026-111583)'
slug: 2026-10-teamviewer-lpe
description: An improper access control vulnerability in the TeamViewer installer staging directory allows local low-privileged users to achieve arbitrary code execution as SYSTEM via a crafted installer options file.
date: "2026-10-27T18:05:02Z"
lastmod: "2026-10-28T18:58:49Z"
type: advisory
claim_state: <nil>
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
  - ipc
  - cve-2026-92375
vendors:
  - TeamViewer
products:
  - TeamViewer Full Client (< 15.82)
  - TeamViewer Host (< 15.82)
  - TeamViewer Full Client (< 15.83)
  - TeamViewer Portable (< 15.83)
  - TeamViewer Remote Control App (< 15.83)
  - TeamViewer Host (< 15.83)
  - Remote Management Monitoring component (< 26.10.1)
  - TeamViewer Remote (< 15.83)
  - TeamViewer Remote Control Android (< 15.83)
  - TeamViewer Remote Management Monitoring (< 26.10.1)
  - TeamViewer Remote Management Patch Management (< 26.9.1)
  - TeamViewer Remote Control app for Android (< 15.83)
  - Remote Management Monitoring add-on (< 26.10.1)
  - Remote Management Patch Management add-on (< 26.9.1)
  - TeamViewer Remote Control Android app (< 15.83)
affected_os:
  - Windows
  - Linux
  - macOS
  - Android
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
  - id: CVE-2026-92375
    cvss: 7.8
    kev_status: "false"
  - id: CVE-2026-92376
    cvss: 7.8
    kev_status: "false"
  - id: CVE-2026-92377
    cvss: 7.8
    kev_status: "false"
  - id: CVE-2026-111582
    cvss: 7.3
    kev_status: "false"
  - id: CVE-2026-111584
    cvss: 7.3
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-111583
  - https://nvd.nist.gov/vuln/detail/CVE-2026-111585
  - https://nvd.nist.gov/vuln/detail/CVE-2026-92372
  - https://nvd.nist.gov/vuln/detail/CVE-2026-92374
  - https://nvd.nist.gov/vuln/detail/CVE-2026-92375
  - https://pwn.watch/i/teamviewer-15-83-security-update-oct-2026
  - https://www.teamviewer.com/en/resources/trust-center/security-bulletins/tv-2026-1011/
  - https://www.teamviewer.com/en/resources/trust-center/security-bulletins/tv-2026-1012/
  - https://www.teamviewer.com/en/resources/trust-center/security-bulletins/
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
    - lead: Monitor for unexpected script execution or child processes spawned by TeamViewer related services under SYSTEM or root context
      technique_id: T1068
      data_needed:
        - Process creation logs (Event ID 1)
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: allows a local authenticated attacker with low privileges to execute scripts as SYSTEM/root.
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
    - priority: immediate
      action: Update TeamViewer Full Client and Host to 15.83 and Remote Management Monitoring component to 26.10.1
      owner: IT Operations
      addresses: CVE-2026-92375
      evidence: TeamViewer Full Client or Host prior to version 15.83 and the Remote Management Monitoring component prior to version 26.10.1
updates:
  - at: "2026-10-27T20:01:20Z"
    level: L2
    summary: added coverage for TeamViewer Full Client (< 15.83) +2 products
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-92375
  - at: "2026-10-28T00:13:47Z"
    level: L2
    summary: added CVE-2026-111582 +3; OS android
    sources:
      - pwn-watch
    source_urls:
      - https://pwn.watch/i/teamviewer-15-83-security-update-oct-2026
  - at: "2026-10-28T03:17:42Z"
    level: L1
    summary: new product
    sources:
      - pwn-watch
    source_urls:
      - https://pwn.watch/i/teamviewer-15-83-security-update-oct-2026
  - at: "2026-10-28T07:32:45Z"
    level: L1
    summary: new product
    sources:
      - pwn-watch
    source_urls:
      - https://pwn.watch/i/teamviewer-15-83-security-update-oct-2026
  - at: "2026-10-28T18:58:49Z"
    level: L1
    summary: new product
    sources:
      - pwn-watch
    source_urls:
      - https://pwn.watch/i/teamviewer-15-83-security-update-oct-2026
---

TeamViewer Full Client and Host for Windows versions prior to 15.82 are vulnerable to a local privilege escalation flaw. During the installation of the Advanced Asset Management component, the installer uses an insecurely permissioned staging directory. A local authenticated user with low privileges can place a crafted installer options file in this directory, which is then processed by the installer, resulting in execution of arbitrary commands with SYSTEM privileges during service activation.

## Impact
Successful exploitation allows a local low-privileged user to gain full SYSTEM access on the affected Windows host.

## Recommendation
- Update all instances of TeamViewer Full Client and TeamViewer Host to version 15.82 or later immediately.
- Review and restrict write permissions on installer staging directories if the upgrade cannot be performed immediately.
- Monitor local file system activity for unexpected file writes to TeamViewer staging directories by non-administrative users.
